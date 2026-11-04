package core

import (
	"context"
	"encoding/binary"
	"fmt"
	"math/rand/v2"
	"net"
	"net/netip"
	"sort"
	"strconv"
	"sync"
	"time"

	"github.com/metacubex/mihomo/component/dialer"
	"github.com/metacubex/mihomo/component/resolver"
)

// The scanner measures the device's own path to candidate addresses, so every
// dial goes through mihomo's dialer: its socket hook keeps the probes out of
// our own tunnel on Android, and its interface handling matches what a proxy
// node would use on the desktops.
const (
	cfScanDefaultSampleCount = 500
	cfScanMaxSampleCount     = 4096
	cfScanDefaultConcurrency = 100
	cfScanMaxConcurrency     = 500
	cfScanDefaultTestCount   = 2
	cfScanMaxTestCount       = 10
	cfScanDefaultTimeout     = 1500
	cfScanMinTimeout         = 100
	cfScanMaxTimeout         = 10000
	// Desktop RPC applies a three-minute default method timeout; a scan that
	// outlives it would come back to nobody.
	cfScanOverallCap = 2 * time.Minute

	cfDetectMaxDomains     = 64
	cfDetectMaxConcurrency = 8
	cfDetectDefaultTimeout = 5000
	cfDetectMinTimeout     = 1000
	cfDetectMaxTimeout     = 30000

	// Selection weight per prefix, capped so a huge IPv6 range cannot overflow
	// the running total; the offset inside a prefix still uses the real size.
	cfScanWeightCap = uint64(1) << 40
)

type CfScanParams struct {
	Ranges      []string `json:"ranges"`
	Port        string   `json:"port"`
	SampleCount int      `json:"sample-count"`
	Concurrency int      `json:"concurrency"`
	TestCount   int      `json:"test-count"`
	Timeout     int64    `json:"timeout"`
	// A non-positive bound means no filtering on that side; the delay bounds
	// compare the average of the successful handshakes, in milliseconds.
	MinDelay    int64   `json:"min-delay"`
	MaxDelay    int64   `json:"max-delay"`
	MaxLossRate float64 `json:"max-loss-rate"`
}

type CfScanItem struct {
	IP       string  `json:"ip"`
	Sent     int     `json:"sent"`
	Recv     int     `json:"recv"`
	LossRate float64 `json:"loss-rate"`
	DelayMs  int64   `json:"delay-ms"`
}

type CfScanResult struct {
	Results   []CfScanItem `json:"results"`
	Sampled   int          `json:"sampled"`
	ElapsedMs int64        `json:"elapsed-ms"`
}

type CfDetectParams struct {
	Domains []string `json:"domains"`
	Ranges  []string `json:"ranges"`
	Timeout int64    `json:"timeout"`
}

type CfDetectItem struct {
	Domain   string   `json:"domain"`
	Ips      []string `json:"ips"`
	IsIp     bool     `json:"is-ip"`
	InRanges bool     `json:"in-ranges"`
	Error    string   `json:"error,omitempty"`
}

type CfDetectResult struct {
	Results []CfDetectItem `json:"results"`
}

type cfSample struct {
	ip    netip.Addr
	sent  int
	recv  int
	delay time.Duration
}

func handleCfScan(params *CfScanParams) (*CfScanResult, error) {
	prefixes, err := parseCfRanges(params.Ranges)
	if err != nil {
		return nil, &MethodError{Code: "invalid_arguments", Message: err.Error()}
	}
	port, err := cfPort(params.Port)
	if err != nil {
		return nil, &MethodError{Code: "invalid_arguments", Message: err.Error()}
	}
	sampleCount := cfClampInt(params.SampleCount, 1, cfScanMaxSampleCount, cfScanDefaultSampleCount)
	concurrency := cfClampInt(params.Concurrency, 1, cfScanMaxConcurrency, cfScanDefaultConcurrency)
	attempts := cfClampInt(params.TestCount, 1, cfScanMaxTestCount, cfScanDefaultTestCount)
	perDial := time.Duration(cfClampInt64(params.Timeout, cfScanMinTimeout, cfScanMaxTimeout, cfScanDefaultTimeout)) * time.Millisecond

	targets, err := sampleCfAddresses(prefixes, sampleCount)
	if err != nil {
		return nil, err
	}
	rounds := (len(targets) + concurrency - 1) / concurrency
	deadline := time.Duration(rounds)*perDial*time.Duration(attempts) + 5*time.Second
	if deadline > cfScanOverallCap {
		deadline = cfScanOverallCap
	}
	ctx, cancel := context.WithTimeout(context.Background(), deadline)
	defer cancel()

	started := time.Now()
	samples := cfProbeAll(ctx, dialer.NewDialer(), targets, port, attempts, concurrency, perDial)

	return &CfScanResult{
		Results:   filterCfSamples(samples, params),
		Sampled:   len(targets),
		ElapsedMs: time.Since(started).Milliseconds(),
	}, nil
}

func handleCfDetect(params *CfDetectParams) (*CfDetectResult, error) {
	prefixes, err := parseCfRanges(params.Ranges)
	if err != nil {
		return nil, &MethodError{Code: "invalid_arguments", Message: err.Error()}
	}
	if len(params.Domains) == 0 {
		return nil, &MethodError{Code: "invalid_arguments", Message: "domains is empty"}
	}
	timeout := time.Duration(cfClampInt64(params.Timeout, cfDetectMinTimeout, cfDetectMaxTimeout, cfDetectDefaultTimeout)) * time.Millisecond

	seen := make(map[string]struct{}, len(params.Domains))
	domains := make([]string, 0, len(params.Domains))
	for _, domain := range params.Domains {
		if domain == "" {
			continue
		}
		if _, dup := seen[domain]; dup {
			continue
		}
		seen[domain] = struct{}{}
		if len(domains) == cfDetectMaxDomains {
			break
		}
		domains = append(domains, domain)
	}

	rounds := (len(domains) + cfDetectMaxConcurrency - 1) / cfDetectMaxConcurrency
	ctx, cancel := context.WithTimeout(context.Background(), time.Duration(rounds)*timeout+5*time.Second)
	defer cancel()

	items := make([]CfDetectItem, len(domains))
	jobs := make(chan int)
	var wg sync.WaitGroup
	worker := func() {
		defer wg.Done()
		for index := range jobs {
			items[index] = cfDetectDomain(ctx, domains[index], timeout, prefixes)
		}
	}
	for range cfDetectMaxConcurrency {
		wg.Add(1)
		go worker()
	}
	for index := range domains {
		jobs <- index
	}
	close(jobs)
	wg.Wait()

	return &CfDetectResult{Results: items}, nil
}

// cfDetectDomain resolves a host the way a proxy node's dial would, so the
// answer covers the app's hosts entries and the configured server resolver
// before falling back to system DNS.
func cfDetectDomain(ctx context.Context, domain string, timeout time.Duration, prefixes []netip.Prefix) CfDetectItem {
	if ip, err := netip.ParseAddr(domain); err == nil {
		ip = ip.Unmap()
		return CfDetectItem{
			Domain:   domain,
			Ips:      []string{ip.String()},
			IsIp:     true,
			InRanges: ipInRanges(ip, prefixes),
		}
	}
	domainCtx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()
	item := CfDetectItem{Domain: domain}
	ips, err := resolver.LookupIPWithResolver(domainCtx, domain, resolver.ProxyServerHostResolver)
	if err != nil {
		item.Error = err.Error()
		return item
	}
	for _, ip := range ips {
		ip = ip.Unmap()
		item.Ips = append(item.Ips, ip.String())
		if ipInRanges(ip, prefixes) {
			item.InRanges = true
		}
	}
	return item
}

// cfProbeAll measures every target with at most concurrency of them in flight.
// The feed watches ctx as well as the workers, because a scan cut short by the
// deadline still has to hand back what it measured: blocking the last send
// after the workers have gone would strand this goroutine and its samples.
func cfProbeAll(
	ctx context.Context,
	d dialer.NetDialer,
	targets []netip.Addr,
	port string,
	attempts, concurrency int,
	perDial time.Duration,
) []cfSample {
	samples := make([]cfSample, len(targets))
	jobs := make(chan int)
	var wg sync.WaitGroup
	worker := func() {
		defer wg.Done()
		for index := range jobs {
			if ctx.Err() != nil {
				return
			}
			samples[index] = probeCfAddress(ctx, d, targets[index], port, attempts, perDial)
		}
	}
	for range concurrency {
		wg.Add(1)
		go worker()
	}
feed:
	for index := range targets {
		select {
		case jobs <- index:
		case <-ctx.Done():
			break feed
		}
	}
	close(jobs)
	wg.Wait()
	return samples
}

func probeCfAddress(ctx context.Context, d dialer.NetDialer, addr netip.Addr, port string, attempts int, perDial time.Duration) cfSample {
	sample := cfSample{ip: addr}
	for range attempts {
		if ctx.Err() != nil {
			return sample
		}
		sample.sent++
		dialCtx, cancel := context.WithTimeout(ctx, perDial)
		started := time.Now()
		conn, err := d.DialContext(dialCtx, "tcp", net.JoinHostPort(addr.String(), port))
		elapsed := time.Since(started)
		cancel()
		if err != nil {
			continue
		}
		sample.recv++
		sample.delay += elapsed
		_ = conn.Close()
	}
	return sample
}

func filterCfSamples(samples []cfSample, params *CfScanParams) []CfScanItem {
	items := make([]CfScanItem, 0, len(samples))
	for _, sample := range samples {
		if sample.recv == 0 {
			continue
		}
		lossRate := 1 - float64(sample.recv)/float64(sample.sent)
		if params.MaxLossRate > 0 && lossRate > params.MaxLossRate {
			continue
		}
		delay := (sample.delay / time.Duration(sample.recv)).Milliseconds()
		if params.MinDelay > 0 && delay < params.MinDelay {
			continue
		}
		if params.MaxDelay > 0 && delay > params.MaxDelay {
			continue
		}
		items = append(items, CfScanItem{
			IP:       sample.ip.String(),
			Sent:     sample.sent,
			Recv:     sample.recv,
			LossRate: lossRate,
			DelayMs:  delay,
		})
	}
	sort.Slice(items, func(i, j int) bool {
		if items[i].LossRate != items[j].LossRate {
			return items[i].LossRate < items[j].LossRate
		}
		if items[i].DelayMs != items[j].DelayMs {
			return items[i].DelayMs < items[j].DelayMs
		}
		return items[i].IP < items[j].IP
	})
	return items
}

func parseCfRanges(ranges []string) ([]netip.Prefix, error) {
	if len(ranges) == 0 {
		return nil, fmt.Errorf("ranges is empty")
	}
	prefixes := make([]netip.Prefix, 0, len(ranges))
	for _, raw := range ranges {
		prefix, err := netip.ParsePrefix(raw)
		if err != nil {
			return nil, fmt.Errorf("invalid range %q: %w", raw, err)
		}
		prefixes = append(prefixes, prefix.Masked())
	}
	return prefixes, nil
}

func cfPort(port string) (string, error) {
	number, err := strconv.Atoi(port)
	if err != nil || number < 1 || number > 65535 {
		return "", fmt.Errorf("invalid port %q", port)
	}
	return port, nil
}

type cfRangePart struct {
	prefix   netip.Prefix
	weight   uint64
	hostBits int
}

// sampleCfAddresses picks up to count distinct random host addresses spread
// across the prefixes, weighted by each prefix's host count, so a /22 gets as
// many picks per address as a /13. A range with more host bits than an offset
// can carry is refused; the scanner is for CDN-sized ranges, not for /0.
func sampleCfAddresses(prefixes []netip.Prefix, count int) ([]netip.Addr, error) {
	parts := make([]cfRangePart, 0, len(prefixes))
	total := uint64(0)
	for _, prefix := range prefixes {
		hostBits := prefix.Addr().BitLen() - prefix.Bits()
		if hostBits > 64 {
			return nil, &MethodError{Code: "invalid_arguments", Message: fmt.Sprintf("range %s is too large to sample; use a smaller prefix", prefix)}
		}
		// Shifting by 64 would wrap to zero and drop the prefix from the draw,
		// so a range that wide already sits above the cap.
		weight := uint64(1) << min(hostBits, 63)
		if weight > cfScanWeightCap {
			weight = cfScanWeightCap
		}
		parts = append(parts, cfRangePart{prefix: prefix, weight: weight, hostBits: hostBits})
		total += weight
	}

	picked := make([]netip.Addr, 0, count)
	seen := make(map[netip.Addr]struct{}, count)
	limit := count * 4
	for attempt := 0; len(picked) < count && attempt < limit; attempt++ {
		prefix := parts[cfPickPart(parts, total)].prefix
		addr := cfRandomHost(prefix)
		if _, dup := seen[addr]; dup {
			continue
		}
		seen[addr] = struct{}{}
		picked = append(picked, addr)
	}
	return picked, nil
}

func cfPickPart(parts []cfRangePart, total uint64) int {
	remaining := rand.Uint64N(total)
	for index, part := range parts {
		if remaining < part.weight {
			return index
		}
		remaining -= part.weight
	}
	return len(parts) - 1
}

func cfRandomHost(prefix netip.Prefix) netip.Addr {
	hostBits := prefix.Addr().BitLen() - prefix.Bits()
	base := prefix.Masked().Addr()
	if base.Is4() {
		as4 := base.As4()
		var host uint32
		if hostBits < 32 {
			host = rand.Uint32N(uint32(1) << hostBits)
		} else {
			host = rand.Uint32()
		}
		host += binary.BigEndian.Uint32(as4[:])
		var raw [4]byte
		binary.BigEndian.PutUint32(raw[:], host)
		addr, _ := netip.AddrFromSlice(raw[:])
		return addr
	}
	var host uint64
	if hostBits < 64 {
		host = rand.Uint64N(uint64(1) << hostBits)
	} else {
		host = rand.Uint64()
	}
	raw := base.As16()
	host += binary.BigEndian.Uint64(raw[8:])
	binary.BigEndian.PutUint64(raw[8:], host)
	return netip.AddrFrom16(raw)
}

func ipInRanges(ip netip.Addr, prefixes []netip.Prefix) bool {
	for _, prefix := range prefixes {
		if prefix.Contains(ip) {
			return true
		}
	}
	return false
}

func cfClampInt(value, min, max, fallback int) int {
	if value <= 0 {
		return fallback
	}
	if value < min {
		return min
	}
	if value > max {
		return max
	}
	return value
}

func cfClampInt64(value int64, min, max, fallback int64) int64 {
	if value <= 0 {
		return fallback
	}
	if value < min {
		return min
	}
	if value > max {
		return max
	}
	return value
}
