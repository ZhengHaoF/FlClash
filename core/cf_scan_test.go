package core

import (
	"context"
	"net"
	"net/netip"
	"strconv"
	"testing"
	"time"

	"github.com/metacubex/mihomo/component/dialer"
)

func TestParseCfRanges(t *testing.T) {
	prefixes, err := parseCfRanges([]string{"104.16.0.0/13", "1.2.3.4/24", "2606:4700::/32"})
	if err != nil {
		t.Fatalf("parseCfRanges: %v", err)
	}
	if len(prefixes) != 3 {
		t.Fatalf("got %d prefixes, want 3", len(prefixes))
	}
	if got := prefixes[1]; got != netip.MustParsePrefix("1.2.3.0/24") {
		t.Fatalf("unmasked host bits: got %s, want 1.2.3.0/24", got)
	}
	if _, err := parseCfRanges([]string{"not-a-range"}); err == nil {
		t.Fatal("expected an error for a malformed range")
	}
	if _, err := parseCfRanges(nil); err == nil {
		t.Fatal("expected an error for empty ranges")
	}
}

func TestSampleCfAddresses(t *testing.T) {
	prefixes := []netip.Prefix{netip.MustParsePrefix("104.16.0.0/13")}
	targets, err := sampleCfAddresses(prefixes, 100)
	if err != nil {
		t.Fatalf("sampleCfAddresses: %v", err)
	}
	if len(targets) != 100 {
		t.Fatalf("got %d targets, want 100", len(targets))
	}
	seen := make(map[netip.Addr]struct{}, len(targets))
	for _, addr := range targets {
		if !prefixes[0].Contains(addr) {
			t.Fatalf("%s is outside %s", addr, prefixes[0])
		}
		if _, dup := seen[addr]; dup {
			t.Fatalf("%s sampled twice", addr)
		}
		seen[addr] = struct{}{}
	}

	// A range smaller than the sample count yields every distinct host once.
	tiny := []netip.Prefix{netip.MustParsePrefix("127.0.0.0/30")}
	targets, err = sampleCfAddresses(tiny, 8)
	if err != nil {
		t.Fatalf("sampleCfAddresses: %v", err)
	}
	if len(targets) != 4 {
		t.Fatalf("got %d targets from a /30, want 4", len(targets))
	}

	if _, err := sampleCfAddresses([]netip.Prefix{netip.MustParsePrefix("2606:4700::/29")}, 1); err == nil {
		t.Fatal("expected an error for a range too large to sample")
	}
}

// A /64 is the smallest IPv6 allocation Cloudflare announces. Its host count
// overflows the weight shift, which used to drop it from the draw entirely and
// panic when it was the only range.
func TestSampleCfAddressesFromASixtyFour(t *testing.T) {
	prefix := netip.MustParsePrefix("2606:4700:4700::/64")
	targets, err := sampleCfAddresses([]netip.Prefix{prefix}, 8)
	if err != nil {
		t.Fatalf("sampleCfAddresses: %v", err)
	}
	if len(targets) != 8 {
		t.Fatalf("got %d targets, want 8", len(targets))
	}
	for _, addr := range targets {
		if !prefix.Contains(addr) {
			t.Fatalf("%s is outside %s", addr, prefix)
		}
	}
}

func TestFilterCfSamples(t *testing.T) {
	samples := []cfSample{
		{ip: netip.MustParseAddr("104.16.0.1"), sent: 2, recv: 2, delay: 80 * time.Millisecond},
		{ip: netip.MustParseAddr("104.16.0.2"), sent: 2, recv: 1, delay: 30 * time.Millisecond},
		{ip: netip.MustParseAddr("104.16.0.3"), sent: 2, recv: 0},
		{ip: netip.MustParseAddr("104.16.0.4"), sent: 2, recv: 2, delay: 100 * time.Millisecond},
	}

	items := filterCfSamples(samples, &CfScanParams{MaxLossRate: 0.2})
	if len(items) != 2 {
		t.Fatalf("got %d items, want 2 (the half-lost and the dead filtered)", len(items))
	}
	if items[0].IP != "104.16.0.1" || items[1].IP != "104.16.0.4" {
		t.Fatalf("got %s then %s, want 104.16.0.1 then 104.16.0.4 by delay", items[0].IP, items[1].IP)
	}
	if items[0].DelayMs != 40 {
		t.Fatalf("got %d ms, want 40", items[0].DelayMs)
	}

	items = filterCfSamples(samples, &CfScanParams{MinDelay: 45})
	if len(items) != 1 || items[0].IP != "104.16.0.4" {
		t.Fatalf("min delay kept %v, want only 104.16.0.4", items)
	}

	items = filterCfSamples(samples, &CfScanParams{MaxDelay: 45})
	if len(items) != 2 || items[0].IP != "104.16.0.1" || items[1].IP != "104.16.0.2" {
		t.Fatalf("max delay kept %v, want 104.16.0.1 then 104.16.0.2", items)
	}

	// No bounds at all: the dead address stays out, nothing else does.
	items = filterCfSamples(samples, &CfScanParams{})
	if len(items) != 3 {
		t.Fatalf("got %d items, want 3", len(items))
	}
	if items[2].IP != "104.16.0.2" {
		t.Fatalf("got %s last, want the half-lost 104.16.0.2 by loss rate", items[2].IP)
	}
}

func TestCfScanLoopback(t *testing.T) {
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	defer listener.Close()
	port := listener.Addr().(*net.TCPAddr).Port

	result, err := handleCfScan(&CfScanParams{
		Ranges:      []string{"127.0.0.0/31"},
		Port:        strconv.Itoa(port),
		SampleCount: 8,
		Concurrency: 2,
		TestCount:   2,
		Timeout:     1000,
	})
	if err != nil {
		t.Fatalf("handleCfScan: %v", err)
	}
	if result.Sampled != 2 {
		t.Fatalf("sampled %d, want 2", result.Sampled)
	}
	var open *CfScanItem
	for i := range result.Results {
		item := &result.Results[i]
		if item.Recv == 0 {
			t.Fatalf("%s answered no handshake but survived the filter", item.IP)
		}
		if item.IP == "127.0.0.1" {
			open = item
		}
	}
	if open == nil {
		t.Fatalf("the listening address is missing from %+v", result.Results)
	}
	if open.Sent != 2 || open.Recv != 2 {
		t.Fatalf("127.0.0.1 sent %d recv %d, want 2/2", open.Sent, open.Recv)
	}
	if open.DelayMs < 0 {
		t.Fatalf("negative delay %d", open.DelayMs)
	}
}

// The scan's own deadline fires while addresses are still queued. Handing them
// out must then stop rather than block on workers that have already gone, or
// the whole call never answers and leaks its goroutines in the Core.
func TestCfProbeAllReturnsWhenTheDeadlineCutsTheScan(t *testing.T) {
	const targetCount = 64
	targets := make([]netip.Addr, targetCount)
	for i := range targets {
		targets[i] = netip.AddrFrom4([4]byte{104, 16, byte(i), 1})
	}
	blocked := dialer.NetDialerFunc(func(ctx context.Context, _, _ string) (net.Conn, error) {
		<-ctx.Done()
		return nil, ctx.Err()
	})

	ctx, cancel := context.WithTimeout(context.Background(), 100*time.Millisecond)
	defer cancel()
	done := make(chan []cfSample, 1)
	go func() {
		done <- cfProbeAll(ctx, blocked, targets, "443", 2, 4, 20*time.Millisecond)
	}()

	var samples []cfSample
	select {
	case samples = <-done:
	case <-time.After(5 * time.Second):
		t.Fatal("cfProbeAll never finished after every worker had left")
	}
	if len(samples) != targetCount {
		t.Fatalf("got %d samples, want %d", len(samples), targetCount)
	}
	for _, sample := range samples {
		if sample.recv > 0 {
			t.Fatalf("%s reported a handshake through a dial that never answers", sample.ip)
		}
	}
}

func TestCfTestIpsLoopback(t *testing.T) {
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	defer listener.Close()
	port := listener.Addr().(*net.TCPAddr).Port

	result, err := handleCfTestIps(&CfTestIpsParams{
		Targets: []CfTestIpsTarget{
			{Domain: "a.example", Ips: []string{"127.0.0.1", "127.0.0.2"}},
			{Domain: "b.example", Ips: []string{"not-an-ip", "127.0.0.1"}},
			{Domain: "c.example", Ips: []string{"127.0.0.2"}},
			{Domain: "a.example", Ips: []string{"127.0.0.1"}},
		},
		Port:        strconv.Itoa(port),
		Concurrency: 2,
		TestCount:   2,
		Timeout:     1000,
	})
	if err != nil {
		t.Fatalf("handleCfTestIps: %v", err)
	}
	if len(result.Results) != 3 {
		t.Fatalf("got %d domains, want 3 with the duplicate domain folded", len(result.Results))
	}
	first := result.Results[0]
	if first.Domain != "a.example" || len(first.Results) != 1 || first.Results[0].IP != "127.0.0.1" {
		t.Fatalf("a.example misreported: %+v", first)
	}
	if first.Results[0].Recv != 2 {
		t.Fatalf("127.0.0.1 recv %d, want 2", first.Results[0].Recv)
	}
	second := result.Results[1]
	if second.Domain != "b.example" || len(second.Results) != 1 || second.Results[0].IP != "127.0.0.1" {
		t.Fatalf("b.example misreported: %+v", second)
	}
	// The refused address keeps the domain in the answer, so the caller can
	// tell a dead answer apart from a domain it never asked about.
	third := result.Results[2]
	if third.Domain != "c.example" || len(third.Results) != 0 {
		t.Fatalf("c.example misreported: %+v", third)
	}
}

func TestCfScanInvalidArguments(t *testing.T) {
	if _, err := handleCfScan(&CfScanParams{Ranges: []string{"104.16.0.0/13"}, Port: "0"}); err == nil {
		t.Fatal("expected an error for port 0")
	}
	if _, err := handleCfScan(&CfScanParams{Ranges: []string{"104.16.0.0/13"}, Port: "abc"}); err == nil {
		t.Fatal("expected an error for a non-numeric port")
	}
	if _, err := handleCfDetect(&CfDetectParams{Domains: []string{"1.0.0.1"}}); err == nil {
		t.Fatal("expected an error for missing ranges")
	}
	if _, err := handleCfDetect(&CfDetectParams{Ranges: []string{"1.0.0.0/24"}}); err == nil {
		t.Fatal("expected an error for empty domains")
	}
	if _, err := handleCfTestIps(&CfTestIpsParams{Port: "443"}); err == nil {
		t.Fatal("expected an error for empty targets")
	}
	if _, err := handleCfTestIps(&CfTestIpsParams{
		Targets: []CfTestIpsTarget{{Domain: "a.example", Ips: []string{"nope"}}},
		Port:    "443",
	}); err == nil {
		t.Fatal("expected an error for targets without a usable address")
	}
	if _, err := handleCfTestIps(&CfTestIpsParams{
		Targets: []CfTestIpsTarget{{Domain: "a.example", Ips: []string{"127.0.0.1"}}},
	}); err == nil {
		t.Fatal("expected an error for a missing port")
	}
}

// Hostname resolution depends on the network and the host resolver; only the
// literal path is covered here, the resolve path is the node dial's own.
func TestCfDetectLiterals(t *testing.T) {
	result, err := handleCfDetect(&CfDetectParams{
		Domains: []string{"1.0.0.1", "8.8.8.8", "1.0.0.1"},
		Ranges:  []string{"1.1.1.0/24", "1.0.0.0/24"},
		Timeout: 1000,
	})
	if err != nil {
		t.Fatalf("handleCfDetect: %v", err)
	}
	if len(result.Results) != 2 {
		t.Fatalf("got %d results, want 2 after dedupe", len(result.Results))
	}
	first := result.Results[0]
	if first.Domain != "1.0.0.1" || !first.IsIp || !first.InRanges {
		t.Fatalf("1.0.0.1 misdetected: %+v", first)
	}
	second := result.Results[1]
	if second.Domain != "8.8.8.8" || !second.IsIp || second.InRanges {
		t.Fatalf("8.8.8.8 misdetected: %+v", second)
	}
}
