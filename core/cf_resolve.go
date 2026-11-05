package core

import (
	"context"
	"fmt"
	"net"
	"net/netip"
	"sync"
	"time"

	"github.com/metacubex/mihomo/component/dialer"
)

// The public resolvers the sweep queries, spread across different networks:
// a CDN answers each resolver's region with its own nearest edge, so the
// union pools addresses no single resolver would hand out.
var cfResolveNameservers = []string{
	"8.8.8.8", "1.1.1.1", "9.9.9.9", "208.67.222.222",
	"114.114.114.114", "223.5.5.5", "119.29.29.29", "180.76.76.76",
}

const (
	cfResolveDefaultTimeout = 3000
	cfResolveMinTimeout     = 500
	cfResolveMaxTimeout     = 15000
)

type CfResolveParams struct {
	Domains     []string `json:"domains"`
	Nameservers []string `json:"nameservers"`
	Timeout     int64    `json:"timeout"`
}

type CfResolveItem struct {
	Domain string   `json:"domain"`
	Ips    []string `json:"ips"`
	Error  string   `json:"error,omitempty"`
}

type CfResolveResult struct {
	Results []CfResolveItem `json:"results"`
}

func handleCfResolve(params *CfResolveParams) (*CfResolveResult, error) {
	if len(params.Domains) == 0 {
		return nil, &MethodError{Code: "invalid_arguments", Message: "domains is empty"}
	}
	timeout := time.Duration(cfClampInt64(params.Timeout, cfResolveMinTimeout, cfResolveMaxTimeout, cfResolveDefaultTimeout)) * time.Millisecond
	nameservers := params.Nameservers
	if len(nameservers) == 0 {
		nameservers = cfResolveNameservers
	}

	seen := make(map[string]struct{}, len(params.Domains))
	domains := make([]string, 0, len(params.Domains))
	for _, domain := range params.Domains {
		if domain == "" {
			continue
		}
		if _, dup := seen[domain]; dup {
			continue
		}
		if len(domains) == cfDetectMaxDomains {
			break
		}
		seen[domain] = struct{}{}
		domains = append(domains, domain)
	}

	items := make([]CfResolveItem, len(domains))
	jobs := make(chan int)
	var wg sync.WaitGroup
	worker := func() {
		defer wg.Done()
		for index := range jobs {
			items[index] = cfResolveDomain(domains[index], nameservers, timeout)
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

	return &CfResolveResult{Results: items}, nil
}

// cfResolveDomain unions the A answers of every resolver, so the pool carries
// the edges each network's own region would reach. One failed or poisoned
// resolver costs nothing; only a domain no resolver answers is an error.
func cfResolveDomain(domain string, nameservers []string, timeout time.Duration) CfResolveItem {
	item := CfResolveItem{Domain: domain}
	answers := make([][]netip.Addr, len(nameservers))
	var wg sync.WaitGroup
	for index, nameserver := range nameservers {
		wg.Add(1)
		go func(index int, nameserver string) {
			defer wg.Done()
			ctx, cancel := context.WithTimeout(context.Background(), timeout)
			defer cancel()
			addrs, err := cfLookupA(ctx, nameserver, domain)
			if err == nil {
				answers[index] = addrs
			}
		}(index, nameserver)
	}
	wg.Wait()

	seen := make(map[netip.Addr]struct{})
	for _, addrs := range answers {
		for _, addr := range addrs {
			if _, dup := seen[addr]; dup {
				continue
			}
			seen[addr] = struct{}{}
			item.Ips = append(item.Ips, addr.String())
		}
	}
	if len(item.Ips) == 0 {
		item.Error = "no A answer"
	}
	return item
}

// Only the A family feeds the pool: an AAAA answer dies wherever no IPv6
// route exists, and dead weight crowds the per-domain cap of the probe run.
var cfLookupA = func(ctx context.Context, nameserver, domain string) ([]netip.Addr, error) {
	resolver := &net.Resolver{
		PreferGo: true,
		Dial: func(ctx context.Context, network, _ string) (net.Conn, error) {
			// The dialer's socket hook keeps the query out of our own tunnel
			// on Android, the same as the scan probes.
			return dialer.NewDialer().DialContext(ctx, network, net.JoinHostPort(nameserver, "53"))
		},
	}
	ips, err := resolver.LookupIPAddr(ctx, domain)
	if err != nil {
		return nil, err
	}
	addrs := make([]netip.Addr, 0, len(ips))
	for _, ip := range ips {
		addr, ok := netip.AddrFromSlice(ip.IP)
		if !ok || !addr.Is4() {
			continue
		}
		addrs = append(addrs, addr)
	}
	if len(addrs) == 0 {
		return nil, fmt.Errorf("no A record for %s", domain)
	}
	return addrs, nil
}
