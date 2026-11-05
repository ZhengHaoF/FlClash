package core

import (
	"context"
	"fmt"
	"net/netip"
	"testing"
	"time"
)

func TestCfResolveDomain(t *testing.T) {
	original := cfLookupA
	defer func() { cfLookupA = original }()

	answers := map[string][]netip.Addr{
		"8.8.8.8": {netip.MustParseAddr("1.2.3.4"), netip.MustParseAddr("5.6.7.8")},
		"1.1.1.1": {netip.MustParseAddr("1.2.3.4")},
		"9.9.9.9": nil,
	}
	cfLookupA = func(_ context.Context, nameserver, _ string) ([]netip.Addr, error) {
		if addrs, ok := answers[nameserver]; ok {
			return addrs, nil
		}
		return nil, fmt.Errorf("refused")
	}

	item := cfResolveDomain(
		"a.example",
		[]string{"8.8.8.8", "1.1.1.1", "9.9.9.9", "203.0.113.1"},
		time.Second,
	)
	if item.Error != "" {
		t.Fatalf("unexpected error: %s", item.Error)
	}
	// The union keeps first-seen order and drops the duplicate the two
	// resolvers share; the dead resolver costs nothing.
	if len(item.Ips) != 2 || item.Ips[0] != "1.2.3.4" || item.Ips[1] != "5.6.7.8" {
		t.Fatalf("got %v, want [1.2.3.4 5.6.7.8]", item.Ips)
	}

	item = cfResolveDomain("a.example", []string{"203.0.113.1"}, time.Second)
	if len(item.Ips) != 0 || item.Error == "" {
		t.Fatalf("a domain no resolver answers must fail: %+v", item)
	}
}

func TestCfResolveInvalidArguments(t *testing.T) {
	if _, err := handleCfResolve(&CfResolveParams{}); err == nil {
		t.Fatal("expected an error for empty domains")
	}
}
