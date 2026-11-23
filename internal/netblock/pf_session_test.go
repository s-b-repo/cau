package netblock

import (
	"context"
	"errors"
	"net"
	"net/netip"
	"slices"
	"strings"
	"sync"
	"testing"
	"time"
)

func TestPFSessionExpiryAndClientDisconnect(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	agent, server := net.Pipe()
	defer agent.Close()
	var mu sync.Mutex
	var active []netip.Addr
	driver := pfDriver{
		ready:     func(context.Context) error { return nil },
		protected: func(context.Context) ([]string, error) { return []string{"192.0.2.1"}, nil },
		apply: func(_ context.Context, peers []netip.Addr) error {
			mu.Lock()
			defer mu.Unlock()
			active = slices.Clone(peers)
			return nil
		},
	}
	done := make(chan error, 1)
	go func() { done <- servePFConnection(ctx, server, driver) }()
	client, protected, err := openPFClient(agent)
	if err != nil || !slices.Contains(protected, "192.0.2.1") {
		t.Fatalf("open failed: peers=%v err=%v", protected, err)
	}
	if _, err := client.block(netip.MustParseAddr("192.0.2.1"), "gateway", time.Hour); err == nil {
		t.Fatal("accepted a protected gateway")
	}
	first, second := netip.MustParseAddr("192.0.2.8"), netip.MustParseAddr("2001:db8::9")
	if _, err := client.block(first, "expiry", 20*time.Millisecond); err != nil {
		t.Fatal(err)
	}
	if _, err := client.block(second, "disconnect", time.Hour); err != nil {
		t.Fatal(err)
	}
	// Wait for the broker's timer without issuing a query that could also
	// expire the lease. After closing the raw connection, verify EOF cleanup.
	waitForLeaseState(t, func() bool {
		mu.Lock()
		defer mu.Unlock()
		return slices.Equal(active, []netip.Addr{second})
	})
	if err := agent.Close(); err != nil {
		t.Fatal(err)
	}
	select {
	case err := <-done:
		if err != nil {
			t.Fatal(err)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("firewall session did not end after disconnect")
	}
	mu.Lock()
	defer mu.Unlock()
	if len(active) != 0 {
		t.Fatalf("firewall rules remained after disconnect: %v", active)
	}
}

func TestPFAmbiguousWriteClearsAnchor(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	agent, server := net.Pipe()
	defer agent.Close()
	var cleared bool
	driver := pfDriver{
		ready:     func(context.Context) error { return nil },
		protected: func(context.Context) ([]string, error) { return nil, nil },
		apply: func(_ context.Context, peers []netip.Addr) error {
			if len(peers) > 0 {
				return errors.New("temporary failure")
			}
			cleared = true
			return nil
		},
	}
	done := make(chan error, 1)
	go func() { done <- servePFConnection(ctx, server, driver) }()
	client, _, err := openPFClient(agent)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := client.block(netip.MustParseAddr("192.0.2.9"), "test", time.Hour); err == nil {
		t.Fatal("accepted a failed PF write")
	}
	if err := client.expiryError(); err == nil || err.Error() != "temporary failure" {
		t.Fatalf("session did not record its terminal error: %v", err)
	}
	select {
	case err := <-done:
		if err != nil || !cleared {
			t.Fatalf("ambiguous write did not clear the anchor: cleared=%v err=%v", cleared, err)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("firewall did not clear the anchor after a failed write")
	}
}

func TestPFGatewaysAndRules(t *testing.T) {
	gateways, err := pfGateways("Routing tables\nInternet:\ndefault 192.0.2.5 UGSc en0\nInternet6:\ndefault fe80::1%en0 UGc en0\ndefault link#10 UCS utun0\n")
	if err != nil || len(gateways) != 2 || gateways[1].String() != "fe80::1" {
		t.Fatalf("unexpected gateways: %v, %v", gateways, err)
	}
	rules := pfRules(gateways)
	if !strings.Contains(rules, "block drop out quick inet from any to 192.0.2.5\n") ||
		!strings.Contains(rules, "block drop in quick inet6 from fe80::1 to any\n") {
		t.Fatalf("unexpected PF rules:\n%s", rules)
	}
	if _, err := pfGateways("Routing tables\ndefault 192.0.example\n"); err == nil {
		t.Fatal("accepted an invalid gateway")
	}
}
