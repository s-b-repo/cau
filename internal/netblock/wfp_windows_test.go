//go:build cgo

package netblock

import (
	"net/netip"
	"os"
	"testing"
	"time"
)

func TestWindowsFilterSessionLifecycle(t *testing.T) {
	if os.Getenv("NATIVE_OS") != "windows" {
		t.Skip("requires a native Windows runner with filter management privileges")
	}
	session, err := openWFP()
	if err != nil {
		t.Fatal(err)
	}
	leases := newFilterLeases(session)
	t.Cleanup(func() { _ = leases.close() })
	observer, err := openWFP()
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = observer.close() })
	kernel := observer.(*windowsFilterSession)

	ipv4, ipv6 := netip.MustParseAddr("192.0.2.27"), netip.MustParseAddr("2001:db8::27")
	for _, ip := range []netip.Addr{ipv4, ipv6} {
		if _, err := leases.block(ip, "native CI", time.Hour); err != nil {
			t.Fatal(err)
		}
	}
	leases.mu.Lock()
	id4, id6 := leases.entries[ipv4].ids, leases.entries[ipv6].ids
	leases.mu.Unlock()
	check := func(ids [2]uint64, expected bool) {
		t.Helper()
		for _, id := range ids {
			found, err := kernel.contains(id)
			if err != nil || found != expected {
				t.Fatalf("filter %d: found=%v, expected=%v, error=%v", id, found, expected, err)
			}
		}
	}
	check(id4, true)
	check(id6, true)
	if _, err := leases.block(ipv4, "expiry", 50*time.Millisecond); err != nil {
		t.Fatal(err)
	}
	waitForLeaseState(t, func() bool {
		entries, err := leases.list()
		return len(entries) == 1 && err == nil
	})
	check(id4, false)
	check(id6, true)
	if err := leases.close(); err != nil {
		t.Fatal(err)
	}
	check(id6, false)
}
