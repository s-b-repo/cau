package netblock

import (
	"errors"
	"net/netip"
	"sync"
	"testing"
	"time"
)

type fakeFilterSession struct {
	mu       sync.Mutex
	next     uint64
	active   map[[2]uint64]bool
	failDrop bool
	closed   bool
}

func (f *fakeFilterSession) add(netip.Addr) ([2]uint64, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.next += 2
	ids := [2]uint64{f.next - 1, f.next}
	if f.active == nil {
		f.active = make(map[[2]uint64]bool)
	}
	f.active[ids] = true
	return ids, nil
}

func (f *fakeFilterSession) remove(ids [2]uint64) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.failDrop {
		return errors.New("remove failed")
	}
	delete(f.active, ids)
	return nil
}

func (f *fakeFilterSession) close() error {
	f.mu.Lock()
	defer f.mu.Unlock()
	clear(f.active)
	f.closed = true
	return nil
}

func waitForLeaseState(t *testing.T, check func() bool) {
	t.Helper()
	deadline := time.After(5 * time.Second)
	ticker := time.NewTicker(10 * time.Millisecond)
	defer ticker.Stop()
	for !check() {
		select {
		case <-ticker.C:
		case <-deadline:
			t.Fatal("firewall lease state did not settle")
		}
	}
}

func TestFilterLeaseRefreshAndExpiry(t *testing.T) {
	session := &fakeFilterSession{}
	leases := newFilterLeases(session)
	t.Cleanup(func() { _ = leases.close() })
	ip := netip.MustParseAddr("192.0.2.9")
	if _, err := leases.block(ip, "original", time.Hour); err != nil {
		t.Fatal(err)
	}
	if _, err := leases.block(ip, "refreshed", 50*time.Millisecond); err != nil {
		t.Fatal(err)
	}
	session.mu.Lock()
	adds, rules := session.next, len(session.active)
	session.mu.Unlock()
	if adds != 2 || rules > 1 {
		t.Fatalf("refresh duplicated rules: next=%d, active=%d", adds, rules)
	}
	waitForLeaseState(t, func() bool {
		entries, err := leases.list()
		return len(entries) == 0 && err == nil
	})
	session.mu.Lock()
	defer session.mu.Unlock()
	if len(session.active) != 0 || session.closed {
		t.Fatalf("expiry did not remove only its own filters: %+v", session.active)
	}
}

func TestFilterLeaseReleaseFailureClosesSession(t *testing.T) {
	session := &fakeFilterSession{failDrop: true}
	leases := newFilterLeases(session)
	t.Cleanup(func() { _ = leases.close() })
	if _, err := leases.block(netip.MustParseAddr("192.0.2.2"), "first", time.Hour); err != nil {
		t.Fatal(err)
	}
	if _, err := leases.block(netip.MustParseAddr("2001:db8::2"), "second", time.Millisecond); err != nil {
		t.Fatal(err)
	}
	waitForLeaseState(t, func() bool {
		session.mu.Lock()
		defer session.mu.Unlock()
		return session.closed && len(session.active) == 0
	})
	if _, err := leases.block(netip.MustParseAddr("192.0.2.3"), "after failure", time.Hour); err == nil {
		t.Fatal("accepted a new lease after the firewall session failed")
	}
}
