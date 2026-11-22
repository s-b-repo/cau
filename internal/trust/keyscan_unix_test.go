//go:build unix

package trust

import (
	"path/filepath"
	"syscall"
	"testing"
	"time"
)

// A FIFO reports a size of zero, so it passes a stat-based size check; an
// unbounded read then blocks forever on a writer that never comes. A named pipe
// called priv.hex in /etc/cau would hang the daemon at startup.
func TestSigningKeysNearbyDoesNotHangOnAFIFO(t *testing.T) {
	dir := t.TempDir()
	if err := syscall.Mkfifo(filepath.Join(dir, "priv.hex"), 0o600); err != nil {
		t.Skipf("mkfifo unavailable: %v", err)
	}
	done := make(chan []string, 1)
	go func() { done <- SigningKeysNearby(dir) }()
	select {
	case found := <-done:
		if len(found) != 0 {
			t.Errorf("a FIFO is not a signing key: %v", found)
		}
	case <-time.After(10 * time.Second):
		t.Fatal("SigningKeysNearby blocked on a FIFO: a named pipe in /etc/cau would hang the daemon at startup")
	}
}
