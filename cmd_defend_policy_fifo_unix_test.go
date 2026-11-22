//go:build unix

package main

import (
	"os"
	"path/filepath"
	"syscall"
	"testing"
	"time"
)

// A pipe where the public key belongs is refused outright rather than waited on.
//
// `cau defend` resolves the key at startup, before it signals readiness. A pipe
// held open by a silent writer made that read wait 120.1s, against systemd's
// 90s default TimeoutStartSec — so the unit was killed as a failed start and
// restarted into the same wall. An attacker with write access to the directory
// holding the public key had a kill switch needing no edit to the unit file or
// the flags. Pipes stay allowed for --sign-key, where the point is keeping a
// secret off disk; a public key is not a secret and $CAU_SELFTEST_PUBKEY
// already supplies one without a file.
func TestPinnedKeyFromAPipeIsRefusedNotAwaited(t *testing.T) {
	dir := t.TempDir()
	fifo := filepath.Join(dir, "pub.hex")
	if err := syscall.Mkfifo(fifo, 0o600); err != nil {
		t.Skipf("mkfifo unavailable: %v", err)
	}
	// A writer that opens and then says nothing: the case that waited.
	w, err := os.OpenFile(fifo, os.O_WRONLY|syscall.O_NONBLOCK, 0)
	if err == nil {
		defer w.Close()
	}

	done := make(chan error, 1)
	go func() {
		_, err := resolveSelftestPubkey(fifo)
		done <- err
	}()
	select {
	case err := <-done:
		if err == nil {
			t.Error("a pipe is not a public key file; it must be refused")
		}
	case <-time.After(15 * time.Second):
		t.Fatal("resolveSelftestPubkey waited on a pipe: at daemon startup that is a failed start, and on retry a kill switch")
	}
}
