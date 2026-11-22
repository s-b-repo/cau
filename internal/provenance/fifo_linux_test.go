package provenance

import (
	"os"
	"path/filepath"
	"strings"
	"syscall"
	"testing"
)

func TestFIFODatabaseFileDoesNotHang(t *testing.T) {
	root := dpkgRoot(t)
	status := filepath.Join(root, "var", "lib", "dpkg", "status")
	if err := os.Remove(status); err != nil {
		t.Fatal(err)
	}
	if err := syscall.Mkfifo(status, 0o644); err != nil {
		t.Skip("mkfifo:", err)
	}
	fifoList := filepath.Join(root, "var", "lib", "dpkg", "info", "fifo.list")
	if err := syscall.Mkfifo(fifoList, 0o644); err != nil {
		t.Skip("mkfifo:", err)
	}
	done := make(chan *Resolver, 1)
	go func() {
		r := New(root)
		r.Load()
		done <- r
	}()
	r := <-done // the test's own timeout is the backstop
	notes := strings.Join(r.Notes(), "\n")
	if !strings.Contains(notes, "status") || !strings.Contains(notes, "fifo.list") {
		t.Errorf("notes should record both FIFOs:\n%s", notes)
	}
	// Without status there is no version, but ownership still resolves.
	if got := r.Lookup(filepath.Join(root, "usr/bin/ls"), digestsOf(lsBytes)); got.State != OwnedIntact || got.Version != "" {
		t.Errorf("ls without status: %+v", got)
	}
}
