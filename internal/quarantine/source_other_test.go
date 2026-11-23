//go:build !windows && (!cgo || (!linux && !darwin))

package quarantine

import (
	"errors"
	"os"
	"path/filepath"
	"testing"
)

func TestUnsupportedRemovalKeepsVaultCopy(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "source")
	if err := os.WriteFile(path, []byte("original"), 0o600); err != nil {
		t.Fatal(err)
	}
	vault, err := Open(filepath.Join(dir, "vault"))
	if err != nil {
		t.Fatal(err)
	}
	entry, err := vault.Quarantine(path, "fixture", false)
	if !errors.Is(err, ErrSafeRemovalUnavailable) {
		t.Fatalf("quarantine error = %v, want ErrSafeRemovalUnavailable", err)
	}
	if err := vault.Verify(entry.ID); err != nil {
		t.Fatal(err)
	}
	if got, err := os.ReadFile(path); err != nil || string(got) != "original" {
		t.Fatalf("source = %q, error = %v", got, err)
	}
}
