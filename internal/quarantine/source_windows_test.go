package quarantine

import (
	"errors"
	"os"
	"path/filepath"
	"testing"
)

func TestWindowsQuarantinePreservesBusySourceAndVaultCopy(t *testing.T) {
	dir := t.TempDir()
	path := writeSample(t, dir, "live", []byte("original"), 0o600)
	writer, err := os.OpenFile(path, os.O_WRONLY, 0)
	if err != nil {
		t.Fatal(err)
	}
	defer writer.Close()
	vault, err := Open(filepath.Join(dir, "vault"))
	if err != nil {
		t.Fatal(err)
	}

	entry, err := vault.Quarantine(path, "fixture", false)
	if err == nil || entry.ID == "" {
		t.Fatalf("busy source returned entry %q and error %v", entry.ID, err)
	}
	if err := vault.Verify(entry.ID); err != nil {
		t.Fatalf("vault copy is missing or invalid: %v", err)
	}
	if data, err := os.ReadFile(path); err != nil || string(data) != "original" {
		t.Fatalf("live source = %q, error = %v", data, err)
	}
}

func TestWindowsQuarantinePinsTheAuthorizedHandle(t *testing.T) {
	dir := t.TempDir()
	path := writeSample(t, dir, "live", []byte("original"), 0o600)
	vault, err := Open(filepath.Join(dir, "vault"))
	if err != nil {
		t.Fatal(err)
	}

	original := removeOriginal
	t.Cleanup(func() { removeOriginal = original })
	removeOriginal = func(source *quarantineSource, info os.FileInfo, size int64, digest [32]byte) error {
		if err := os.Rename(path, filepath.Join(dir, "moved")); err == nil {
			t.Fatal("a second handle was able to rename the source")
		}
		return original(source, info, size, digest)
	}
	entry, err := vault.Quarantine(path, "fixture", false)
	if err != nil {
		t.Fatal(err)
	}
	if err := vault.Verify(entry.ID); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Lstat(path); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("source still exists after handle-based removal: %v", err)
	}
}
