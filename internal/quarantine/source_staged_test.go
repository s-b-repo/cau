//go:build (linux || darwin) && cgo

package quarantine

import (
	"crypto/sha256"
	"errors"
	"os"
	"path/filepath"
	"syscall"
	"testing"
)

func TestStagedReplacementIsRestoredOrPreserved(t *testing.T) {
	for _, occupy := range []bool{false, true} {
		name := "restore"
		if occupy {
			name = "preserve"
		}
		t.Run(name, func(t *testing.T) {
			dir := t.TempDir()
			path := writeSample(t, dir, "source", []byte("scanned"), 0o600)
			source, info, data := readSourceForTest(t, path)

			var stagedPath string
			err := source.removeWithRename(info, int64(len(data)), sha256.Sum256(data),
				func(from *os.File, base string, to *os.File, slot string) error {
					if err := os.Rename(path, filepath.Join(dir, "first")); err != nil {
						t.Fatal(err)
					}
					writeSample(t, dir, base, []byte("replacement"), 0o600)
					if err := renameNoReplace(from, base, to, slot); err != nil {
						return err
					}
					if occupy {
						stagedPath = filepath.Join(dir, stageDirName(), slot)
						writeSample(t, dir, base, []byte("new occupant"), 0o600)
					}
					return nil
				})
			if !errors.Is(err, ErrPathChanged) {
				t.Fatalf("error = %v, want ErrPathChanged", err)
			}
			want := "replacement"
			if occupy {
				want = "new occupant"
				if !errors.Is(err, syscall.EEXIST) {
					t.Fatalf("rollback did not report the occupied path: %v", err)
				}
				if staged, err := os.ReadFile(stagedPath); err != nil || string(staged) != "replacement" {
					t.Fatalf("staged replacement = %q, err = %v", staged, err)
				}
			}
			if got, err := os.ReadFile(path); err != nil || string(got) != want {
				t.Fatalf("source path = %q, err = %v, want %q", got, err, want)
			}
		})
	}
}

func TestResolveQuarantinePathChecksParentSymlinkTarget(t *testing.T) {
	if _, err := os.Stat("/etc/passwd"); err != nil {
		t.Skip("no /etc/passwd")
	}
	dir := t.TempDir()
	link := filepath.Join(dir, "parent")
	if err := os.Symlink("/etc", link); err != nil {
		t.Fatal(err)
	}
	if _, err := resolveQuarantinePath(filepath.Join(link, "passwd")); err == nil {
		t.Fatal("a symlinked parent bypassed protected-path validation")
	}
}
