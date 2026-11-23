//go:build windows || (darwin && cgo)

package watch

import (
	"os"
	"path/filepath"
	"testing"
	"time"
)

func TestNativeWatcherReportsFileChanges(t *testing.T) {
	parent, err := filepath.EvalSymlinks(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	root := filepath.Join(parent, "watch")
	if err := os.Mkdir(root, 0o700); err != nil {
		t.Fatal(err)
	}
	write := func(t *testing.T, path, contents string) {
		t.Helper()
		if err := os.WriteFile(path, []byte(contents), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	existing := filepath.Join(root, "existing.txt")
	write(t, existing, "before")
	w, err := New([]string{root, root, filepath.Join(parent, "missing")}, 1)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = w.Close() })
	if w.Dirs() != 1 || w.Truncated() {
		t.Fatalf("duplicate and missing roots changed coverage: %d, truncated=%v", w.Dirs(), w.Truncated())
	}
	events, done := make(chan Event, 128), make(chan error, 1)
	go func() {
		done <- w.Run(func(event Event) {
			select {
			case events <- event:
			default:
			}
		})
	}()
	expect := func(t *testing.T, condition func(Event) bool, detail string) {
		t.Helper()
		timer := time.NewTimer(10 * time.Second)
		defer timer.Stop()
		for {
			select {
			case event := <-events:
				if condition(event) {
					return
				}
			case <-timer.C:
				t.Fatalf("watcher did not report %s", detail)
			}
		}
	}
	write(t, existing, "a different file size")
	expect(t, func(event Event) bool { return samePath(event.Path, existing) }, "an in-place write")

	descendant := filepath.Join(root, "descendant")
	if err := os.Mkdir(descendant, 0o700); err != nil {
		t.Fatal(err)
	}
	expect(t, func(event Event) bool { return event.Overflow }, "a rescan for the new directory")
	child := filepath.Join(descendant, "audit.txt")
	write(t, child, "new file")
	expect(t, func(event Event) bool { return samePath(event.Path, child) }, "a new file in a descendant")

	t.Run("moved-tree", func(t *testing.T) {
		source := filepath.Join(parent, "ready")
		if err := os.Mkdir(source, 0o700); err != nil {
			t.Fatal(err)
		}
		write(t, filepath.Join(source, "preexisting.txt"), "renamed into scope")
		target := filepath.Join(root, "moved")
		if err := os.Rename(source, target); err != nil {
			t.Fatal(err)
		}
		expect(t, func(event Event) bool { return event.Overflow }, "a rescan for the moved directory")
		child := filepath.Join(target, "測試.txt")
		write(t, child, "new file")
		expect(t, func(event Event) bool { return samePath(event.Path, child) }, "a new file in the moved directory")
	})

	if err := w.Close(); err != nil {
		t.Fatal(err)
	}
	select {
	case err := <-done:
		if err != nil {
			t.Fatal(err)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("watch did not stop")
	}
}
