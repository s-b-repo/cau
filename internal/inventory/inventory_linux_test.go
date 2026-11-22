package inventory

import (
	"context"
	"os"
	"path/filepath"
	"testing"
)

func TestInventoryQueryScope(t *testing.T) {
	c := parseQuery(collection("dpkg", "system"), []byte(
		"installed\tlibfixture\t2:1.0-3\tamd64\n"+
			"triggers-pending\tlibfixture\t2:1.0-3\ti386\n"+
			"config-files\tremoved\t1.0-1\tall\n"+
			"unknown\tinvalid\t1\tall\n"))
	if c.Status != Partial || len(c.Packages) != 2 || c.Packages[0].Version != "2:1.0-3" ||
		c.Packages[0].ID != "libfixture:amd64" || c.Packages[1].ID != "libfixture:i386" {
		t.Fatalf("dpkg collection has unexpected coverage or records: %+v", c)
	}
	c = parseQuery(collection("rpm", "system"), []byte("kernel\t0:1-1\tx86_64\nkernel\t0:2-1\tx86_64\nkernel\t0:2-1\tx86_64\n"))
	if c.Status != Complete || len(c.Packages) != 2 || c.Packages[0].ID != c.Packages[1].ID {
		t.Fatalf("RPM should retain distinct installed versions and deduplicate repeats: %+v", c)
	}
}

func TestInventoryPacmanReportsUnreadableRecords(t *testing.T) {
	root := t.TempDir()
	writeRecord := func(name, text string) {
		t.Helper()
		dir := filepath.Join(root, name)
		if err := os.Mkdir(dir, 0o700); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(filepath.Join(dir, "desc"), []byte(text), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	const fixture = "%NAME%\nfixture\n\n%VERSION%\n1:1.2.0-2\n\n%ARCH%\nx86_64\n"
	writeRecord("fixture-1.2.0-2", fixture)
	if c := pacmanPackages(context.Background(), root); c.Status != Complete || len(c.Packages) != 1 || c.Packages[0].Version != "1:1.2.0-2" {
		t.Fatalf("complete pacman collection: %+v", c)
	}
	writeRecord("invalid-1.0-1", "%NAME%\ninvalid\n\n%VERSION%\n1.0-1\n")
	if err := os.Symlink(t.TempDir(), filepath.Join(root, "symlink-1.0-1")); err != nil {
		t.Fatal(err)
	}
	if c := pacmanPackages(context.Background(), root); c.Status != Partial || len(c.Packages) != 1 {
		t.Fatalf("partially unreadable pacman collection: %+v", c)
	}
}
