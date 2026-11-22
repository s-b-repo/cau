package inventory

import (
	"context"
	"os"
	"path/filepath"
	"testing"
)

func TestInventoryMacBundle(t *testing.T) {
	path := t.TempDir()
	const app = "Example.app"
	dir := filepath.Join(path, app, "Contents")
	if err := os.MkdirAll(dir, 0o700); err != nil {
		t.Fatal(err)
	}
	data := []byte(`<?xml version="1.0" encoding="UTF-8"?>
<plist version="1.0"><dict>
<key>CFBundleIdentifier</key><string>org.example.fixture</string>
<key>CFBundleName</key><string>Example &amp; Demo</string>
<key>CFBundleVersion</key><string>3010</string>
<key>Resources</key><dict><key>ignored</key><string>ignored value</string></dict>
</dict></plist>`)
	if err := os.WriteFile(filepath.Join(dir, "Info.plist"), data, 0o600); err != nil {
		t.Fatal(err)
	}
	root, err := os.OpenRoot(path)
	if err != nil {
		t.Fatal(err)
	}
	defer root.Close()
	pkg, err := macApplication(context.Background(), root, app)
	if err != nil || pkg.ID != "org.example.fixture" || pkg.Name != "Example & Demo" || pkg.Version != "3010" {
		t.Fatalf("mac application metadata: %+v, %v", pkg, err)
	}
}
