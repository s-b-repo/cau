package inventory

import (
	"bytes"
	"context"
	"encoding/xml"
	"errors"
	"io"
	"io/fs"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/s-b-repo/cau/internal/parallel"
)

const plistLimit = 256 << 10

func platformCollections(ctx context.Context) []Collection {
	ctx, cancel := context.WithTimeout(ctx, 45*time.Second)
	defer cancel()
	var receipts, apps Collection
	parallel.Do(
		func() { receipts = macReceipts(ctx) },
		func() { apps = macApplications(ctx) },
	)
	return []Collection{receipts, apps}
}

func macReceipts(ctx context.Context) Collection {
	const pkgutil = "/usr/sbin/pkgutil"
	c := collection("macos-receipts", "system")
	data, err := runQuery(ctx, maxQueryBytes, nil, pkgutil, "--pkgs")
	if err != nil {
		c.fail(err, "installer receipt list could not be read")
		return c
	}
	ids := strings.Fields(string(data))
	if len(ids) > maxPackages {
		c.fail(nil, "installer receipt count exceeds the limit")
		return c
	}
	packages := make([]Package, len(ids))
	parallel.For(len(ids), 4, func(i int) {
		id := ids[i]
		if !validMacID(id) || ctx.Err() != nil {
			return
		}
		data, err := runQuery(ctx, plistLimit, nil, pkgutil, "--pkg-info-plist", id)
		if err != nil {
			return
		}
		fields, err := plistStrings(data)
		if err != nil || fields["pkgid"] != id || !validInventoryField(fields["pkg-version"]) {
			return
		}
		packages[i] = Package{ID: id, Name: id, Version: fields["pkg-version"]}
	})
	appendMacPackages(&c, packages, "some installer receipts could not be read or validated")
	return c
}

func macApplications(ctx context.Context) Collection {
	c := collection("macos-applications", "shared-application-directories")
	var incomplete error
	seen := make(map[[2]string]bool)
	for _, path := range []string{"/Applications", "/Applications/Utilities", "/System/Applications", "/System/Applications/Utilities"} {
		packages, err := macAppsIn(ctx, path)
		if err != nil {
			incomplete = err
		}
		for _, pkg := range packages {
			key := [2]string{pkg.ID, pkg.Version}
			if !seen[key] {
				seen[key] = true
				c.Packages = append(c.Packages, pkg)
			}
			if len(c.Packages) == maxPackages {
				c.fail(nil, "application bundle count exceeds the limit")
				return c
			}
		}
	}
	if incomplete != nil {
		c.fail(incomplete, "some shared application bundles could not be read or validated")
	}
	return c
}

func macAppsIn(ctx context.Context, path string) ([]Package, error) {
	root, err := os.OpenRoot(path)
	if errors.Is(err, fs.ErrNotExist) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	defer root.Close()
	dir, err := root.Open(".")
	if err != nil {
		return nil, err
	}
	defer dir.Close()
	entries, err := dir.ReadDir(maxPackages + 1)
	if err != nil && !errors.Is(err, io.EOF) {
		return nil, err
	}
	if len(entries) > maxPackages {
		return nil, errors.New("application directory exceeds the entry limit")
	}
	var packages []Package
	var incomplete error
	for _, entry := range entries {
		if err := ctx.Err(); err != nil {
			return packages, err
		}
		if !entry.IsDir() || !strings.EqualFold(filepath.Ext(entry.Name()), ".app") {
			continue
		}
		pkg, err := macApplication(ctx, root, entry.Name())
		if err != nil {
			incomplete = err
			continue
		}
		packages = append(packages, pkg)
	}
	return packages, incomplete
}

func macApplication(ctx context.Context, root *os.Root, name string) (Package, error) {
	data, err := readRootFile(root, filepath.Join(name, "Contents", "Info.plist"), plistLimit)
	if err != nil {
		return Package{}, err
	}
	if bytes.HasPrefix(data, []byte("bplist00")) {
		data, err = runQuery(ctx, plistLimit, bytes.NewReader(data), "/usr/bin/plutil", "-convert", "xml1", "-o", "-", "-")
		if err != nil {
			return Package{}, err
		}
	}
	fields, err := plistStrings(data)
	if err != nil {
		return Package{}, err
	}
	id := fields["CFBundleIdentifier"]
	version := fields["CFBundleShortVersionString"]
	if version == "" {
		version = fields["CFBundleVersion"]
	}
	label := fields["CFBundleDisplayName"]
	if label == "" {
		label = fields["CFBundleName"]
	}
	if label == "" {
		label = strings.TrimSuffix(name, filepath.Ext(name))
	}
	if !validMacID(id) || !validInventoryField(label) || !validInventoryField(version) {
		return Package{}, errors.New("invalid application bundle metadata")
	}
	return Package{ID: id, Name: label, Version: version}, nil
}

func validMacID(s string) bool {
	return validInventoryField(s) && !strings.HasPrefix(s, "-") && !strings.ContainsAny(s, "/\\ \t")
}

func appendMacPackages(c *Collection, packages []Package, reason string) {
	incomplete := false
	for _, pkg := range packages {
		if pkg.ID == "" {
			incomplete = true
			continue
		}
		c.Packages = append(c.Packages, pkg)
	}
	if incomplete {
		c.fail(nil, reason)
	}
}

// Read the top-level strings and ignore non-string values, including nested dictionaries.
func plistStrings(data []byte) (map[string]string, error) {
	type field struct {
		XMLName xml.Name
		Text    string `xml:",chardata"`
	}
	var plist struct {
		XMLName xml.Name
		Dict    *struct {
			Fields []field `xml:",any"`
		} `xml:"dict"`
	}
	if err := xml.Unmarshal(data, &plist); err != nil {
		return nil, err
	}
	if plist.XMLName.Local != "plist" || plist.Dict == nil || len(plist.Dict.Fields)%2 != 0 {
		return nil, errors.New("invalid property list")
	}
	values := make(map[string]string)
	for i := 0; i < len(plist.Dict.Fields); i += 2 {
		k, v := plist.Dict.Fields[i], plist.Dict.Fields[i+1]
		if k.XMLName.Local != "key" {
			return nil, errors.New("invalid property list dictionary")
		}
		if v.XMLName.Local == "string" {
			if _, exists := values[k.Text]; exists {
				return nil, errors.New("duplicate property list key")
			}
			values[k.Text] = v.Text
		}
	}
	return values, nil
}
