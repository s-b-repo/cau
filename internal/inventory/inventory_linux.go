package inventory

import (
	"bufio"
	"bytes"
	"context"
	"errors"
	"io"
	"io/fs"
	"os"
	"path/filepath"
	"strings"
	"time"
	"unicode"

	"github.com/s-b-repo/cau/internal/safefs"
)

const dpkgFormat = `--showformat=${db:Status-Status}\t${Package}\t${Version}\t${Architecture}\n`
const rpmFormat = `%{NAME}\t%{EPOCHNUM}:%{VERSION}-%{RELEASE}\t%{ARCH}\n`

func platformCollections(ctx context.Context) []Collection {
	var out []Collection
	if present("/var/lib/dpkg/status") {
		out = append(out, queryPackages(ctx, "dpkg", "/var/lib/dpkg/status", "/usr/bin/dpkg-query", "--admindir=/var/lib/dpkg", "--show", dpkgFormat))
	}
	if present("/var/lib/pacman/local") {
		out = append(out, pacmanPackages(ctx, "/var/lib/pacman/local"))
	}
	if database := systemRPMDatabase(); database != "" {
		out = append(out, queryPackages(ctx, "rpm", database, "/usr/bin/rpm", "--noplugins", "--dbpath", filepath.Dir(database),
			"--query", "--all", "--queryformat", rpmFormat))
	}
	if len(out) == 0 {
		return []Collection{{Provider: "system-packages", Scope: "system", Status: Unsupported, Reason: "no dpkg, pacman, or system RPM database found"}}
	}
	return out
}

func systemRPMDatabase() string {
	for _, dir := range []string{"/usr/lib/sysimage/rpm", "/var/lib/rpm"} {
		for _, name := range []string{"rpmdb.sqlite", "Packages", "Packages.db"} {
			path := filepath.Join(dir, name)
			if present(path) {
				return path
			}
		}
	}
	return ""
}

func present(path string) bool {
	_, err := os.Stat(path)
	return !errors.Is(err, fs.ErrNotExist)
}

// A native query keeps version and install-state semantics with the package
// manager. Fixed paths and environment avoid resolving a tool from the caller's PATH.
func queryPackages(ctx context.Context, provider, database, executable string, args ...string) Collection {
	c := collection(provider, "system")
	f, _, err := safefs.Open(database)
	if err != nil {
		c.fail(err, "package database could not be read")
		return c
	}
	f.Close()
	ctx, cancel := context.WithTimeout(ctx, 15*time.Second)
	defer cancel()
	data, err := runQuery(ctx, maxQueryBytes, nil, executable, args...)
	if err != nil {
		c.fail(err, "package manager query failed")
		if errors.Is(err, fs.ErrNotExist) {
			c.Status = Unsupported
			c.Reason = "package manager query tool is unavailable"
		}
		if errors.Is(ctx.Err(), context.Canceled) {
			c.Reason = "package manager query was cancelled"
		} else if errors.Is(ctx.Err(), context.DeadlineExceeded) {
			c.Reason = "package manager query timed out"
		}
		if errors.Is(err, safefs.ErrTooLarge) {
			c.Reason = "package manager output exceeds the limit"
		}
		return c
	}
	return parseQuery(c, data)
}

func parseQuery(c Collection, data []byte) Collection {
	s := bufio.NewScanner(bytes.NewReader(data))
	s.Buffer(make([]byte, 0, 4096), 64<<10)
	seen := make(map[[2]string]bool)
	malformed := false
	for s.Scan() {
		row := strings.Split(s.Text(), "\t")
		if c.Provider == "dpkg" {
			if len(row) != 4 {
				malformed = true
				continue
			}
			switch row[0] {
			case "installed", "triggers-pending", "triggers-awaited":
				row = row[1:]
			case "not-installed", "config-files", "half-installed", "unpacked", "half-configured":
				continue
			}
		}
		if len(row) != 3 || !validPackageField(row[0]) || !validPackageField(row[1]) || !validPackageField(row[2]) {
			malformed = true
			continue
		}
		id := row[0] + ":" + row[2]
		key := [2]string{id, row[1]}
		if seen[key] {
			continue
		}
		if len(c.Packages) == maxPackages {
			c.fail(nil, "package count exceeds the limit")
			return c
		}
		seen[key] = true
		c.Packages = append(c.Packages, Package{ID: id, Name: row[0], Version: row[1], Architecture: row[2]})
	}
	if malformed || s.Err() != nil {
		c.fail(s.Err(), "invalid package manager output")
	}
	return c
}

func validPackageField(s string) bool {
	return validInventoryField(s) &&
		!strings.ContainsAny(s, `/\`) && strings.IndexFunc(s, func(r rune) bool {
		return unicode.IsSpace(r)
	}) < 0
}

func pacmanPackages(ctx context.Context, path string) Collection {
	c := collection("pacman", "system")
	root, err := os.OpenRoot(path)
	if err != nil {
		c.fail(err, "pacman database is unavailable")
		return c
	}
	defer root.Close()
	dir, err := root.Open(".")
	if err != nil {
		c.fail(err, "pacman database directory could not be opened")
		return c
	}
	defer dir.Close()
	before, err := dir.Stat()
	if err != nil {
		c.fail(err, "pacman database directory could not be inspected")
		return c
	}
	entries, err := dir.ReadDir(maxPackages + 2) // also leaves space for ALPM_DB_VERSION
	if err != nil && !errors.Is(err, io.EOF) {
		c.fail(err, "pacman database directory could not be read")
		return c
	}
	if len(entries) == maxPackages+2 {
		c.fail(nil, "pacman database directory exceeds the entry limit")
		return c
	}
	var incomplete error
	seen := make(map[string]bool)
	for _, entry := range entries {
		if err := ctx.Err(); err != nil {
			c.fail(err, "pacman collection was interrupted")
			return c
		}
		if entry.Name() == "ALPM_DB_VERSION" && entry.Type().IsRegular() {
			continue
		}
		if !entry.IsDir() {
			incomplete = errors.New("unexpected database entry")
			continue
		}
		pkg, err := pacmanPackage(root, filepath.Join(entry.Name(), "desc"))
		if err != nil {
			incomplete = err
			continue
		}
		if seen[pkg.ID] {
			incomplete = errors.New("duplicate package ID")
			continue
		}
		if len(c.Packages) == maxPackages {
			c.fail(nil, "pacman package count exceeds the limit")
			return c
		}
		seen[pkg.ID] = true
		c.Packages = append(c.Packages, pkg)
	}
	if incomplete != nil {
		c.fail(incomplete, "some pacman package records could not be read or validated")
		return c
	}
	after, err := dir.Stat()
	if err != nil || !after.ModTime().Equal(before.ModTime()) {
		c.fail(err, "pacman database directory changed during collection")
	}
	return c
}

func pacmanPackage(root *os.Root, path string) (Package, error) {
	data, err := readRootFile(root, path, 64<<10)
	if err != nil {
		return Package{}, err
	}
	return parsePacmanRecord(data)
}

func parsePacmanRecord(data []byte) (Package, error) {
	var pkg Package
	var target *string
	s := bufio.NewScanner(bytes.NewReader(data))
	s.Buffer(make([]byte, 0, 4096), 64<<10)
	for s.Scan() {
		line := s.Text()
		if target != nil {
			if *target != "" || !validPackageField(line) {
				return Package{}, errors.New("invalid pacman package field")
			}
			*target = line
			target = nil
			continue
		}
		switch line {
		case "%NAME%":
			target = &pkg.Name
		case "%VERSION%":
			target = &pkg.Version
		case "%ARCH%":
			target = &pkg.Architecture
		}
	}
	if target != nil || s.Err() != nil || pkg.Name == "" || pkg.Version == "" || pkg.Architecture == "" {
		return Package{}, errors.New("incomplete pacman package record")
	}
	pkg.ID = pkg.Name + ":" + pkg.Architecture
	return pkg, nil
}
