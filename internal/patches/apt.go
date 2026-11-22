package patches

import (
	"bufio"
	"bytes"
	"context"
	"errors"
	"os"
	"path/filepath"
	"regexp"
	"slices"
	"strconv"
	"strings"
	"time"
)

const (
	aptGet         = "/usr/bin/apt-get"
	aptIndexMaxAge = 7 * 24 * time.Hour
	aptIndexFormat = "$(FILENAME)\t$(SITE)\t$(RELEASE)\t$(COMPONENT)"
)

var (
	nativeToken = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9.+:~_-]{0,255}$`)
	aptID       = regexp.MustCompile(`^[a-z0-9][a-z0-9+.-]+(:[a-z0-9-]+)?$`)
	aptArch     = regexp.MustCompile(`^[a-z0-9][a-z0-9-]{0,31}$`)
	aptSummary  = regexp.MustCompile(`^([0-9]+) upgraded, ([0-9]+) newly installed, ([0-9]+) to remove and ([0-9]+) not upgraded\.$`)
)

func collectAPT(ctx context.Context, result *Assessment, query nativeQuery, stat func(string) (os.FileInfo, error), now func() time.Time) {
	result.Source = "apt-upgrade-simulation"
	result.AssessmentStatus = Unknown

	current, currentWarning, currentErr := query(ctx, aptGet, "indextargets", "--format", aptIndexFormat, "Identifier: Packages")
	config, configWarning, configErr := query(ctx, aptGet, "indextargets", "--no-release-info", "--format", aptIndexFormat, "Identifier: Packages")
	if currentErr != nil || configErr != nil {
		result.Warnings = append(result.Warnings, "APT package metadata inventory did not complete")
	} else {
		meta, err := readAPTMetadata(current, config, stat, now())
		if err != nil {
			result.Warnings = append(result.Warnings, "APT package metadata inventory could not be verified")
		} else {
			result.Metadata = meta
		}
	}

	plan, planWarning, err := query(ctx, aptGet, "--simulate", "--no-remove",
		"-o", "APT::Get::Upgrade-Allow-New=false", "-o", "Dir::Cache::pkgcache=",
		"-o", "Dir::Cache::srcpkgcache=", "upgrade")
	if err != nil {
		result.Warnings = append(result.Warnings, "APT upgrade simulation did not complete")
		return
	}
	updates, deferred, err := parseAPTPlan(plan)
	if err != nil {
		result.Warnings = append(result.Warnings, "APT upgrade simulation output could not be verified")
		return
	}
	result.Updates = updates
	result.DeferredUpdates = &deferred
	assessedAt := now().UTC()
	result.AssessedAt = &assessedAt

	result.AssessmentStatus = Complete
	if result.Metadata.Status != Current {
		result.AssessmentStatus = Partial
		result.Warnings = append(result.Warnings, "APT package metadata is stale, incomplete or unavailable")
	}
	if currentWarning || configWarning || planWarning {
		result.AssessmentStatus = Partial
		result.Warnings = append(result.Warnings, "APT reported diagnostics during collection")
	}
}

type aptTarget struct {
	path  string
	group string // Site, suite and component. Empty architecture variants are normal.
}

func readAPTTargets(data []byte) ([]aptTarget, error) {
	targets := []aptTarget{}
	s := bufio.NewScanner(bytes.NewReader(data))
	s.Buffer(make([]byte, 0, 4096), 64<<10)
	for s.Scan() {
		fields := strings.Split(s.Text(), "\t")
		if len(fields) != 4 || !filepath.IsAbs(fields[0]) || fields[1] == "" || fields[1] == "$(SITE)" || fields[2] == "$(RELEASE)" {
			return nil, errors.New("unrecognized APT index target")
		}
		targets = append(targets, aptTarget{path: fields[0], group: strings.Join(fields[1:], "\t")})
	}
	return targets, s.Err()
}

func readAPTMetadata(current, config []byte, stat func(string) (os.FileInfo, error), now time.Time) (Metadata, error) {
	result := Metadata{Status: Unknown}
	active, err := readAPTTargets(current)
	if err != nil {
		return result, err
	}
	configured, err := readAPTTargets(config)
	if err != nil {
		return result, err
	}

	paths := make(map[string]struct{}, len(active))
	groups := make(map[string]bool, len(configured))
	latestIndexTime := now.Add(5 * time.Minute)
	for _, target := range active {
		groups[target.group] = true
		if _, checked := paths[target.path]; checked {
			continue
		}
		paths[target.path] = struct{}{}
		mtime := aptIndexTime(target.path, stat)
		if mtime.IsZero() || mtime.Compare(latestIndexTime) > 0 {
			result.MissingIndexes++
			continue
		}
		result.KnownIndexes++
		if result.OldestIndexAt == nil || mtime.Before(*result.OldestIndexAt) {
			result.OldestIndexAt = &mtime
		}
	}
	for _, target := range configured {
		if _, seen := groups[target.group]; !seen {
			result.MissingSources++
			groups[target.group] = false
		}
	}

	switch {
	case result.KnownIndexes == 0 || len(configured) == 0:
	case result.MissingIndexes != 0 || result.MissingSources != 0:
		result.Status = Partial
	case now.Sub(*result.OldestIndexAt) > aptIndexMaxAge:
		result.Status = Stale
	default:
		result.Status = Current
	}
	return result, nil
}

func aptIndexTime(path string, stat func(string) (os.FileInfo, error)) time.Time {
	for _, extension := range []string{"", ".lz4", ".zst", ".gz", ".xz", ".bz2", ".lzma"} {
		if info, err := stat(path + extension); err == nil && info.Mode().IsRegular() {
			return info.ModTime().UTC()
		}
	}
	return time.Time{}
}

func parseAPTPlan(data []byte) ([]Update, int, error) {
	updates := []Update{}
	seen := map[[2]string]bool{}
	expected, deferred := -1, 0
	s := bufio.NewScanner(bytes.NewReader(data))
	s.Buffer(make([]byte, 0, 4096), 64<<10)
	for s.Scan() {
		line := s.Text()
		switch {
		case strings.HasPrefix(line, "Inst "):
			update, err := parseAPTUpgrade(strings.TrimPrefix(line, "Inst "))
			if err != nil {
				return nil, 0, err
			}
			key := [2]string{update.ID, update.Architecture}
			if seen[key] {
				return nil, 0, errors.New("duplicate APT upgrade")
			}
			seen[key] = true
			updates = append(updates, update)
		case strings.HasPrefix(line, "Remv ") || strings.HasPrefix(line, "Purg "):
			return nil, 0, errors.New("unexpected APT removal operation")
		default:
			if summary := aptSummary.FindStringSubmatch(line); summary != nil {
				if expected >= 0 || summary[2] != "0" || summary[3] != "0" {
					return nil, 0, errors.New("unexpected APT upgrade summary")
				}
				var err error
				expected, err = strconv.Atoi(summary[1])
				if err != nil {
					return nil, 0, err
				}
				deferred, err = strconv.Atoi(summary[4])
				if err != nil {
					return nil, 0, err
				}
			}
		}
	}
	if err := s.Err(); err != nil {
		return nil, 0, err
	}
	if expected != len(updates) {
		return nil, 0, errors.New("APT upgrade summary did not match the operation count")
	}
	slices.SortFunc(updates, func(a, b Update) int {
		if order := strings.Compare(a.ID, b.ID); order != 0 {
			return order
		}
		return strings.Compare(a.Architecture, b.Architecture)
	})
	return updates, deferred, nil
}

func parseAPTUpgrade(line string) (Update, error) {
	id, rest, idOK := strings.Cut(line, " [")
	installed, rest, oldOK := strings.Cut(rest, "] (")
	candidate, rest, newOK := strings.Cut(rest, " ")
	_, rest, archOK := strings.Cut(rest, "[")
	arch, _, endOK := strings.Cut(rest, "])")
	if !idOK || !oldOK || !newOK || !archOK || !endOK || !aptID.MatchString(id) || len(id) > 256 ||
		!nativeToken.MatchString(installed) || !nativeToken.MatchString(candidate) || !aptArch.MatchString(arch) {
		return Update{}, errors.New("unrecognized APT upgrade record")
	}
	return Update{ID: id, InstalledVersion: installed, CandidateVersion: candidate, Architecture: arch}, nil
}
