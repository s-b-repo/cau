package patches

import (
	"context"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

const aptPlanFixture = `Reading package lists...
The following packages have been kept back:
  fixture-held
2 upgraded, 0 newly installed, 0 to remove and 1 not upgraded.
Inst fixture-z:arm64 [1:3.0~rc1-1] (1:3.0-1 archive.invalid/testing [arm64]) []
Conf fixture-z:arm64 (1:3.0-1 archive.invalid/testing [arm64])
Inst fixture-a [2.0-1] (2.0-1+b1 [all])
Conf fixture-a (2.0-1+b1 [all])
`

func TestParseAPTPlan(t *testing.T) {
	updates, deferred, err := parseAPTPlan([]byte(aptPlanFixture))
	if err != nil || len(updates) != 2 || deferred != 1 {
		t.Fatalf("updates=%+v deferred=%d err=%v", updates, deferred, err)
	}
	if updates[0].ID != "fixture-a" || updates[0].Architecture != "all" || updates[1].InstalledVersion != "1:3.0~rc1-1" || updates[1].CandidateVersion != "1:3.0-1" || updates[1].Architecture != "arm64" {
		t.Fatalf("unexpected versions or sort order: %+v", updates)
	}
	encoded, err := json.Marshal(updates)
	if err != nil || strings.Contains(string(encoded), "archive.invalid") {
		t.Fatalf("native repository data entered result: %q err=%v", encoded, err)
	}
}

func TestParseAPTPlanRejectsIncompleteOrUnexpectedOperations(t *testing.T) {
	for name, plan := range map[string]string{
		"absent summary":    "Reading package lists...\n",
		"count mismatch":    strings.Replace(aptPlanFixture, "2 upgraded", "3 upgraded", 1),
		"malformed upgrade": strings.Replace(aptPlanFixture, " [1:3.0~rc1-1]", "", 1),
		"duplicate upgrade": aptPlanFixture + "Inst fixture-a [2.0-1] (2.0-1+b1 [all])\n",
		"removal":           aptPlanFixture + "Remv fixture-b [1.0]\n",
		"new installation":  strings.Replace(aptPlanFixture, "0 newly installed", "1 newly installed", 1),
	} {
		t.Run(name, func(t *testing.T) {
			if _, _, err := parseAPTPlan([]byte(plan)); err == nil {
				t.Fatal("accepted an incomplete or unexpected plan")
			}
		})
	}
}

func TestCollectAPTTracksMetadataAndUnavailableUpdates(t *testing.T) {
	now := time.Date(2026, 11, 20, 13, 0, 0, 0, time.UTC)
	path := filepath.Join(t.TempDir(), "dists_stable_test_binary-amd64_Packages")
	if err := os.WriteFile(path+".lz4", []byte("fixture"), 0600); err != nil {
		t.Fatal(err)
	}
	setTime := func(indexTime time.Time) {
		t.Helper()
		if err := os.Chtimes(path+".lz4", indexTime, indexTime); err != nil {
			t.Fatal(err)
		}
	}
	setTime(now.Add(-time.Hour))
	active := path + "\thttps://archive.invalid\tstable\tmain\n"
	configured := active + filepath.Join(filepath.Dir(path), "dists_stable_test_binary-all_Packages") + "\thttps://archive.invalid\tstable\tmain\n"
	query := func(ctx context.Context, name string, args ...string) ([]byte, bool, error) {
		t.Helper()
		if name != aptGet {
			t.Fatalf("unexpected executable %s", name)
		}
		switch args[0] {
		case "indextargets":
			if args[1] == "--no-release-info" {
				return []byte(configured), false, nil
			}
			return []byte(active), false, nil
		case "--simulate":
			if args[1] != "--no-remove" || args[len(args)-1] != "upgrade" {
				t.Fatalf("unexpected APT upgrade arguments %v", args)
			}
			return []byte("0 upgraded, 0 newly installed, 0 to remove and 0 not upgraded.\n"), false, nil
		default:
			t.Fatalf("unexpected APT invocation %v", args)
			return nil, false, nil
		}
	}
	assess := func(run nativeQuery) Assessment {
		var result Assessment
		collectAPT(t.Context(), &result, run, os.Stat, func() time.Time { return now })
		return result
	}
	if got := assess(query); got.AssessmentStatus != Complete || got.Metadata.Status != Current || got.Metadata.KnownIndexes != 1 || got.AssessedAt == nil || got.Updates == nil || got.DeferredUpdates == nil {
		t.Fatalf("fresh metadata: %+v", got)
	}
	setTime(now.Add(-8 * 24 * time.Hour))
	if got := assess(query); got.AssessmentStatus != Partial || got.Metadata.Status != Stale || got.AssessedAt == nil {
		t.Fatalf("stale metadata: %+v", got)
	}
	configured += path + ".missing\thttps://missing.invalid\tstable\tmain\n"
	if got := assess(query); got.AssessmentStatus != Partial || got.Metadata.Status != Partial || got.Metadata.MissingSources != 1 {
		t.Fatalf("missing configured source: %+v", got)
	}
	if got := assess(func(ctx context.Context, name string, args ...string) ([]byte, bool, error) {
		if args[0] == "--simulate" {
			return []byte(aptPlanFixture), true, errors.New("native details")
		}
		return query(ctx, name, args...)
	}); got.AssessmentStatus != Unknown || got.AssessedAt != nil || got.DeferredUpdates != nil || len(got.Updates) != 0 || strings.Contains(strings.Join(got.Warnings, " "), "native details") {
		t.Fatalf("failed assessment: %+v", got)
	}
}

func TestRestartMarker(t *testing.T) {
	path := filepath.Join(t.TempDir(), "reboot-required")
	if got := readRestartMarker(os.Lstat, path); got.State != Unknown {
		t.Fatalf("missing marker: %+v", got)
	}
	if err := os.WriteFile(path, []byte("fixture\n"), 0600); err != nil {
		t.Fatal(err)
	}
	if got := readRestartMarker(os.Lstat, path); got.State != Pending {
		t.Fatalf("present marker: %+v", got)
	}
	if got := readRestartMarker(os.Lstat, filepath.Dir(path)); got.State != Unknown {
		t.Fatalf("non-regular marker: %+v", got)
	}
}
