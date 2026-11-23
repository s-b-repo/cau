// Package patches assesses OS update and restart readiness without applying it.
package patches

import (
	"context"
	"errors"
	"os"
	"runtime"
	"strings"
	"time"

	"github.com/s-b-repo/cau/internal/nativecmd"
	"github.com/s-b-repo/cau/internal/safefs"
)

const (
	Complete    = "complete"
	Partial     = "partial"
	Unknown     = "unknown"
	Unsupported = "unsupported"
	Pending     = "pending"
	NotPending  = "not_pending"
	Current     = "current"
	Stale       = "stale"

	Timeout       = 45 * time.Second
	OnlineTimeout = 2 * time.Minute
)

type OS struct {
	ID      string `json:"id"`
	Version string `json:"version,omitempty"`
	Build   string `json:"build,omitempty"`
}

type Metadata struct {
	Status                 string     `json:"status"`
	OldestIndexAt          *time.Time `json:"oldest_index_at,omitempty"`
	LastSuccessfulSearchAt *time.Time `json:"last_successful_search_at,omitempty"`
	KnownIndexes           int        `json:"known_indexes,omitempty"`
	MissingIndexes         int        `json:"missing_indexes,omitempty"`
	MissingSources         int        `json:"missing_sources,omitempty"`
}

type Update struct {
	ID               string `json:"id"`
	InstalledVersion string `json:"installed_version,omitempty"`
	CandidateVersion string `json:"candidate_version,omitempty"`
	Architecture     string `json:"architecture,omitempty"`
	Revision         int    `json:"revision,omitempty"`
	RequiresRestart  bool   `json:"requires_restart,omitempty"`
}

type Restart struct {
	State  string `json:"state"`
	Source string `json:"source,omitempty"`
	Reason string `json:"reason,omitempty"`
}

type Assessment struct {
	SchemaVersion    string     `json:"schema_version"`
	OS               OS         `json:"os"`
	Source           string     `json:"source"`
	ObservedAt       time.Time  `json:"observed_at"`
	AssessedAt       *time.Time `json:"assessed_at,omitempty"`
	AssessmentStatus string     `json:"assessment_status"`
	Metadata         Metadata   `json:"metadata"`
	Updates          []Update   `json:"updates"`
	DeferredUpdates  *int       `json:"deferred_updates,omitempty"`
	Restart          Restart    `json:"restart"`
	Warnings         []string   `json:"warnings,omitempty"`
}

// Assess reads the host's locally available patch evidence. AssessedAt is set
// only when the update provider returned a usable assessment in this invocation.
func Assess(ctx context.Context, online bool) Assessment {
	result := Assessment{
		SchemaVersion: "1", OS: OS{ID: runtime.GOOS}, Source: "unavailable",
		AssessmentStatus: Unsupported, Metadata: Metadata{Status: Unknown},
		Updates: []Update{}, Restart: Restart{State: Unknown, Reason: "no local restart provider"},
	}
	switch runtime.GOOS {
	case "linux":
		result.OS = readLinuxOS()
		result.Restart = readRestartMarker(os.Lstat, "/run/reboot-required")
		if _, err := os.Stat(aptGet); errors.Is(err, os.ErrNotExist) {
			result.Warnings = append(result.Warnings, "no APT patch provider on this host")
		} else {
			collectAPT(ctx, &result, nativecmd.Unix, os.Stat, time.Now)
		}
	case "darwin":
		result.OS.ID = "macos"
		result.OS.Version = readMacOS(ctx, "-productVersion")
		result.OS.Build = readMacOS(ctx, "-buildVersion")
		if online {
			result.Source = "macos-softwareupdate"
			result.Restart = Restart{State: Unknown, Reason: "offered updates cannot attest a restart pending on the host"}
			output, err := nativecmd.UnixCombined(ctx, "/usr/sbin/softwareupdate", "--list")
			readMacUpdates(&result, string(output), err, time.Now())
		} else {
			result.Warnings = append(result.Warnings, "use --online to query macOS update availability")
		}
	case "windows":
		collectWindows(ctx, &result)
	default:
		result.Warnings = append(result.Warnings, "no local patch provider on this operating system")
	}
	result.ObservedAt = time.Now().UTC()
	return result
}

func readLinuxOS() OS {
	result := OS{ID: "linux"}
	data, err := safefs.ReadFile("/etc/os-release", 16<<10)
	if errors.Is(err, os.ErrNotExist) {
		data, err = safefs.ReadFile("/usr/lib/os-release", 16<<10)
	}
	if err != nil {
		return result
	}
	for _, line := range strings.Split(string(data), "\n") {
		key, value, found := strings.Cut(line, "=")
		if !found {
			continue
		}
		value = strings.Trim(value, `"'`)
		if !nativeToken.MatchString(value) {
			continue
		}
		switch key {
		case "ID":
			result.ID = value
		case "VERSION_ID":
			result.Version = value
		case "BUILD_ID":
			result.Build = value
		}
	}
	return result
}

func readMacOS(ctx context.Context, arg string) string {
	data, warning, err := nativecmd.Unix(ctx, "/usr/bin/sw_vers", arg)
	value := strings.TrimSpace(string(data))
	if err != nil || warning || !nativeToken.MatchString(value) {
		return ""
	}
	return value
}

func readRestartMarker(lstat func(string) (os.FileInfo, error), path string) Restart {
	result := Restart{State: Unknown, Source: "reboot-required-marker"}
	info, err := lstat(path)
	switch {
	case errors.Is(err, os.ErrNotExist):
		result.Reason = "marker absent, which does not attest restart state"
	case err != nil || !info.Mode().IsRegular():
		result.Reason = "marker could not be verified"
	default:
		result.State = Pending
		result.Reason = "the operating system marked a restart required"
	}
	return result
}

type nativeQuery func(context.Context, string, ...string) (output []byte, warned bool, err error)
