package main

import (
	"bytes"
	"encoding/json"
	"io"
	"runtime"
	"strings"
	"testing"
	"time"

	"github.com/s-b-repo/cau/internal/report"
)

func TestCapabilitiesPlatformMatrix(t *testing.T) {
	at := time.Date(2026, 11, 20, 19, 0, 0, 0, time.UTC)
	tests := []struct {
		os                        string
		watch, inventory, patches string
		service                   string
	}{
		{"linux", "inotify", "system-package-databases", "apt-upgrade-simulation", "systemd"},
		{"windows", "none", "machine-uninstall-registry", "windows-update-agent-cache", "none"},
		{"darwin", "none", "installer-receipts-and-app-bundles", "none", "none"},
		{"freebsd", "none", "none", "none", "none"},
	}
	for _, test := range tests {
		t.Run(test.os, func(t *testing.T) {
			result := buildCapabilities(test.os, "arm64", at)
			if result.Architecture != "arm64" || result.OS != test.os || result.SchemaVersion != "1" || result.EngineVersion != version {
				t.Fatalf("unexpected report header %+v", result)
			}
			want := map[string]string{
				"scan": "cau-scan", "quarantine_restore": "cau-vault", "file_watch": test.watch,
				"software_inventory": test.inventory, "patch_assessment": test.patches, "service_health": test.service,
				"kernel_integrity": "none",
			}
			if test.os == "linux" {
				want["kernel_integrity"] = "cau-kernel"
			}
			for _, item := range result.Capabilities {
				p, ok := want[item.ID]
				status := "unprobed"
				if p == "none" {
					status = "unsupported"
				}
				if !ok || p != item.Provider || item.Status != status || item.Reason == "" || !item.EvaluatedAt.Equal(at) {
					t.Errorf("unexpected capability %+v", item)
				}
				delete(want, item.ID)
			}
			if len(want) != 0 {
				t.Errorf("missing capabilities %+v", want)
			}
		})
	}
}

func TestCapabilitiesCLI(t *testing.T) {
	var stdout, stderr bytes.Buffer
	if got := run([]string{"capabilities", "--format", "json"}, &stdout, &stderr); got != report.ExitOK || stderr.Len() != 0 {
		t.Fatalf("JSON returned %d, stderr %s", got, &stderr)
	}
	var result capabilityReport
	if err := json.Unmarshal(stdout.Bytes(), &result); err != nil {
		t.Fatal(err)
	}
	if result.SchemaVersion != "1" || result.OS != runtime.GOOS || result.Architecture != runtime.GOARCH || len(result.Capabilities) != 7 {
		t.Fatalf("unexpected JSON report %+v", result)
	}
	stdout.Reset()
	if got := run([]string{"capabilities"}, &stdout, &stderr); got != report.ExitOK || !strings.Contains(stdout.String(), "scan: unprobed") {
		t.Fatalf("text returned %d, stdout %s", got, &stdout)
	}
	for _, args := range [][]string{{"--format", "xml"}, {"unexpected"}, {"--unknown"}} {
		stdout.Reset()
		if got := run(append([]string{"capabilities"}, args...), &stdout, io.Discard); got != report.ExitUsage || stdout.Len() != 0 {
			t.Errorf("%v returned %d, stdout %s", args, got, &stdout)
		}
	}
}
