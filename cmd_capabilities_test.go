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
		service, dns, posture     string
	}{
		{"linux", "inotify", "system-package-databases", "apt-upgrade-simulation", "systemd", "resolv-conf", "none"},
		{"windows", "read-directory-changes", "machine-uninstall-registry", "windows-update-agent-cache", "windows-scm", "windows-dns-client", "windows-firewall-and-bitlocker"},
		{"darwin", "fsevents", "installer-receipts-and-app-bundles", "macos-softwareupdate", "launchd", "system-configuration", "application-firewall-and-filevault"},
		{"freebsd", "none", "none", "none", "none", "none", "none"},
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
				"kernel_integrity": "none", "dns_configuration": test.dns, "endpoint_posture": test.posture,
				"process_scan": "none", "persistence_scan": "none", "connection_scan": "none", "network_response": "none",
				"process_response": "none",
			}
			switch test.os {
			case "linux":
				want["kernel_integrity"] = "cau-kernel"
				want["process_scan"], want["persistence_scan"], want["connection_scan"] = "procfs", "linux-startup-and-accounts", "procfs"
				want["network_response"] = "nftables-or-iptables"
				want["process_response"] = "linux-signals"
			case "windows":
				want["process_scan"], want["persistence_scan"], want["connection_scan"] = "windows-cim-process", "windows-registry-and-services", "windows-nettcpip"
				want["network_response"] = "wfp"
				want["process_response"] = "windows-process-handle"
			case "darwin":
				want["process_scan"], want["persistence_scan"], want["connection_scan"] = "macos-ps", "macos-launchd-plists", "macos-lsof"
				want["process_response"] = "macos-task-control"
				want["network_response"] = "pf"
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
	if result.SchemaVersion != "1" || result.OS != runtime.GOOS || result.Architecture != runtime.GOARCH || len(result.Capabilities) != 14 {
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
