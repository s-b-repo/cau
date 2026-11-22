package main

import (
	"errors"
	"flag"
	"fmt"
	"io"
	"runtime"
	"strings"
	"time"

	"github.com/s-b-repo/cau/internal/report"
)

type capability struct {
	ID          string    `json:"id"`
	Provider    string    `json:"provider"`
	Status      string    `json:"status"`
	Reason      string    `json:"reason"`
	EvaluatedAt time.Time `json:"evaluated_at"`
}

type capabilityReport struct {
	SchemaVersion string       `json:"schema_version"`
	EngineVersion string       `json:"engine_version"`
	OS            string       `json:"os"`
	Architecture  string       `json:"architecture"`
	Capabilities  []capability `json:"capabilities"`
}

func cmdCapabilities(args []string, stdout, stderr io.Writer) int {
	fs := flag.NewFlagSet("capabilities", flag.ContinueOnError)
	fs.SetOutput(stderr)
	fs.Usage = func() {
		fmt.Fprint(stderr, `Usage: cau capabilities [flags]

List capability providers and their platform support. This discovery command
does not assess host readiness or change local state.

Flags:
  --format <fmt>  text or json (default text)

Exit codes: 0 report written, 3 output error, 4 usage.
`)
	}
	format := fs.String("format", "text", "output format: text or json")
	if err := fs.Parse(interspersed(fs, args)); err != nil {
		if errors.Is(err, flag.ErrHelp) {
			return report.ExitOK
		}
		return report.ExitUsage
	}
	if *format != "text" && *format != "json" {
		return fail(stderr, report.ExitUsage, "--format must be text or json")
	}
	if fs.NArg() != 0 {
		return fail(stderr, report.ExitUsage, "capabilities accepts no positional arguments")
	}
	result := buildCapabilities(runtime.GOOS, runtime.GOARCH, time.Now().UTC())
	var err error
	if *format == "json" {
		err = writeJSON(stdout, result)
	} else {
		var text strings.Builder
		fmt.Fprintf(&text, "CAU %s capabilities on %s/%s\n", result.EngineVersion, result.OS, result.Architecture)
		for _, feature := range result.Capabilities {
			fmt.Fprintf(&text, "%s: %s (%s) — %s\n", feature.ID, feature.Status, feature.Provider, feature.Reason)
		}
		_, err = io.WriteString(stdout, text.String())
	}
	if err != nil {
		return fail(stderr, report.ExitRunFailed, "write capabilities: %v", err)
	}
	return report.ExitOK
}

// buildCapabilities describes the available integrations without running any
// of them. A provider can compile for this OS and still lack a local dependency,
// usable data, or permission on a particular installation.
func buildCapabilities(osName, architecture string, at time.Time) capabilityReport {
	known := func(id, provider, reason string) capability {
		return capability{id, provider, "unprobed", reason, at}
	}
	unsupported := func(id, reason string) capability {
		return capability{id, "none", "unsupported", reason, at}
	}
	scan := known("scan", "cau-scan", "local scan and detection-resource readiness were not checked")
	vault := known("quarantine_restore", "cau-vault", "vault access and file handling were not checked")
	watch := unsupported("file_watch", "real-time file watching requires Linux inotify")
	inventory := unsupported("software_inventory", "no system software inventory provider for this OS")
	patch := unsupported("patch_assessment", "no local OS update and restart provider for this OS")
	service := unsupported("service_health", "no packaged service health integration for this OS")
	switch osName {
	case "linux":
		watch = known("file_watch", "inotify", "watch attachment, scope and available watch quota were not checked")
		inventory = known("software_inventory", "system-package-databases", "run cau inventory to assess dpkg, pacman or RPM collection")
		patch = known("patch_assessment", "apt-upgrade-simulation", "run cau patches to check local APT, its cached indexes and restart evidence")
		service = known("service_health", "systemd", "package installation and cau-defend.service health were not checked")
	case "windows":
		inventory = known("software_inventory", "machine-uninstall-registry", "run cau inventory to assess the machine-wide registry views")
		patch = known("patch_assessment", "windows-update-agent-cache", "run cau patches to check cached Windows updates and restart evidence")
	case "darwin":
		inventory = known("software_inventory", "installer-receipts-and-app-bundles", "run cau inventory to assess receipts and shared app directories")
		patch = unsupported("patch_assessment", "cau patches reports the installed OS build; pending updates and restart need a separate source")
	}
	return capabilityReport{
		SchemaVersion: "1", EngineVersion: version, OS: osName, Architecture: architecture,
		Capabilities: []capability{scan, watch, vault, inventory, patch, service},
	}
}
