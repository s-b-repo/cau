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
	SchemaVersion   string                    `json:"schema_version"`
	EngineVersion   string                    `json:"engine_version"`
	OS              string                    `json:"os"`
	Architecture    string                    `json:"architecture"`
	Capabilities    []capability              `json:"capabilities"`
	KernelIntegrity *kernelCapabilityEvidence `json:"kernel_integrity,omitempty"`
}

func cmdCapabilities(args []string, stdout, stderr io.Writer) int {
	fs := flag.NewFlagSet("capabilities", flag.ContinueOnError)
	fs.SetOutput(stderr)
	fs.Usage = func() {
		fmt.Fprint(stderr, `Usage: cau capabilities [flags]

List capability providers and their platform support. This discovery command
can read an existing kernel drift report when requested.

Flags:
  --format <fmt>         text or json (default text)
  --kernel-report <file> Linux kernel drift JSON saved by a trusted local job

Exit codes: 0 report written, 3 output error, 4 usage.
`)
	}
	format := fs.String("format", "text", "output format: text or json")
	kernelReport := fs.String("kernel-report", "", "read a saved Linux kernel drift report")
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
	if *kernelReport != "" && result.OS == "linux" {
		result.readKernelEvidence(*kernelReport)
	}
	var err error
	if *format == "json" {
		err = writeJSON(stdout, result)
	} else {
		var text strings.Builder
		fmt.Fprintf(&text, "CAU %s capabilities on %s/%s\n", result.EngineVersion, result.OS, result.Architecture)
		for _, feature := range result.Capabilities {
			fmt.Fprintf(&text, "%s: %s (%s) — %s\n", feature.ID, feature.Status, feature.Provider, feature.Reason)
		}
		if k := result.KernelIntegrity; k != nil {
			fmt.Fprintf(&text, "  Kernel observation %s, %d drift alerts, %s coverage\n", k.ObservedAt.Format(time.RFC3339), k.AlertCount, k.Coverage)
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
	watch := unsupported("file_watch", "no native file notification provider for this OS")
	dns := unsupported("dns_configuration", "no native resolver configuration provider for this OS")
	posture := unsupported("endpoint_posture", "no native firewall and disk encryption provider for this OS")
	inventory := unsupported("software_inventory", "no system software inventory provider for this OS")
	patch := unsupported("patch_assessment", "no local OS update and restart provider for this OS")
	service := unsupported("service_health", "no packaged service health integration for this OS")
	kernel := unsupported("kernel_integrity", "the kernel drift provider requires Linux")
	process := unsupported("process_scan", "no native process collector for this OS")
	startup := unsupported("persistence_scan", "no native startup collector for this OS")
	connections := unsupported("connection_scan", "no native socket collector for this OS")
	firewall := unsupported("network_response", "no temporary network response provider for this OS")
	processResponse := unsupported("process_response", "no process response provider for this OS")
	switch osName {
	case "linux":
		watch = known("file_watch", "inotify", "watch attachment, scope and available watch quota were not checked")
		dns = known("dns_configuration", "resolv-conf", "run cau net dns to inspect client and systemd resolver configuration")
		inventory = known("software_inventory", "system-package-databases", "run cau inventory to assess dpkg, pacman or RPM collection")
		patch = known("patch_assessment", "apt-upgrade-simulation", "run cau patches to check local APT, its cached indexes and restart evidence")
		service = known("service_health", "systemd", "package installation and cau-defend.service health were not checked")
		kernel = known("kernel_integrity", "cau-kernel", "use --kernel-report to read a local drift report")
		process = known("process_scan", "procfs", "run cau ps to inspect visible processes")
		startup = known("persistence_scan", "linux-startup-and-accounts", "run cau persist to inspect startup and account evidence")
		connections = known("connection_scan", "procfs", "run cau net to inspect Linux network evidence")
		firewall = known("network_response", "nftables-or-iptables", "local firewall access was not checked")
		processResponse = known("process_response", "linux-signals", "process stop and kill require permission to signal the target")
	case "windows":
		watch = known("file_watch", "read-directory-changes", "watch attachment, scope and notification delivery were not checked")
		dns = known("dns_configuration", "windows-dns-client", "run cau net dns to inspect connected interface resolver addresses")
		inventory = known("software_inventory", "machine-uninstall-registry", "run cau inventory to assess the machine-wide registry views")
		patch = known("patch_assessment", "windows-update-agent-cache", "run cau patches to check cached Windows updates and restart evidence")
		service = known("service_health", "windows-scm", "query the CauDefend service with Get-Service after registration")
		posture = known("endpoint_posture", "windows-firewall-and-bitlocker", "run cau posture to inspect firewall profile settings and the system volume")
		process = known("process_scan", "windows-cim-process", "run cau ps to inspect visible process command lines and executable paths")
		startup = known("persistence_scan", "windows-registry-and-services", "run cau persist to inspect Run and RunOnce values, services and scheduled task actions")
		connections = known("connection_scan", "windows-nettcpip", "run cau net to inspect TCP connections and UDP endpoints")
		firewall = known("network_response", "wfp", "temporary peer filters require a running CAU process and Windows Filtering Platform access")
		processResponse = known("process_response", "windows-process-handle", "explicit termination requires process query and terminate access")
	case "darwin":
		watch = known("file_watch", "fsevents", "watch attachment, scope and notification delivery were not checked")
		dns = known("dns_configuration", "system-configuration", "run cau net dns to inspect the resolver configuration")
		inventory = known("software_inventory", "installer-receipts-and-app-bundles", "run cau inventory to assess receipts and shared app directories")
		patch = known("patch_assessment", "macos-softwareupdate", "run cau patches --online to list offered updates through Software Update")
		service = known("service_health", "launchd", "query the org.cau.defend launch job with launchctl after registration")
		posture = known("endpoint_posture", "application-firewall-and-filevault", "run cau posture to inspect application firewall and FileVault protection")
		process = known("process_scan", "macos-ps", "run cau ps to inspect visible processes")
		startup = known("persistence_scan", "macos-launchd-plists", "run cau persist to inspect shared and current-account launch jobs")
		connections = known("connection_scan", "macos-lsof", "run cau net to inspect visible TCP and UDP sockets")
		firewall = known("network_response", "pf", "temporary peer filters require the launchd firewall service and a configured PF anchor")
		processResponse = known("process_response", "macos-task-control", "explicit termination requires macOS to grant task control access")
	}
	return capabilityReport{
		SchemaVersion: "1", EngineVersion: version, OS: osName, Architecture: architecture,
		Capabilities: []capability{scan, watch, vault, inventory, patch, service, kernel, dns, posture, process, startup, connections, firewall, processResponse},
	}
}
