package main

import (
	"encoding/json"
	"strings"
	"time"

	"github.com/s-b-repo/cau/internal/safefs"
)

const kernelReportMaxAge = time.Hour

type kernelCapabilityEvidence struct {
	ObservedAt time.Time `json:"observed_at"`
	Coverage   string    `json:"coverage"`
	AlertCount int       `json:"alert_count"`
}

func (r *capabilityReport) readKernelEvidence(path string) {
	for index := range r.Capabilities {
		item := &r.Capabilities[index]
		if item.ID != "kernel_integrity" {
			continue
		}
		evidence, reason := readKernelReport(path, item.EvaluatedAt)
		if evidence == nil {
			item.Status, item.Reason = "unknown", reason
			return
		}
		r.KernelIntegrity = evidence
		item.Status, item.Reason = "observed", "local drift observation for the current Linux boot"
		return
	}
}

func readKernelReport(path string, now time.Time) (*kernelCapabilityEvidence, string) {
	boot, err := safefs.ReadFile("/proc/sys/kernel/random/boot_id", 128)
	if err != nil {
		return nil, "the current Linux boot identifier could not be read"
	}
	raw, err := safefs.ReadFile(path, 64<<10)
	if err != nil {
		return nil, "the kernel report could not be read"
	}
	return decodeKernelEvidence(raw, strings.TrimSpace(string(boot)), now)
}

func decodeKernelEvidence(raw []byte, bootID string, now time.Time) (*kernelCapabilityEvidence, string) {
	var document struct {
		SchemaVersion  string    `json:"schema_version"`
		ObservedAt     time.Time `json:"observed_at"`
		Scope          string    `json:"scope"`
		BootID         string    `json:"boot_id"`
		BaselineStatus string    `json:"baseline_status"`
		Coverage       string    `json:"coverage"`
		AlertCount     *int      `json:"alert_count"`
	}
	if err := json.Unmarshal(raw, &document); err != nil || document.SchemaVersion != "1" ||
		document.ObservedAt.IsZero() || document.AlertCount == nil || *document.AlertCount < 0 ||
		(document.Coverage != "complete" && document.Coverage != "partial") {
		return nil, "the kernel report has an unsupported schema or invalid fields"
	}
	if document.BaselineStatus != "verified" || document.Scope != "live" {
		return nil, "the report requires a live snapshot and a verified baseline"
	}
	if bootID == "" || document.BootID != bootID {
		return nil, "the report does not describe the current Linux boot"
	}
	if age := now.Sub(document.ObservedAt); age < 0 || age > kernelReportMaxAge {
		return nil, "the report timestamp is outside the last hour"
	}
	return &kernelCapabilityEvidence{
		ObservedAt: document.ObservedAt, Coverage: document.Coverage, AlertCount: *document.AlertCount,
	}, ""
}
