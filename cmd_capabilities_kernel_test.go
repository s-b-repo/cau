package main

import (
	"encoding/json"
	"testing"
	"time"
)

func TestKernelCapabilityEvidenceRequiresCurrentVerifiedReport(t *testing.T) {
	now := time.Date(2026, 11, 22, 12, 0, 0, 0, time.UTC)
	fields := map[string]any{
		"schema_version": "1", "scope": "live", "baseline_status": "verified",
		"boot_id": "boot-fixture", "observed_at": now.Add(-time.Minute),
		"coverage": "partial", "alert_count": 2,
	}
	evaluate := func() (*kernelCapabilityEvidence, string) {
		t.Helper()
		raw, err := json.Marshal(fields)
		if err != nil {
			t.Fatal(err)
		}
		return decodeKernelEvidence(raw, "boot-fixture", now)
	}
	evidence, reason := evaluate()
	if evidence == nil || reason != "" || evidence.AlertCount != 2 || evidence.Coverage != "partial" {
		t.Fatalf("expected current evidence: %+v, %q", evidence, reason)
	}
	for _, rejected := range []struct {
		field string
		value any
	}{
		{"baseline_status", "unsigned"},
		{"boot_id", "previous-boot"},
		{"scope", "fixture"},
		{"schema_version", "2"},
		{"observed_at", now.Add(-2 * time.Hour)},
		{"observed_at", now.Add(time.Minute)},
		{"alert_count", nil},
		{"alert_count", -1},
	} {
		t.Run(rejected.field, func(t *testing.T) {
			saved := fields[rejected.field]
			fields[rejected.field] = rejected.value
			evidence, reason := evaluate()
			fields[rejected.field] = saved
			if evidence != nil || reason == "" {
				t.Fatalf("invalid report accepted: %+v, %q", evidence, reason)
			}
		})
	}
}
