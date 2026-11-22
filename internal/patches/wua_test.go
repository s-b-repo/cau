package patches

import (
	"strings"
	"testing"
	"time"
)

const wuaFixture = `{
  "version": "24H2",
  "build": "26100.2000",
  "reboot_required": true,
  "last_search": "2026-11-19T13:00:00Z",
  "result_code": 2,
  "warning_count": 0,
  "update_count": 1,
  "updates": [{"id": "ABCDEF01-0000-0000-0000-000000000000", "revision": 201}]
}`

func TestReadWUAKeepsSearchAndRestartEvidenceIndependent(t *testing.T) {
	now := time.Date(2026, 11, 20, 13, 0, 0, 0, time.UTC)
	assess := func(payload string, warned bool) Assessment {
		result := Assessment{AssessmentStatus: Unknown, Metadata: Metadata{Status: Unknown}, Restart: Restart{State: Unknown}}
		readWUA(&result, []byte(payload), warned, now)
		return result
	}
	fresh := assess(wuaFixture, false)
	if fresh.AssessmentStatus != Complete || fresh.AssessedAt == nil || fresh.OS.Build != "26100.2000" || fresh.Metadata.Status != Current || fresh.Metadata.LastSuccessfulSearchAt == nil || fresh.Restart.State != Pending || len(fresh.Updates) != 1 || fresh.Updates[0].ID != "abcdef01-0000-0000-0000-000000000000" || fresh.Updates[0].Revision != 201 {
		t.Fatalf("fresh search: %+v", fresh)
	}
	if got := assess(strings.Replace(wuaFixture, "2026-11-19", "2026-11-01", 1), false); got.AssessmentStatus != Partial || got.Metadata.Status != Stale || got.AssessedAt == nil || len(got.Updates) != 1 {
		t.Fatalf("stale search: %+v", got)
	}
	if got := assess(strings.Replace(wuaFixture, "\"result_code\": 2", "\"result_code\": 3", 1), false); got.AssessmentStatus != Partial || len(got.Updates) != 1 {
		t.Fatalf("partial native search: %+v", got)
	}
	if got := assess(wuaFixture, true); got.AssessmentStatus != Partial || got.Restart.State != Pending {
		t.Fatalf("native diagnostics: %+v", got)
	}
	if got := assess(strings.Replace(wuaFixture, "\"update_count\": 1", "\"update_count\": 2", 1), false); got.AssessmentStatus != Unknown || got.AssessedAt != nil || got.Restart.State != Pending || len(got.Updates) != 0 {
		t.Fatalf("incomplete search with verified restart: %+v", got)
	}
	if got := assess(strings.Replace(wuaFixture, "\"reboot_required\": true", "\"reboot_required\": false", 1), false); got.Restart.State != NotPending {
		t.Fatalf("verified no restart: %+v", got)
	}
	if got := assess(strings.Replace(wuaFixture, "\"reboot_required\": true", "\"reboot_required\": null", 1), false); got.Restart.State != Unknown || got.AssessmentStatus != Complete {
		t.Fatalf("verified search with unknown restart: %+v", got)
	}
}
