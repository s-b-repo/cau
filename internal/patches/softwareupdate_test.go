package patches

import (
	"errors"
	"testing"
	"time"
)

func TestMacSoftwareUpdateAvailability(t *testing.T) {
	const prefix = "Software Update Tool\n\nFinding available software\n"
	const offered = `Software Update found the following new or updated software:
* Label: Safari26.0SequoiaAuto-26.0
    Title: Safari, Version: 26.0, Size: 190000KiB, Recommended: YES,
* Label: macOS Sequoia 15.7-24G222
    Title: macOS Sequoia, Version: 15.7, Size: 1800000KiB, Recommended: YES, Action: restart,
`
	cases := []struct {
		name, output, status string
		err                  error
		updates              int
		restart              bool
	}{
		{"offered", prefix + offered, Complete, nil, 2, true},
		{"empty", prefix + "No new software available.\n", Complete, nil, 0, false},
		{"diagnostic", prefix + "No new software available.\nnetwork failed\n", Unknown, nil, 0, false},
		{"failed", prefix + offered, Unknown, errors.New("timeout"), 0, false},
		{"truncated", prefix + offered + "* Label: Other-1\n", Partial, nil, 2, true},
		{"contradictory", prefix + offered + "No new software available.\n", Unknown, nil, 0, false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			now := time.Date(2026, 11, 23, 1, 2, 3, 0, time.UTC)
			got := Assessment{Metadata: Metadata{Status: Unknown}, Restart: Restart{State: Unknown}, Updates: []Update{}}
			readMacUpdates(&got, tc.output, tc.err, now)
			if got.AssessmentStatus != tc.status || len(got.Updates) != tc.updates || got.Restart.State != Unknown {
				t.Fatalf("unexpected assessment: %+v", got)
			}
			if (got.AssessedAt != nil) != (tc.status != Unknown) ||
				(got.Metadata.Status == Current) != (tc.status == Complete) {
				t.Fatalf("unexpected evidence metadata: %+v", got)
			}
			if tc.restart && (!got.Updates[1].RequiresRestart || got.Updates[0].RequiresRestart ||
				got.Updates[1].CandidateVersion != "15.7") {
				t.Fatalf("unexpected updates: %+v", got.Updates)
			}
		})
	}
}
