package patches

import (
	"encoding/json"
	"regexp"
	"slices"
	"strings"
	"time"
)

const (
	wuaSearchSucceeded       = 2
	wuaSearchPartlySucceeded = 3
	wuaSearchMaxAge          = 7 * 24 * time.Hour
)

var wuaUpdateID = regexp.MustCompile(`^[a-f0-9]{8}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{12}$`)

type wuaReport struct {
	Version        string     `json:"version"`
	Build          string     `json:"build"`
	RebootRequired *bool      `json:"reboot_required"`
	LastSearch     *time.Time `json:"last_search"`
	ResultCode     int        `json:"result_code"`
	WarningCount   int        `json:"warning_count"`
	UpdateCount    *int       `json:"update_count"`
	Updates        []struct {
		ID       string `json:"id"`
		Revision int    `json:"revision"`
	} `json:"updates"`
}

func readWUA(result *Assessment, data []byte, warned bool, now time.Time) {
	var raw wuaReport
	if err := json.Unmarshal(data, &raw); err != nil {
		result.Warnings = append(result.Warnings, "Windows Update Agent output could not be read")
		return
	}
	if nativeToken.MatchString(raw.Version) {
		result.OS.Version = raw.Version
	}
	if nativeToken.MatchString(raw.Build) {
		result.OS.Build = raw.Build
	}
	if raw.RebootRequired != nil {
		result.Restart.State = NotPending
		result.Restart.Reason = "Windows Update Agent reports no restart required for updates"
		if *raw.RebootRequired {
			result.Restart.State = Pending
			result.Restart.Reason = "Windows Update Agent reports a restart required for updates"
		}
	}
	if raw.LastSearch != nil && raw.LastSearch.Year() >= 2000 && !raw.LastSearch.After(now.Add(5*time.Minute)) {
		last := raw.LastSearch.UTC()
		result.Metadata.LastSuccessfulSearchAt = &last
		result.Metadata.Status = Current
		if now.Sub(last) > wuaSearchMaxAge {
			result.Metadata.Status = Stale
		}
	}
	if raw.ResultCode != wuaSearchSucceeded && raw.ResultCode != wuaSearchPartlySucceeded {
		result.Warnings = append(result.Warnings, "Windows Update Agent did not report a successful cached search")
		return
	}
	if raw.UpdateCount == nil || *raw.UpdateCount != len(raw.Updates) || len(raw.Updates) > 10000 {
		result.Warnings = append(result.Warnings, "Windows Update Agent update count could not be verified")
		return
	}
	updates := make([]Update, 0, len(raw.Updates))
	seen := make(map[Update]struct{}, len(raw.Updates))
	for _, update := range raw.Updates {
		id := strings.ToLower(update.ID)
		if !wuaUpdateID.MatchString(id) || update.Revision < 1 {
			result.Warnings = append(result.Warnings, "Windows Update Agent returned an invalid update identity")
			return
		}
		item := Update{ID: id, Revision: update.Revision}
		if _, duplicate := seen[item]; duplicate {
			result.Warnings = append(result.Warnings, "Windows Update Agent returned a duplicate update identity")
			return
		}
		seen[item] = struct{}{}
		updates = append(updates, item)
	}
	slices.SortFunc(updates, func(a, b Update) int {
		if order := strings.Compare(a.ID, b.ID); order != 0 {
			return order
		}
		return a.Revision - b.Revision
	})
	assessedAt := now.UTC()
	result.AssessedAt = &assessedAt
	result.Updates = updates
	result.AssessmentStatus = Complete
	if result.Metadata.Status != Current {
		result.AssessmentStatus = Partial
		result.Warnings = append(result.Warnings, "Windows Update Agent has no recent successful Automatic Updates search")
	}
	if raw.ResultCode == wuaSearchPartlySucceeded || raw.WarningCount != 0 || warned {
		result.AssessmentStatus = Partial
		result.Warnings = append(result.Warnings, "Windows Update Agent reported diagnostics during collection")
	}
}
