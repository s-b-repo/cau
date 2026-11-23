package patches

import (
	"strings"
	"time"
	"unicode"
	"unicode/utf8"
)

func readMacUpdates(result *Assessment, output string, queryErr error, now time.Time) {
	result.AssessmentStatus = Unknown
	if queryErr != nil {
		result.Warnings = append(result.Warnings, "macOS Software Update did not complete")
		return
	}

	var label string
	listed, empty, incomplete := false, false, false
	seen := make(map[string]bool)
	for line := range strings.Lines(output) {
		line = strings.TrimSpace(line)
		switch {
		case line == "", line == "Software Update Tool", line == "Finding available software":
		case line == "No new software available.":
			empty = true
		case line == "Software Update found the following new or updated software:":
			listed = true
		case listed && strings.HasPrefix(line, "* Label:"):
			if label != "" {
				incomplete = true
			}
			label = strings.TrimSpace(strings.TrimPrefix(line, "* Label:"))
			if !validMacUpdateLabel(label) || seen[label] {
				label, incomplete = "", true
			}
		case label != "" && strings.HasPrefix(line, "Title:"):
			_, version, found := strings.Cut(line, ", Version:")
			version, _, _ = strings.Cut(version, ",")
			version = strings.TrimSpace(version)
			if !found || !nativeToken.MatchString(version) || len(result.Updates) >= 10000 {
				incomplete = true
			} else {
				result.Updates = append(result.Updates, Update{
					ID: label, CandidateVersion: version,
					RequiresRestart: strings.Contains(line, ", Action: restart,") || strings.HasSuffix(line, ", Action: restart"),
				})
				seen[label] = true
			}
			label = ""
		default:
			incomplete = true
		}
	}
	switch {
	case !incomplete && label == "" && ((empty && !listed) || (!empty && listed && len(result.Updates) > 0)):
		result.AssessmentStatus = Complete
		result.Metadata.Status = Current
	case len(result.Updates) > 0 && !empty:
		result.AssessmentStatus = Partial
		result.Warnings = append(result.Warnings, "macOS Software Update output was incomplete")
	default:
		result.Updates = []Update{}
		result.Warnings = append(result.Warnings, "macOS Software Update output could not be verified")
		return
	}
	at := now.UTC()
	result.AssessedAt = &at
}

func validMacUpdateLabel(label string) bool {
	return label != "" && len(label) <= 256 && utf8.ValidString(label) &&
		!strings.ContainsFunc(label, func(r rune) bool {
			return unicode.IsControl(r) || unicode.Is(unicode.Cf, r)
		})
}
