// Package posture reads operating-system security settings.
package posture

import (
	"context"
	"time"
)

const (
	observed    = "observed"
	partial     = "partial"
	unavailable = "unavailable"
	unsupported = "unsupported"
)

type FirewallProfile struct {
	Name    string `json:"name"`
	Enabled bool   `json:"enabled"`
}

type Firewall struct {
	Source   string            `json:"source"`
	Status   string            `json:"status"`
	Profiles []FirewallProfile `json:"profiles"`
}

type DiskEncryption struct {
	Source     string `json:"source"`
	Status     string `json:"status"`
	Protection string `json:"protection"`
	Volume     string `json:"volume"`
}

type Report struct {
	SchemaVersion  string         `json:"schema_version"`
	OS             string         `json:"os"`
	ObservedAt     time.Time      `json:"observed_at"`
	Firewall       Firewall       `json:"firewall"`
	DiskEncryption DiskEncryption `json:"disk_encryption"`
}

func Read(ctx context.Context) Report {
	report := read(ctx)
	report.SchemaVersion = "1"
	report.ObservedAt = time.Now().UTC()
	return report
}

func (p Report) Complete() bool {
	return p.Firewall.Status == observed && p.DiskEncryption.Status == observed
}

func newReport(platform, firewall, disk, status string) Report {
	return Report{
		OS:             platform,
		Firewall:       Firewall{Source: firewall, Status: status, Profiles: []FirewallProfile{}},
		DiskEncryption: DiskEncryption{Source: disk, Status: status, Protection: "unknown", Volume: "unknown"},
	}
}
