// Package inventory reports the software registered with the host's installers.
package inventory

import (
	"context"
	"errors"
	"io/fs"
	"runtime"
	"sort"
	"strings"
	"time"
	"unicode"
	"unicode/utf8"
)

const (
	Complete      = "complete"
	Partial       = "partial"
	Denied        = "denied"
	Unknown       = "unknown"
	Unsupported   = "unsupported"
	maxPackages   = 25_000
	maxFieldBytes = 512
)

// Package IDs belong to a provider and scope. Some providers, such as RPM,
// can have several installed versions of one ID at the same time.
type Package struct {
	ID           string `json:"id"`
	Name         string `json:"name"`
	Version      string `json:"version"`
	Architecture string `json:"architecture,omitempty"`
}

type Collection struct {
	Provider   string    `json:"provider"`
	Scope      string    `json:"scope"`
	ObservedAt time.Time `json:"observed_at"`
	Status     string    `json:"status"`
	Reason     string    `json:"reason,omitempty"`
	Packages   []Package `json:"packages"`
}

type Snapshot struct {
	SchemaVersion string       `json:"schema_version"`
	OS            string       `json:"os"`
	ObservedAt    time.Time    `json:"observed_at"`
	Collections   []Collection `json:"collections"`
}

func Collect(ctx context.Context) Snapshot {
	at := time.Now().UTC()
	collections := platformCollections(ctx)
	for i := range collections {
		c := &collections[i]
		c.ObservedAt = at
		if c.Packages == nil {
			c.Packages = []Package{}
		}
		sort.Slice(c.Packages, func(i, j int) bool {
			a, b := c.Packages[i], c.Packages[j]
			if a.ID != b.ID {
				return a.ID < b.ID
			}
			return a.Version < b.Version
		})
	}
	return Snapshot{SchemaVersion: "1", OS: runtime.GOOS, ObservedAt: at, Collections: collections}
}

func (s Snapshot) Complete() bool {
	for _, c := range s.Collections {
		if c.Status != Complete {
			return false
		}
	}
	return len(s.Collections) > 0
}

func collection(provider, scope string) Collection {
	return Collection{Provider: provider, Scope: scope, Status: Complete}
}

func (c *Collection) fail(err error, reason string) {
	c.Status = Unknown
	if errors.Is(err, fs.ErrPermission) {
		c.Status = Denied
	}
	if len(c.Packages) > 0 {
		c.Status = Partial
	}
	c.Reason = reason
}

func validInventoryField(s string) bool {
	return s != "" && len(s) <= maxFieldBytes && utf8.ValidString(s) && strings.IndexFunc(s, unicode.IsControl) < 0
}
