package main

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/s-b-repo/cau/internal/netscan"
	"github.com/s-b-repo/cau/internal/report"
)

func TestNetDNSDeclaredAndUpstreamPolicy(t *testing.T) {
	etc := t.TempDir()
	run := t.TempDir()
	upstream := filepath.Join(run, "systemd", "resolve", "resolv.conf")
	if err := os.MkdirAll(filepath.Dir(upstream), 0o700); err != nil {
		t.Fatal(err)
	}
	put := func(path, data string) {
		t.Helper()
		if err := os.WriteFile(path, []byte(data), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	put(filepath.Join(etc, "resolv.conf"), "nameserver 127.0.0.53\nsearch private.example\n")
	put(upstream, "nameserver 192.0.2.53 # site\nnameserver 2001:0db8::53\nnameserver fe80::53%eth0\n")
	query := func(want int, flags ...string) netscan.DNSPosture {
		t.Helper()
		args := []string{"net", "dns", "--etc-root", etc, "--run-root", run, "--format", "json"}
		code, out, stderr := runCLI(t, append(args, flags...)...)
		if code != want {
			t.Fatalf("exit %d, want %d: %s %s", code, want, out, stderr)
		}
		if strings.Contains(out, "private.example") {
			t.Fatalf("the report disclosed a search domain: %s", out)
		}
		var result netscan.DNSPosture
		if err := json.Unmarshal([]byte(out), &result); err != nil {
			t.Fatal(err)
		}
		return result
	}
	got := query(report.ExitOK, "--expect", "127.0.0.53")
	if got.SchemaVersion != "1" || got.ObservedAt.IsZero() || got.Upstreams == nil ||
		got.Policy.Status != "match" || got.Stub != "systemd_address_configured" {
		t.Fatalf("client nameserver posture: %+v", got)
	}
	got = query(report.ExitThreat, "--scope", "systemd-upstream", "--expect", "2001:db8::53", "--expect", "fe80::53%eth0", "--expect", "192.0.2.54")
	if got.Policy.Status != "drift" || strings.Join(got.Policy.Unexpected, ",") != "192.0.2.53" ||
		strings.Join(got.Policy.Missing, ",") != "192.0.2.54" {
		t.Fatalf("upstream drift: %+v", got.Policy)
	}
	put(upstream, "nameserver 192.0.2.53\nnameserver gibberish\n")
	got = query(report.ExitScanFailed, "--scope", "systemd-upstream", "--expect", "192.0.2.54")
	if got.Upstreams.Status != "partial" || got.Policy.Status != "unknown" ||
		len(got.Policy.Missing) != 0 || len(got.Policy.Unexpected) != 1 {
		t.Fatalf("an incomplete source asserted absence or hid evidence: %+v", got.Policy)
	}
	if err := os.Remove(upstream); err != nil {
		t.Fatal(err)
	}
	got = query(report.ExitScanFailed, "--scope", "systemd-upstream", "--expect", "192.0.2.53")
	if got.Upstreams.Status != "unavailable" || got.Policy.Status != "unknown" {
		t.Fatalf("missing upstream source: %+v", got)
	}
}
