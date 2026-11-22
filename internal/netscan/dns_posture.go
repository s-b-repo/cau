package netscan

import (
	"errors"
	"net/netip"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"time"
	"unicode"
	"unicode/utf8"

	"github.com/s-b-repo/cau/internal/safefs"
)

const (
	DNSClientScope   = "client"
	DNSUpstreamScope = "systemd-upstream"
	dnsComplete      = "complete"
)

type DNSResolverSource struct {
	Path        string   `json:"path"`
	Status      string   `json:"status"`
	Reason      string   `json:"reason,omitempty"`
	Nameservers []string `json:"nameservers"`
}

type DNSPolicyCheck struct {
	Scope      string   `json:"scope"`
	Status     string   `json:"status"`
	Expected   []string `json:"expected"`
	Missing    []string `json:"missing,omitempty"`
	Unexpected []string `json:"unexpected,omitempty"`
}

type DNSPosture struct {
	SchemaVersion string             `json:"schema_version"`
	ObservedAt    time.Time          `json:"observed_at"`
	Client        DNSResolverSource  `json:"client"`
	Stub          string             `json:"stub"`
	Upstreams     *DNSResolverSource `json:"systemd_upstreams,omitempty"`
	Policy        *DNSPolicyCheck    `json:"policy,omitempty"`
}

func UnsupportedDNSPosture() DNSPosture {
	return DNSPosture{
		SchemaVersion: "1", ObservedAt: time.Now().UTC(), Stub: "unknown",
		Client: DNSResolverSource{
			Path: "/etc/resolv.conf", Status: "unsupported",
			Reason: "the resolver configuration provider requires Linux", Nameservers: []string{},
		},
	}
}

// ReadDNSPosture reads resolver declarations. The systemd-resolved flat
// upstream file represents visible addresses and cannot express split DNS.
func ReadDNSPosture(etc, run string) DNSPosture {
	const clientPath = "resolv.conf"
	const upstreamPath = "systemd/resolve/resolv.conf"
	if etc == "" {
		etc = "/etc"
	}
	if run == "" {
		run = "/run"
	}
	out := DNSPosture{
		SchemaVersion: "1", ObservedAt: time.Now().UTC(),
		Client: readDNSResolverSource(etc, clientPath, "/etc/"+clientPath), Stub: "none_observed",
	}
	if out.Client.Status != dnsComplete {
		out.Stub = "unknown"
	}
	for _, ns := range out.Client.Nameservers {
		switch ns {
		case "127.0.0.53", "127.0.0.54":
			upstreams := readDNSResolverSource(run, upstreamPath, "/run/"+upstreamPath)
			out.Upstreams = &upstreams
			out.Stub = "systemd_address_configured"
		default:
			if out.Stub == "none_observed" && netip.MustParseAddr(ns).IsLoopback() {
				out.Stub = "loopback_address_configured"
			}
		}
		if out.Upstreams != nil {
			break
		}
	}
	return out
}

func (p DNSPosture) Complete() bool {
	return p.Client.Status == dnsComplete && (p.Upstreams == nil || p.Upstreams.Status == dnsComplete)
}

// Compare checks unordered address sets. A partial source can corroborate
// unexpected addresses but cannot establish that an expected address is absent.
func (p *DNSPosture) Compare(scope string, expected []string) {
	check := &DNSPolicyCheck{Scope: scope, Status: "unknown", Expected: uniqueDNSAddresses(expected)}
	p.Policy = check
	source := &p.Client
	if scope == DNSUpstreamScope {
		source = p.Upstreams
	}
	if source == nil {
		return
	}
	seen := uniqueDNSAddresses(source.Nameservers)
	check.Unexpected = dnsDifference(seen, check.Expected)
	if source.Status != dnsComplete {
		return
	}
	check.Missing = dnsDifference(check.Expected, seen)
	check.Status = "match"
	if len(check.Missing)+len(check.Unexpected) != 0 {
		check.Status = "drift"
	}
}

func readDNSResolverSource(root, relative, label string) DNSResolverSource {
	out := DNSResolverSource{Path: label, Status: dnsComplete, Nameservers: []string{}}
	data, err := safefs.ReadFile(filepath.Join(root, relative), maxConfBytes)
	switch {
	case errors.Is(err, os.ErrNotExist):
		out.Status, out.Reason = "unavailable", "resolver file is absent"
	case errors.Is(err, os.ErrPermission):
		out.Status, out.Reason = "denied", "permission denied reading resolver file"
	case errors.Is(err, safefs.ErrTooLarge):
		out.Status, out.Reason = "partial", "resolver file exceeds the read limit"
	case err != nil:
		out.Status, out.Reason = "unavailable", "resolver file could not be read"
	default:
		malformed := false
		for line := range strings.Lines(string(data)) {
			if end := strings.IndexAny(line, "#;"); end >= 0 {
				line = line[:end]
			}
			fields := strings.Fields(line)
			if len(fields) == 0 || fields[0] != "nameserver" {
				continue
			}
			if len(fields) != 2 {
				malformed = true
				continue
			}
			ns, ok := DNSAddress(fields[1])
			if !ok {
				malformed = true
				continue
			}
			out.Nameservers = append(out.Nameservers, ns)
		}
		if malformed {
			out.Status, out.Reason = "partial", "some nameserver declarations are invalid"
		} else if len(out.Nameservers) == 0 {
			out.Status, out.Reason = "unknown", "resolver file contains no nameserver declarations"
		}
	}
	return out
}

// DNSAddress canonicalizes a literal including a valid scoped IPv6 address.
func DNSAddress(value string) (string, bool) {
	if len(value) > 128 || !utf8.ValidString(value) || strings.ContainsFunc(value, func(r rune) bool {
		return unicode.IsControl(r) || unicode.IsSpace(r)
	}) {
		return "", false
	}
	addr, err := netip.ParseAddr(value)
	if err != nil {
		return "", false
	}
	if addr.Zone() == "" {
		addr = addr.Unmap()
	}
	return addr.String(), true
}

func uniqueDNSAddresses(values []string) []string {
	out := slices.Clone(values)
	slices.Sort(out)
	return slices.Compact(out)
}

func dnsDifference(values, compared []string) []string {
	var difference []string
	for _, value := range values {
		if _, found := slices.BinarySearch(compared, value); !found {
			difference = append(difference, value)
		}
	}
	return difference
}
