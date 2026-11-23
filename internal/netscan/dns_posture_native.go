package netscan

import (
	"strconv"
	"strings"
)

func macDNSAddresses(output string) []string {
	var addresses []string
	inConfig := false
	for line := range strings.Lines(output) {
		line = strings.TrimSpace(line)
		if line == "DNS configuration" || strings.HasPrefix(line, "DNS configuration (") {
			inConfig = true
			continue
		}
		if !inConfig || !strings.HasPrefix(line, "nameserver[") {
			continue
		}
		index, rest, found := strings.Cut(strings.TrimPrefix(line, "nameserver["), "]")
		_, err := strconv.ParseUint(index, 10, 32)
		value, colon := strings.CutPrefix(strings.TrimSpace(rest), ":")
		if !found || err != nil || !colon {
			addresses = append(addresses, "")
			continue
		}
		addresses = append(addresses, strings.TrimSpace(value))
	}
	return addresses
}

func readNativeDNS(source string, addresses []string, warned bool, err error) DNSResolverSource {
	out := DNSResolverSource{Path: source, Status: dnsComplete, Nameservers: []string{}}
	malformed := false
	for _, raw := range addresses {
		address, ok := DNSAddress(raw)
		if !ok {
			malformed = true
			continue
		}
		out.Nameservers = append(out.Nameservers, address)
	}
	out.Nameservers = uniqueDNSAddresses(out.Nameservers)
	switch {
	case err != nil && len(out.Nameservers) == 0:
		out.Status, out.Reason = "unavailable", "native resolver query did not complete"
	case err != nil || warned || malformed:
		out.Status, out.Reason = "partial", "native resolver output was incomplete or invalid"
	case len(out.Nameservers) == 0:
		out.Status, out.Reason = "unknown", "no nameserver addresses were returned"
	}
	return out
}
