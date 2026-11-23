//go:build !linux && !darwin && !windows

package netscan

import "context"

func readHostDNS(context.Context) DNSPosture {
	return nativeDNSPosture(DNSResolverSource{Path: "none", Status: "unsupported",
		Reason: "no native resolver configuration provider for this OS", Nameservers: []string{}})
}
