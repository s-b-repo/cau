package netscan

import (
	"context"

	"github.com/s-b-repo/cau/internal/nativecmd"
)

func readHostDNS(ctx context.Context) DNSPosture {
	output, warned, err := nativecmd.Unix(ctx, "/usr/sbin/scutil", "--dns")
	return nativeDNSPosture(readNativeDNS("scutil --dns", macDNSAddresses(string(output)), warned, err))
}
