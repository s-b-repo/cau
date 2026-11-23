package netscan

import "context"

func readHostDNS(context.Context) DNSPosture {
	return ReadDNSPosture("", "")
}
