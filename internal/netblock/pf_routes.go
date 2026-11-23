package netblock

import (
	"errors"
	"net/netip"
	"strings"
)

func pfGateways(output string) ([]netip.Addr, error) {
	var gateways []netip.Addr
	haveTable := false
	for line := range strings.Lines(output) {
		fields := strings.Fields(line)
		if len(fields) == 0 {
			continue
		}
		if strings.TrimSpace(line) == "Routing tables" {
			haveTable = true
		}
		if fields[0] != "default" && fields[0] != "0.0.0.0/0" && fields[0] != "::/0" {
			continue
		}
		if len(fields) < 2 {
			return nil, errors.New("macOS returned an incomplete default route")
		}
		if strings.HasPrefix(fields[1], "link#") {
			continue // on-link routes have no gateway address
		}
		gateway, err := netip.ParseAddr(fields[1])
		if err != nil {
			return nil, errors.New("macOS returned an invalid default gateway")
		}
		gateways = append(gateways, gateway.WithZone("").Unmap())
	}
	if !haveTable {
		return nil, errors.New("macOS routing table was unavailable")
	}
	return gateways, nil
}
