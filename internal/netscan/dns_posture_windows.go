package netscan

import (
	"context"
	"strings"

	"github.com/s-b-repo/cau/internal/nativecmd"
)

const dnsClientScript = `
$ErrorActionPreference = 'Stop'
$connected = @(Get-NetIPInterface -ConnectionState Connected)
foreach ($entry in @(Get-DnsClientServerAddress)) {
    if ($connected | Where-Object {
        $_.InterfaceIndex -eq $entry.InterfaceIndex -and $_.AddressFamily -eq $entry.AddressFamily
    } | Select-Object -First 1) {
        foreach ($address in $entry.ServerAddresses) { [Console]::WriteLine($address) }
    }
}
`

func readHostDNS(ctx context.Context) DNSPosture {
	output, warned, err := nativecmd.PowerShell(ctx, dnsClientScript)
	var addresses []string
	for line := range strings.Lines(string(output)) {
		if line = strings.TrimSpace(line); line != "" {
			addresses = append(addresses, line)
		}
	}
	return nativeDNSPosture(readNativeDNS("DnsClient connected IP interfaces", addresses, warned, err))
}
