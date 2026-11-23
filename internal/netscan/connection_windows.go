package netscan

import (
	"context"

	"github.com/s-b-repo/cau/internal/nativecmd"
)

const socketScript = `
$ErrorActionPreference = 'Stop'
[Console]::OutputEncoding = [System.Text.UTF8Encoding]::new($false)
$partial = $false
$available = 0
$names = @{}
try {
    foreach ($process in Get-Process) { $names[[int]$process.Id] = $process.ProcessName }
} catch { $partial = $true }
$rows = @(
    try {
        Get-NetTCPConnection | Select-Object -First 16385 | ForEach-Object {
            @{ pid = $_.OwningProcess; name = $names[[int]$_.OwningProcess]; proto = 'tcp'; state = [string]$_.State
               local_address = $_.LocalAddress; local_port = $_.LocalPort
               remote_address = $_.RemoteAddress; remote_port = $_.RemotePort }
        }
        $available++
    } catch { $partial = $true }
    try {
        Get-NetUDPEndpoint | Select-Object -First 16385 | ForEach-Object {
            @{ pid = $_.OwningProcess; name = $names[[int]$_.OwningProcess]; proto = 'udp'; local_address = $_.LocalAddress; local_port = $_.LocalPort }
        }
        $available++
    } catch { $partial = $true }
)
if ($available -eq 0) { exit 1 }
[Console]::WriteLine((ConvertTo-Json -InputObject @{ rows = $rows; partial = $partial } -Depth 4 -Compress))
`

func nativeConnections(ctx context.Context) connectionSnapshot {
	out, warned, err := nativecmd.PowerShell(ctx, socketScript)
	if err != nil {
		return collectedConnections("windows-nettcpip", nil, 0, warned, err)
	}
	rows, bad, err := parseWindowsConnections(out)
	return collectedConnections("windows-nettcpip", rows, bad, warned, err)
}
