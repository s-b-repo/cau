package posture

import (
	"context"

	"github.com/s-b-repo/cau/internal/nativecmd"
)

const securitySettings = `
$ErrorActionPreference = 'Stop'
$result = [ordered]@{ firewall = $null; disk = $null }
try {
    $result.firewall = @(Get-NetFirewallProfile -PolicyStore ActiveStore | ForEach-Object {
        @{ name = [string]$_.Name; enabled = [string]$_.Enabled }
    })
} catch {}
try {
    $drive = [IO.Path]::GetPathRoot($env:SystemRoot).TrimEnd('\')
    $volume = Get-BitLockerVolume -MountPoint $drive
    if ($null -ne $volume.ProtectionStatus -and $null -ne $volume.VolumeStatus) {
        $result.disk = @{ protection = [string]$volume.ProtectionStatus; volume = [string]$volume.VolumeStatus }
    }
} catch {}
[Console]::WriteLine((ConvertTo-Json -InputObject $result -Depth 4 -Compress))
`

func read(ctx context.Context) Report {
	result := newReport("windows", "windows-firewall-active-store", "bitlocker-system-volume", unavailable)
	data, warned, err := nativecmd.PowerShell(ctx, securitySettings)
	if err == nil {
		readWindowsSettings(&result, data, warned)
	}
	return result
}
