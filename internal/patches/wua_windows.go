package patches

import (
	"context"
	"time"

	"github.com/s-b-repo/cau/internal/nativecmd"
)

// The Windows Update Agent stays on the configured update source, uses its
// local cache, and is explicitly prevented from upgrading itself on search.
// Each independent query can fail without erasing the others' observations.
const wuaScript = `
$ErrorActionPreference = 'Stop'
$result = [ordered]@{ version = ''; build = ''; reboot_required = $null; last_search = $null; result_code = 0; warning_count = 0; update_count = $null; updates = @() }
try {
    $os = Get-ItemProperty -LiteralPath 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion'
    $result.version = [string]$os.DisplayVersion
    $result.build = [string]$os.CurrentBuildNumber
    if ($null -ne $os.UBR) { $result.build += '.' + [string]$os.UBR }
} catch {}
try {
    $info = New-Object -ComObject 'Microsoft.Update.SystemInfo'
    $reboot = $info.RebootRequired
    if ($reboot -is [bool]) { $result.reboot_required = $reboot }
} catch {}
try {
    $auto = New-Object -ComObject 'Microsoft.Update.AutoUpdate'
    $searchDate = [datetime]$auto.Results.LastSearchSuccessDate
    if ($searchDate.Year -ge 2000) {
        $result.last_search = $searchDate.ToString("yyyy-MM-ddTHH:mm:ss'Z'", [Globalization.CultureInfo]::InvariantCulture)
    }
} catch {}
try {
    $session = New-Object -ComObject 'Microsoft.Update.Session'
    $searcher = $session.CreateUpdateSearcher()
    $searcher.Online = $false
    $searcher.CanAutomaticallyUpgradeService = $false
    $found = $searcher.Search('IsInstalled=0 and IsHidden=0')
    $result.result_code = [int]$found.ResultCode
    $result.warning_count = [int]$found.Warnings.Count
    $result.update_count = [int]$found.Updates.Count
    if ($result.update_count -le 10000) {
        $result.updates = @(for ($i = 0; $i -lt $result.update_count; $i++) {
            $identity = $found.Updates.Item($i).Identity
            @{ id = [string]$identity.UpdateID; revision = [int]$identity.RevisionNumber }
        })
    }
} catch {}
[Console]::WriteLine((ConvertTo-Json -InputObject $result -Depth 4 -Compress))
`

func collectWindows(ctx context.Context, result *Assessment) {
	result.Source = "windows-update-agent-cache"
	result.AssessmentStatus = Unknown
	result.Restart = Restart{State: Unknown, Source: "windows-update-agent", Reason: "Windows Update Agent could not attest restart state"}
	output, warned, err := nativecmd.PowerShell(ctx, wuaScript)
	if err != nil {
		result.Warnings = append(result.Warnings, "Windows Update Agent query did not complete")
		return
	}
	readWUA(result, output, warned, time.Now())
}
