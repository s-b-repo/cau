package persist

import (
	"context"
	"encoding/json"

	"github.com/s-b-repo/cau/internal/nativecmd"
)

const nativeStartupScript = `
$ErrorActionPreference = 'Stop'
[Console]::OutputEncoding = [System.Text.UTF8Encoding]::new($false)
$rows = [Collections.Generic.List[object]]::new()
$gaps = [Collections.Generic.List[string]]::new()
foreach ($hive in 'LocalMachine','CurrentUser') {
    foreach ($view in 'Registry64','Registry32') {
        $base = $null
        try {
            $base = [Microsoft.Win32.RegistryKey]::OpenBaseKey($hive, $view)
            foreach ($suffix in 'Run','RunOnce') {
                $path = 'SOFTWARE\Microsoft\Windows\CurrentVersion\' + $suffix
                $key = $base.OpenSubKey($path)
                if ($null -eq $key) { continue }
                try {
                    foreach ($name in $key.GetValueNames()) {
                        if ($rows.Count -ge 8192) { break }
                        $value = $key.GetValue($name, $null, 'DoNotExpandEnvironmentNames')
                        if ($value -is [string]) {
                            $rows.Add(@{ path = "$hive/$view/$suffix/$name"; technique = 'T1547.001'; command = $value })
                        } else { $gaps.Add("$hive/$view/$suffix") }
                    }
                } finally { $key.Dispose() }
            }
        } catch { $gaps.Add("$hive/$view/Run and RunOnce") }
        finally { if ($null -ne $base) { $base.Dispose() } }
    }
}
try {
    Get-CimInstance -ClassName Win32_Service -Property Name,PathName |
        Select-Object -First 8193 | ForEach-Object {
            if ($rows.Count -lt 8192 -and $_.PathName) {
                $rows.Add(@{ path = 'SCM/' + $_.Name; technique = 'T1543.003'; command = $_.PathName })
            }
        }
} catch { $gaps.Add('Windows services') }
try {
    foreach ($task in (Get-ScheduledTask | Select-Object -First 8193)) {
        if ($rows.Count -ge 8192) { break }
        foreach ($action in $task.Actions) {
            if ($rows.Count -ge 8192) { break }
            if ($action.Execute) {
                $rows.Add(@{
                    path = 'Task Scheduler/' + $task.TaskPath + $task.TaskName
                    technique = 'T1053.005'
                    executable = [string]$action.Execute
                    command = ([string]$action.Execute + ' ' + [string]$action.Arguments).Trim()
                })
            }
        }
    }
} catch { $gaps.Add('Windows scheduled tasks') }
if ($rows.Count -ge 8192) { $gaps.Add('native startup record limit') }
[Console]::WriteLine((ConvertTo-Json -InputObject @{ rows = @($rows.ToArray()); incomplete = @($gaps.ToArray()) } -Depth 4 -Compress))
`

func readNativeStartup(ctx context.Context) startupSnapshot {
	result := startupSnapshot{source: "windows-registry-and-services"}
	out, warned, err := nativecmd.PowerShell(ctx, nativeStartupScript)
	var raw struct {
		Rows       []nativeStartup `json:"rows"`
		Incomplete []string        `json:"incomplete"`
	}
	if err != nil || json.Unmarshal(out, &raw) != nil {
		result.incomplete = []string{"Windows startup query"}
		return result
	}
	result.entries = raw.Rows[:min(len(raw.Rows), nativeStartupLimit)]
	result.incomplete = raw.Incomplete
	if warned || len(raw.Rows) > nativeStartupLimit {
		result.incomplete = append(result.incomplete, "Windows startup query")
	}
	return result
}
