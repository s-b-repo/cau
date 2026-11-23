package desktop

import (
	"context"

	"github.com/s-b-repo/cau/internal/nativecmd"
)

const processScript = `
$ErrorActionPreference = 'Stop'
[Console]::OutputEncoding = [System.Text.UTF8Encoding]::new($false)
$rows = @(Get-CimInstance -ClassName Win32_Process -Property ProcessId,ParentProcessId,Name,ExecutablePath,CommandLine,CreationDate |
    Select-Object -First 32769 | ForEach-Object {
        @{
            pid = $_.ProcessId
            ppid = $_.ParentProcessId
            name = $_.Name
            image = $_.ExecutablePath
            command = $_.CommandLine
            created = if ($null -ne $_.CreationDate) { $_.CreationDate.ToFileTimeUtc() } else { 0 }
        }
    })
[Console]::WriteLine((ConvertTo-Json -InputObject $rows -Compress))
`

func readProcesses(ctx context.Context) ProcessSnapshot {
	out, warned, err := nativecmd.PowerShell(ctx, processScript)
	return processSnapshot("windows-cim-process", out, warned, err, parseWindowsProcesses)
}
