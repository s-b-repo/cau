package patches

import (
	"context"
	"encoding/base64"
	"encoding/binary"
	"path/filepath"
	"syscall"
	"time"
	"unicode/utf16"
	"unsafe"
)

var getSystemDirectory = syscall.NewLazyDLL("kernel32.dll").NewProc("GetSystemDirectoryW")

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
	var buffer [32768]uint16
	n, _, _ := getSystemDirectory.Call(uintptr(unsafe.Pointer(&buffer[0])), uintptr(len(buffer))) // audit:ok synchronous Win32 call with a UTF-16 array and its character count
	if n == 0 || n >= uintptr(len(buffer)) {
		result.Warnings = append(result.Warnings, "Windows system directory could not be located")
		return
	}
	systemDir := syscall.UTF16ToString(buffer[:n])
	powershellDir := filepath.Join(systemDir, "WindowsPowerShell", "v1.0")
	env := []string{"SystemRoot=" + filepath.Dir(systemDir), "PATH=" + systemDir, "PSModulePath=" + filepath.Join(powershellDir, "Modules")}
	command := utf16.Encode([]rune(wuaScript))
	encoded := make([]byte, len(command)*2)
	for i, ch := range command {
		binary.LittleEndian.PutUint16(encoded[2*i:], ch)
	}
	output, warned, err := runCommand(ctx, filepath.Join(powershellDir, "powershell.exe"), env,
		"-NoLogo", "-NoProfile", "-NonInteractive", "-EncodedCommand", base64.StdEncoding.EncodeToString(encoded))
	if err != nil {
		result.Warnings = append(result.Warnings, "Windows Update Agent query did not complete")
		return
	}
	readWUA(result, output, warned, time.Now())
}
