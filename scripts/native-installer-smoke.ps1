param(
    [Parameter(Mandatory = $true)][string]$Payload,
    [Parameter(Mandatory = $true)][string]$Wix,
    [ValidateSet('amd64', 'arm64')][string]$Arch = 'amd64',
    [Parameter(Mandatory = $true)][string]$SaveInstaller
)

$ErrorActionPreference = 'Stop'
$work = Join-Path $env:RUNNER_TEMP ([Guid]::NewGuid().ToString('N'))
$install = Join-Path $env:ProgramFiles CAU
$logMarker = Join-Path $install 'Logs/upgrade-fixture.txt'
$older = Join-Path $work 'older.msi'
$newer = Join-Path $work 'newer.msi'
$inventoryExe = Join-Path (Resolve-Path -LiteralPath $Payload).Path 'cau.exe'
$installed = $null
if ((Test-Path -LiteralPath $install) -or (Get-Service CauDefend -ErrorAction SilentlyContinue)) {
    throw 'Native installer smoke requires a fresh runner'
}
$null = New-Item -ItemType Directory -Path $work
function Invoke-Msi([string]$Operation, [string]$Package) {
    $log = "$Package.log"
    Write-Output "Running Windows Installer $Operation for $(Split-Path -Leaf $Package)"
    $result = Start-Process "$env:SystemRoot/System32/msiexec.exe" `
        -ArgumentList $Operation, ('"' + $Package + '"'), '/qn', '/norestart', '/l*v', ('"' + $log + '"') -PassThru
    if (-not $result.WaitForExit(120000)) {
        $result.Kill()
        if (Test-Path -LiteralPath $log) { Get-Content -Tail 80 -LiteralPath $log }
        throw "Windows Installer timed out during $Operation"
    }
    if ($result.ExitCode -ne 0) {
        if (Test-Path -LiteralPath $log) { Get-Content -Tail 80 -LiteralPath $log }
        throw "Windows Installer returned $($result.ExitCode) during $Operation"
    }
}

function Assert-CauInventory([string[]]$Expected) {
    Write-Output "Checking installed CAU versions [$Expected]"
    $output = & $inventoryExe inventory --format json
    if ($LASTEXITCODE -notin 0, 2) { throw "Inventory returned $LASTEXITCODE" }
    $snapshot = ($output -join "`n") | ConvertFrom-Json
    $view = @($snapshot.collections | Where-Object provider -eq 'windows-uninstall-64')
    if ($view.Count -ne 1 -or $view[0].status -notin 'complete', 'partial') {
        throw 'Inventory could not read the native Windows uninstall registry'
    }
    $versions = @($view[0].packages | Where-Object name -eq 'CAU EDR' | ForEach-Object { $_.version })
    if ($versions.Count -ne $Expected.Count -or ($versions -join ',') -ne ($Expected -join ',')) {
        throw "Expected CAU inventory versions [$Expected], got [$versions]"
    }
}

try {
    Write-Output "Building the Windows $Arch installer fixtures"
    & "$PSScriptRoot/build-windows-installer.ps1" -Payload $Payload -Version 0.0.1 -Output $older -Wix $Wix -Arch $Arch
    & "$PSScriptRoot/build-windows-installer.ps1" -Payload $Payload -Version 0.0.2 -Output $newer -Wix $Wix -Arch $Arch
    Assert-CauInventory @()
    Invoke-Msi /i $older
    $installed = $older
    if ((Get-Service CauDefend).Status -ne 'Running') { throw 'Initial service start failed' }
    Assert-CauInventory @('0.0.1')
    Set-Content -LiteralPath $logMarker -Value 'keep across upgrade'
    Invoke-Msi /i $newer
    $installed = $newer
    if ((Get-Service CauDefend).Status -ne 'Running') { throw 'Service restart during upgrade failed' }
    Assert-CauInventory @('0.0.2')
    if ((Get-Content -Raw -LiteralPath $logMarker).Trim() -ne 'keep across upgrade') {
        throw 'Upgrade lost protected service logs'
    }
    & (Join-Path $install 'cau.exe') rules list | Out-Null
    if ($LASTEXITCODE -ne 0) { throw 'Installed agent could not load its rules' }
    Invoke-Msi /x $newer
    $installed = $null
    if (Get-Service CauDefend -ErrorAction SilentlyContinue) { throw 'Uninstall left the service registered' }
    if (Test-Path -LiteralPath (Join-Path $install 'cau.exe')) { throw 'Uninstall left the executable installed' }
    if ((Get-Content -Raw -LiteralPath $logMarker).Trim() -ne 'keep across upgrade') {
        throw 'Uninstall removed service logs'
    }
    Assert-CauInventory @()
    Copy-Item -LiteralPath $newer -Destination $SaveInstaller
    Write-Output "Verified Windows $Arch MSI install, major upgrade, uninstall and inventory"
} finally {
    if ($installed) { Invoke-Msi /x $installed }
    Remove-Item -LiteralPath $work -Recurse -Force
}
