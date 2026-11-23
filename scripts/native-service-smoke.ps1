param(
    [Parameter(Mandatory = $true)][string]$Binary,
    [Parameter(Mandatory = $true)][string]$Work
)

$ErrorActionPreference = 'Stop'
$name = 'CauDefend'
if (Get-Service -Name $name -ErrorAction SilentlyContinue) {
    throw "$name already exists"
}
$watch = Join-Path $Work 'watch'
$logs = Join-Path $Work 'logs'
$rules = Join-Path $Work 'smoke.yar'
$null = New-Item -ItemType Directory -Path $watch, $logs
$command = '"' + $Binary + '" --windows-service "' + $logs + '" --report-only --watch "' + $watch + '" --rules "' + $rules + '"'
$null = New-Service -Name $name -BinaryPathName $command -StartupType Manual
try {
    foreach ($attempt in 1, 2) {
        $service = Start-Service -Name $name -PassThru
        $service.WaitForStatus('Running', [TimeSpan]::FromSeconds(30))
        $log = Get-Content -Raw -LiteralPath (Join-Path $logs 'defend.log')
        if ($log -notmatch 'watching 1 directory subscriptions' -or $log -notmatch 'REPORT-ONLY') {
            throw "Service startup did not attach the watch: $log"
        }
        $fixture = "match-$attempt.txt"
        Copy-Item -LiteralPath (Join-Path $Work 'match.txt') -Destination (Join-Path $watch $fixture)
        $deadline = [DateTime]::UtcNow.AddSeconds(20)
        $incidents = Join-Path $logs 'incidents.jsonl'
        do {
            if (Select-String -Quiet -SimpleMatch -LiteralPath $incidents -Pattern $fixture) { break }
            Start-Sleep -Milliseconds 250
        } while ([DateTime]::UtcNow -lt $deadline)
        if (-not (Select-String -Quiet -SimpleMatch -LiteralPath $incidents -Pattern $fixture)) {
            throw "Service did not scan $fixture"
        }
        try {
            Stop-Service -Name $name
        } catch {
            if ((Get-Service -Name $name).Status -ne 'Stopped') { throw }
        }
        $service.WaitForStatus('Stopped', [TimeSpan]::FromSeconds(30))
        $status = Get-CimInstance -ClassName Win32_Service -Filter "Name='$name'"
        if ($status.ExitCode -ne 0 -or $status.ServiceSpecificExitCode -ne 0) {
            throw "Service stopped with exit codes $($status.ExitCode) and $($status.ServiceSpecificExitCode)"
        }
    }
    Write-Output 'Verified Windows Service Control Manager start, live scan, stop and restart'
} finally {
    Stop-Service -Name $name -ErrorAction SilentlyContinue
    & "$env:SystemRoot\System32\sc.exe" delete $name
    if ($LASTEXITCODE -ne 0) { throw "Could not remove CI service $name" }
}
