param(
    [Parameter(Mandatory = $true)][string]$Payload,
    [Parameter(Mandatory = $true)][string]$Version,
    [Parameter(Mandatory = $true)][string]$Output,
    [Parameter(Mandatory = $true)][string]$Wix,
    [ValidateSet('amd64', 'arm64')][string]$Arch = 'amd64'
)

$ErrorActionPreference = 'Stop'
if ($Version -notmatch '^(0|[1-9][0-9]{0,2})[.](0|[1-9][0-9]{0,2})[.](0|[1-9][0-9]{0,4})(?:[+-][0-9A-Za-z.+-]+)?$') {
    throw 'MSI version must begin with a three-component release version'
}
$parts = @([int]$Matches[1], [int]$Matches[2], [int]$Matches[3])
if ($parts[0] -gt 255 -or $parts[1] -gt 255 -or $parts[2] -gt 65535) {
    throw 'MSI version exceeds the Windows Installer numeric range'
}
$productVersion = $parts -join '.'
$payloadPath = (Resolve-Path -LiteralPath $Payload).Path
$machine = @{amd64 = 0x8664; arm64 = 0xaa64}[$Arch]
foreach ($name in 'cau.exe', 'cau-mcp.exe') {
    $stream = [IO.File]::OpenRead((Join-Path $payloadPath $name))
    $pe = [IO.BinaryReader]::new($stream)
    try {
        if ($pe.ReadUInt16() -ne 0x5a4d) { throw "$name does not have a Windows executable header" }
        $stream.Position = 0x3c
        $header = $pe.ReadInt32()
        if ($header -lt 64 -or $header -gt $stream.Length - 6) {
            throw "$name has an invalid PE header offset"
        }
        $stream.Position = $header
        if ($pe.ReadUInt32() -ne 0x4550 -or $pe.ReadUInt16() -ne $machine) {
            throw "$name does not match the Windows $Arch package"
        }
    } finally {
        $pe.Dispose()
    }
}
$wixArch = @{amd64 = 'x64'; arm64 = 'arm64'}[$Arch]
$outputPath = $ExecutionContext.SessionState.Path.GetUnresolvedProviderPathFromPSPath($Output)
$source = Join-Path $PSScriptRoot '../packaging/windows/CAU.wxs'
& $Wix build -arch $wixArch -d "Payload=$payloadPath" -d "ProductVersion=$productVersion" -o $outputPath $source
if ($LASTEXITCODE -ne 0 -or -not (Test-Path -LiteralPath $outputPath -PathType Leaf)) {
    throw "WiX did not build $outputPath"
}
