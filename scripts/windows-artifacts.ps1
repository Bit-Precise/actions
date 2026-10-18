#Requires -Version 7.0
[CmdletBinding()]
param(
    [Parameter(Mandatory)] [ValidateSet('Prepare', 'Verify')] [string] $Phase,
    [Parameter(Mandatory)] [ValidateSet('exe', 'msi')] [string] $Stage,
    [Parameter(Mandatory)] [string] $InputDirectory,
    [Parameter(Mandatory)] [string] $OutputDirectory
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'
$PSNativeCommandUseErrorActionPreference = $false

function Get-CheckedFiles {
    param([string] $Directory)
    $root = Get-Item -LiteralPath $Directory
    if (-not $root.PSIsContainer -or ($root.Attributes -band [IO.FileAttributes]::ReparsePoint)) {
        throw 'Artifact root must be a regular directory, not a reparse point.'
    }
    $items = @(Get-ChildItem -LiteralPath $Directory -Force)
    if ($items.Count -lt 1 -or $items.Count -gt 32) { throw 'Expected 1-32 flat signing inputs.' }
    $total = 0L
    foreach ($item in $items) {
        if ($item.PSIsContainer -or ($item.Attributes -band [IO.FileAttributes]::ReparsePoint)) {
            throw 'Artifact inputs must be regular files; directories, junctions and symlinks are not supported.'
        }
        if ($item.Name -notmatch '^[A-Za-z0-9][A-Za-z0-9._-]*\.(exe|msi)$' -or $item.Extension -cne ".$Stage") {
            throw "All files must have safe names and the selected .$Stage extension."
        }
        if ($item.Length -lt 8 -or $item.Length -gt 512MB) { throw 'Each signing input must be 8 bytes to 512 MiB.' }
        $total += $item.Length
        $stream = [IO.File]::OpenRead($item.FullName)
        try {
            $header = [byte[]]::new(8)
            $null = $stream.Read($header, 0, 8)
        } finally { $stream.Dispose() }
        if ($Stage -eq 'exe' -and ($header[0] -ne 0x4d -or $header[1] -ne 0x5a)) { throw 'EXE is missing its PE header.' }
        if ($Stage -eq 'msi' -and [Convert]::ToHexString($header) -ne 'D0CF11E0A1B11AE1') { throw 'MSI is missing its compound-file header.' }
    }
    if ($total -gt 2GB) { throw 'Signing input exceeds the 2 GiB batch limit.' }
    return $items
}

try {
    if (-not $IsWindows) { throw 'Windows signing verification requires a native Windows runner.' }
    $inputRoot = [IO.Path]::GetFullPath($InputDirectory)
    $outputRoot = [IO.Path]::GetFullPath($OutputDirectory)
    if ($inputRoot -eq $outputRoot) { throw 'Signing output must be separate from input.' }
    if ($Phase -eq 'Prepare') {
        $files = @(Get-CheckedFiles $inputRoot)
        if (Test-Path -LiteralPath $outputRoot) { throw 'Signing output directory must not exist.' }
        $null = New-Item -ItemType Directory -Path $outputRoot
        foreach ($file in $files) { Copy-Item -LiteralPath $file.FullName -Destination (Join-Path $outputRoot $file.Name) }
    } else {
        $files = @(Get-CheckedFiles $outputRoot)
        $sdkRoot = Join-Path ${env:ProgramFiles(x86)} 'Windows Kits/10/bin'
        $sdkTool = Get-ChildItem -Path (Join-Path $sdkRoot '*/x64/signtool.exe') | Sort-Object FullName -Descending | Select-Object -First 1
        if ($null -eq $sdkTool) { throw 'Windows SDK signtool.exe is required.' }
        $records = @()
        foreach ($file in $files) {
            $signature = Get-AuthenticodeSignature -LiteralPath $file.FullName
            if ($signature.Status -ne 'Valid' -or $null -eq $signature.SignerCertificate -or $null -eq $signature.TimeStamperCertificate) {
                throw 'Every output must have a valid Authenticode signature and timestamp certificate.'
            }
            & $sdkTool.FullName verify /pa /all /tw $file.FullName
            if ($LASTEXITCODE -ne 0) { throw 'signtool signature/timestamp verification failed.' }
            $records += @{name = $file.Name; sha256 = (Get-FileHash -LiteralPath $file.FullName -Algorithm SHA256).Hash.ToLowerInvariant(); signerThumbprint = $signature.SignerCertificate.Thumbprint; timestampVerified = $true}
        }
        @{provider = 'Azure Artifact Signing'; stage = $Stage; signed = $true; files = $records} |
            ConvertTo-Json -Depth 10 | Set-Content -LiteralPath (Join-Path $outputRoot 'SIGNINGINFO.json') -Encoding utf8
        $lines = Get-ChildItem -LiteralPath $outputRoot -File | Sort-Object Name | ForEach-Object {
            (Get-FileHash -LiteralPath $_.FullName -Algorithm SHA256).Hash.ToLowerInvariant() + '  ' + $_.Name
        }
        $lines | Set-Content -LiteralPath (Join-Path $outputRoot 'SHA256SUMS') -Encoding utf8
    }
} catch {
    Write-Error $_ -ErrorAction Continue
    exit 1
}
