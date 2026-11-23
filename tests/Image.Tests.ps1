#Requires -Version 5.1
Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

$RepoRoot = Split-Path -Parent $PSScriptRoot
. (Join-Path $RepoRoot 'scripts\lib\Config.ps1')
. (Join-Path $RepoRoot 'scripts\lib\Image.ps1')

$script:Passed = 0
$script:Failed = 0

function Assert-True {
    param([string]$Name, [bool]$Condition)
    if ($Condition) {
        Write-Host "  [PASS] $Name"
        $script:Passed++
    } else {
        Write-Host "  [FAIL] $Name"
        $script:Failed++
    }
}

Write-Host "=== Running Image.ps1 Automated Tests ==="

# 1. Enable-ModernTls executes without error
Enable-ModernTls
Assert-True "Enable-ModernTls completes cleanly" $true

# 2. Get-FileSha256Hex returns known SHA-256 for empty and non-empty files
$tmpDir = Join-Path ([System.IO.Path]::GetTempPath()) ("wsl-box-img-test-" + [Guid]::NewGuid().ToString('N').Substring(0, 8))
New-Item -ItemType Directory -Path $tmpDir -Force | Out-Null
try {
    $emptyFile = Join-Path $tmpDir 'empty.bin'
    [System.IO.File]::WriteAllBytes($emptyFile, [byte[]]@())
    $emptyHash = Get-FileSha256Hex -Path $emptyFile
    Assert-True "Get-FileSha256Hex matches known empty-file SHA-256" ($emptyHash -eq 'e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855')

    $helloFile = Join-Path $tmpDir 'hello.txt'
    [System.IO.File]::WriteAllBytes($helloFile, [System.Text.Encoding]::ASCII.GetBytes('hello'))
    $helloHash = Get-FileSha256Hex -Path $helloFile
    Assert-True "Get-FileSha256Hex matches known 'hello' SHA-256" ($helloHash -eq '2cf24dba5fb0a30e26e83b2ac5b9e29e1b161e5c1fa7425e73043362938b9824')
} finally {
    if (Test-Path -LiteralPath $tmpDir) {
        Remove-Item -LiteralPath $tmpDir -Recurse -Force
    }
}

# 3. Canonical SHA256SUMS regex pattern matches .wsl and .rootfs.tar.gz for amd64 & arm64
$release = '26.04'
$amd64Pattern = "^([0-9a-fA-F]{64})\s+\*?(ubuntu-$([regex]::Escape($release))[0-9.]*-wsl-amd64\.(?:wsl|rootfs\.tar\.gz))$"
$arm64Pattern = "^([0-9a-fA-F]{64})\s+\*?(ubuntu-$([regex]::Escape($release))[0-9.]*-wsl-arm64\.(?:wsl|rootfs\.tar\.gz))$"
$sampleHash = 'a' * 64

Assert-True "SHA256SUMS pattern matches point-release .wsl amd64 entry" (("$sampleHash *ubuntu-26.04.1-wsl-amd64.wsl") -match $amd64Pattern)
Assert-True "SHA256SUMS pattern matches .rootfs.tar.gz arm64 entry" (("$sampleHash  ubuntu-26.04-wsl-arm64.rootfs.tar.gz") -match $arm64Pattern)
Assert-True "SHA256SUMS pattern rejects non-WSL server ISO entry" (-not (("$sampleHash *ubuntu-26.04.1-live-server-amd64.iso") -match $amd64Pattern))

Write-Host ""
Write-Host "Results: $($script:Passed) passed, $($script:Failed) failed"
if ($script:Failed -gt 0) {
    exit 1
}
