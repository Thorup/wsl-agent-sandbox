#Requires -Version 5.1
Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

$RepoRoot = Split-Path -Parent $PSScriptRoot
. (Join-Path $RepoRoot 'scripts\lib\Config.ps1')
. (Join-Path $RepoRoot 'scripts\lib\Secrets.ps1')

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

Write-Host "=== Running Backward-Compatibility Fixture Tests ==="

$compatDir = Join-Path $RepoRoot 'tests\fixtures\compat'
$boxFixtures = @(Get-ChildItem -Path $compatDir -Filter 'box-*.json' | Sort-Object Name)
Assert-True "At least one golden box-*.json compat fixture exists" ($boxFixtures.Count -ge 1)

foreach ($bf in $boxFixtures) {
    $cfg = Read-BoxConfig -ConfigPath $bf.FullName
    Assert-BoxConfigValid -Config $cfg
    Assert-True "Legacy fixture $($bf.Name) parses and validates via Read-BoxConfig" ($cfg.distroName -eq 'wsl-agent-sandbox')
}

$secretFixtures = @(Get-ChildItem -Path $compatDir -Filter 'secrets-*.json' | Sort-Object Name)
Assert-True "At least one golden secrets-*.json compat fixture exists" ($secretFixtures.Count -ge 1)

foreach ($sf in $secretFixtures) {
    $resolved = Build-SeedSecretsPayload -ManifestPath $sf.FullName -AgentName 'agent'
    Assert-True "Legacy fixture $($sf.Name) resolves cleanly via Build-SeedSecretsPayload" ($null -ne $resolved -and $null -ne $resolved.Payload.services.github -and $null -ne $resolved.Payload.services.aws)
}

Write-Host ""
Write-Host "Results: $($script:Passed) passed, $($script:Failed) failed"
if ($script:Failed -gt 0) {
    exit 1
}
