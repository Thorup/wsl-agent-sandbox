#Requires -Version 5.1
Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

$RepoRoot = Split-Path -Parent $PSScriptRoot
. (Join-Path $RepoRoot 'scripts\lib\Config.ps1')

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

function Assert-Throws {
    param([string]$Name, [scriptblock]$Block, [string]$ExpectedPattern = '')
    try {
        & $Block
        Write-Host "  [FAIL] $Name (expected exception, none thrown)"
        $script:Failed++
    } catch {
        if ($ExpectedPattern -and $_.Exception.Message -notmatch $ExpectedPattern) {
            Write-Host "  [FAIL] $Name (unexpected error: $($_.Exception.Message))"
            $script:Failed++
        } else {
            Write-Host "  [PASS] $Name"
            $script:Passed++
        }
    }
}

function Copy-Config {
    param($Obj)
    return ($Obj | ConvertTo-Json -Depth 10 | ConvertFrom-Json)
}

Write-Host "=== Running Config.ps1 Automated Tests ==="

$baseCfg = Read-BoxConfig -ConfigPath (Join-Path $RepoRoot 'box.json')
Assert-True "Default box.json parses and validates cleanly" ($baseCfg.distroName -eq 'wsl-agent-sandbox')
Assert-True "Default installDir matches distroName" ($baseCfg.installDir -eq '%LOCALAPPDATA%\WSL\wsl-agent-sandbox')
Assert-True "Default sharedFolders is empty (deny-all)" (@($baseCfg.sharedFolders).Count -eq 0)
Assert-True "Default agentUser UID is in high isolated range (26040)" ($baseCfg.agentUser.uid -eq 26040)
Assert-True "Default box.json enables GitHub, Azure, Azure DevOps, and Jira CLIs" (
    [bool]$baseCfg.packages.installGithubCli -and
    [bool]$baseCfg.packages.installAzureCli -and
    [bool]$baseCfg.packages.installAzureDevopsCli -and
    [bool]$baseCfg.packages.installJiraCli
)

# Reject root user
Assert-Throws "Rejects agentUser.name = root" {
    $c = Copy-Config $baseCfg
    $c.agentUser.name = 'root'
    Assert-BoxConfigValid -Config $c
} 'non-root'

# Reject low UID (could collide with UID 1000 in other WSL distros)
Assert-Throws "Rejects agentUser.uid = 1000 (collision with other distros)" {
    $c = Copy-Config $baseCfg
    $c.agentUser.uid = 1000
    Assert-BoxConfigValid -Config $c
} 'between 10000 and 60000'

# Reject mounting entire C:\ drive
Assert-Throws "Rejects sharing entire Windows C:\ drive root" {
    $c = Copy-Config $baseCfg
    $c.sharedFolders = @([pscustomobject]@{ name = 'croot'; windowsPath = 'C:\'; mode = 'ro'; allowDockerBind = $false })
    Assert-BoxConfigValid -Config $c
} 'drive root'

# Reject invalid shared folder name (path traversal)
Assert-Throws "Rejects path traversal in sharedFolders name" {
    $c = Copy-Config $baseCfg
    $c.sharedFolders = @([pscustomobject]@{ name = '../evil'; windowsPath = 'C:\Temp\a'; mode = 'ro'; allowDockerBind = $false })
    Assert-BoxConfigValid -Config $c
} 'Invalid sharedFolders'

# Reject invalid mode
Assert-Throws "Rejects invalid sharedFolders mode" {
    $c = Copy-Config $baseCfg
    $c.sharedFolders = @([pscustomobject]@{ name = 'docs'; windowsPath = 'C:\Temp\docs'; mode = 'rwx'; allowDockerBind = $false })
    Assert-BoxConfigValid -Config $c
} 'must be ''ro'' or ''rw'''

# Accept valid sharedFolder
$validShareCfg = Copy-Config $baseCfg
$validShareCfg.sharedFolders = @([pscustomobject]@{ name = 'docs'; windowsPath = 'C:\Users\demo\docs'; mode = 'ro'; allowDockerBind = $true })
Assert-BoxConfigValid -Config $validShareCfg
Assert-True "Accepts valid read-only sharedFolder entry" $true

# Reject invalid host port
Assert-Throws "Rejects out-of-range allowedHostPorts port" {
    $c = Copy-Config $baseCfg
    $c.network.allowedHostPorts = @([pscustomobject]@{ port = 70000; protocol = 'tcp' })
    Assert-BoxConfigValid -Config $c
} '1-65535'

# Reject invalid CIDR
Assert-Throws "Rejects invalid blockedCidrs entry" {
    $c = Copy-Config $baseCfg
    $c.network.blockedCidrs = @('999.999.999.999/24')
    Assert-BoxConfigValid -Config $c
} 'Invalid IP'

# Reject unsafe docker.allowBindPrefixes
Assert-Throws "Rejects /mnt/c in docker.allowBindPrefixes" {
    $c = Copy-Config $baseCfg
    $c.docker.allowBindPrefixes = @('/home/agent', '/mnt/c')
    Assert-BoxConfigValid -Config $c
} 'Unsafe docker.allowBindPrefixes'

Assert-Throws "Rejects / in docker.allowBindPrefixes" {
    $c = Copy-Config $baseCfg
    $c.docker.allowBindPrefixes = @('/')
    Assert-BoxConfigValid -Config $c
} 'Unsafe docker.allowBindPrefixes'

# Reject shell injection in apt package names
Assert-Throws "Rejects shell metacharacters in apt package names" {
    $c = Copy-Config $baseCfg
    $c.packages.apt = @('git; rm -rf /')
    Assert-BoxConfigValid -Config $c
} 'Invalid apt package'

# Accept optional non-secret secrets.manifestPath pointer
$withSecretsPtr = Copy-Config $baseCfg
$withSecretsPtr | Add-Member -NotePropertyName 'secrets' -NotePropertyValue ([pscustomobject]@{ manifestPath = '%USERPROFILE%\.wsl-agent-sandbox\secrets.json' })
Assert-BoxConfigValid -Config $withSecretsPtr
Assert-True "Accepts optional non-secret secrets.manifestPath pointer" $true

# Reject storing actual secret values inside box.json
Assert-Throws "Rejects storing raw credential keys inside box.json secrets section" {
    $c = Copy-Config $baseCfg
    $c | Add-Member -NotePropertyName 'secrets' -NotePropertyValue ([pscustomobject]@{ github = @{ token = 'ghp_nope' } })
    Assert-BoxConfigValid -Config $c
} 'only allows non-secret pointer property'

# Deep-merge box.local.json override tests
$tmpCfgDir = Join-Path ([System.IO.Path]::GetTempPath()) ("wsl-box-cfg-test-" + [Guid]::NewGuid().ToString('N').Substring(0, 8))
New-Item -ItemType Directory -Path $tmpCfgDir -Force | Out-Null
try {
    $baseFile = Join-Path $tmpCfgDir 'box.json'
    $localFile = Join-Path $tmpCfgDir 'box.local.json'
    Copy-Item -LiteralPath (Join-Path $RepoRoot 'box.json') -Destination $baseFile

    $overrideObj = @{
        sharedFolders = @(
            @{ name = 'work'; windowsPath = 'C:\Users\demo\work'; mode = 'ro'; allowDockerBind = $true }
        )
        network = @{
            allowedHostPorts = @(
                @{ port = 8080; protocol = 'tcp'; comment = 'local test' }
            )
        }
        packages = @{
            installKubectl = $false
        }
    }
    [System.IO.File]::WriteAllText($localFile, ($overrideObj | ConvertTo-Json -Depth 10), (New-Object System.Text.UTF8Encoding($false)))

    $mergedCfg = Read-BoxConfig -ConfigPath $baseFile
    Assert-True "box.local.json overrides array (sharedFolders)" (@($mergedCfg.sharedFolders).Count -eq 1 -and $mergedCfg.sharedFolders[0].name -eq 'work')
    Assert-True "box.local.json deep-merges nested object while preserving sibling keys (network.blockHostAndLan)" ([bool]$mergedCfg.network.blockHostAndLan -and @($mergedCfg.network.allowedHostPorts).Count -eq 1 -and $mergedCfg.network.allowedHostPorts[0].port -eq 8080)
    Assert-True "box.local.json overrides nested boolean while preserving other package flags" (-not [bool]$mergedCfg.packages.installKubectl -and [bool]$mergedCfg.packages.installNodeLts)
    Assert-True "Get-BoxLocalOverridePath detects adjacent box.local.json" ((Get-BoxLocalOverridePath -ConfigPath $baseFile) -eq $localFile)

    [System.IO.File]::WriteAllText($localFile, (@{ agentUser = @{ uid = 1000 } } | ConvertTo-Json -Depth 5), (New-Object System.Text.UTF8Encoding($false)))
    Assert-Throws "Rejects invalid agentUser.uid introduced via box.local.json" {
        Read-BoxConfig -ConfigPath $baseFile | Out-Null
    } 'between 10000 and 60000'
} finally {
    if (Test-Path -LiteralPath $tmpCfgDir) {
        Remove-Item -LiteralPath $tmpCfgDir -Recurse -Force
    }
}

Write-Host ""
Write-Host "=== Config.Tests.ps1 Summary: PASS=$script:Passed FAIL=$script:Failed ==="
if ($script:Failed -gt 0) {
    exit 1
}
exit 0
