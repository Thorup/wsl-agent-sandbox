#Requires -Version 5.1
Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

$RepoRoot = Split-Path -Parent $PSScriptRoot
. (Join-Path $RepoRoot 'scripts\lib\Config.ps1')
. (Join-Path $RepoRoot 'scripts\lib\Terminal.ps1')

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

$baseCfg = Read-BoxConfig -ConfigPath (Join-Path $RepoRoot 'box.json') -IgnoreLocalOverride
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

# Validate network.logDrops boolean type
$logDropsOk = Copy-Config $baseCfg
$logDropsOk.network | Add-Member -NotePropertyName 'logDrops' -NotePropertyValue $false -Force
Assert-BoxConfigValid -Config $logDropsOk
Assert-True "Accepts boolean network.logDrops = false" $true

Assert-Throws "Rejects non-boolean string network.logDrops = 'false'" {
    $c = Copy-Config $baseCfg
    $c.network | Add-Member -NotePropertyName 'logDrops' -NotePropertyValue 'false' -Force
    Assert-BoxConfigValid -Config $c
} 'must be a boolean'

# Validate egressMode and allowedDomains
$allowlistCfg = Copy-Config $baseCfg
$allowlistCfg.network | Add-Member -NotePropertyName 'egressMode' -NotePropertyValue 'allowlist'
$allowlistCfg.network | Add-Member -NotePropertyName 'allowedDomains' -NotePropertyValue @('llm-apis', 'api.github.com')
Assert-BoxConfigValid -Config $allowlistCfg
Assert-True "Accepts valid network.egressMode=allowlist with allowedDomains" $true

Assert-Throws "Rejects invalid network.egressMode" {
    $c = Copy-Config $baseCfg
    $c.network | Add-Member -NotePropertyName 'egressMode' -NotePropertyValue 'deny-all'
    Assert-BoxConfigValid -Config $c
} 'egressMode'

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

foreach ($unsafePrefix in @('/etc', '/etc/wsl-agent-sandbox', '/var', '/var/run', '/var/spool', '/run/box-root', '/root', '/shared/foo', '/home/agent/../etc')) {
    Assert-Throws "Rejects $unsafePrefix in docker.allowBindPrefixes" {
        $c = Copy-Config $baseCfg
        $c.docker.allowBindPrefixes = @($unsafePrefix)
        Assert-BoxConfigValid -Config $c
    } 'Unsafe docker.allowBindPrefixes'
}

Assert-Throws "Rejects null item in docker.allowBindPrefixes" {
    $c = Copy-Config $baseCfg
    $c.docker.allowBindPrefixes = @($null)
    Assert-BoxConfigValid -Config $c
} 'Unsafe docker.allowBindPrefixes'

$customBindCfg = Copy-Config $baseCfg
$customBindCfg.docker.allowBindPrefixes = @('/home/agent/work', '/tmp/builds', '/var/tmp/builds')
Assert-BoxConfigValid -Config $customBindCfg
Assert-True "Accepts subdirectory and custom safe paths in docker.allowBindPrefixes" $true

$emptyBindCfg = Copy-Config $baseCfg
$emptyBindCfg.docker.allowBindPrefixes = @()
Assert-BoxConfigValid -Config $emptyBindCfg
Assert-True "Accepts empty array [] in docker.allowBindPrefixes" $true

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

    # Finding 1: Hashtable input to Merge-BoxConfigObject must not leak .Keys/.Values/.Count
    $htMerged = Merge-BoxConfigObject -Base $baseCfg -Override @{ packages = @{ installKubectl = $false }; customSection = @{ enabled = $true } }
    $leakedProps = @($htMerged.PSObject.Properties.Name | Where-Object { $_ -in @('Keys', 'Values', 'Count', 'IsReadOnly', 'SyncRoot') })
    Assert-True "Merge-BoxConfigObject supports Hashtable overrides without corrupting properties" ($leakedProps.Count -eq 0 -and -not [bool]$htMerged.packages.installKubectl -and [bool]$htMerged.packages.installNodeLts -and [bool]$htMerged.customSection.enabled)

    # Finding 2: Reject non-object box.local.json (array and scalar)
    [System.IO.File]::WriteAllText($localFile, '["oops"]', (New-Object System.Text.UTF8Encoding($false)))
    Assert-Throws "Rejects JSON array in box.local.json" {
        Read-BoxConfig -ConfigPath $baseFile | Out-Null
    } 'must be a JSON object'

    [System.IO.File]::WriteAllText($localFile, '"oops"', (New-Object System.Text.UTF8Encoding($false)))
    Assert-Throws "Rejects JSON scalar string in box.local.json" {
        Read-BoxConfig -ConfigPath $baseFile | Out-Null
    } 'must be a JSON object'

    # Finding 3: Explicit missing -LocalOverridePath must fail clearly
    $missingOv = Join-Path $tmpCfgDir 'missing.local.json'
    Assert-Throws "Rejects missing explicit -LocalOverridePath" {
        Read-BoxConfig -ConfigPath $baseFile -LocalOverridePath $missingOv | Out-Null
    } 'override file not found'

    # Finding 4: Custom -ConfigPath must not auto-discover adjacent box.local.json
    $customFile = Join-Path $tmpCfgDir 'custom.json'
    Copy-Item -LiteralPath (Join-Path $RepoRoot 'box.json') -Destination $customFile
    [System.IO.File]::WriteAllText($localFile, (@{ distroName = 'should-not-apply' } | ConvertTo-Json -Depth 3), (New-Object System.Text.UTF8Encoding($false)))
    Assert-True "Get-BoxLocalOverridePath ignores box.local.json for non-box.json ConfigPath" ($null -eq (Get-BoxLocalOverridePath -ConfigPath $customFile))
    $customCfg = Read-BoxConfig -ConfigPath $customFile
    Assert-True "Read-BoxConfig on custom.json does not merge adjacent box.local.json" ($customCfg.distroName -eq 'wsl-agent-sandbox')

    # -IgnoreLocalOverride skips adjacent box.local.json on box.json
    [System.IO.File]::WriteAllText($localFile, (@{ ide = @{ configureRemoteWsl = $true } } | ConvertTo-Json -Depth 4), (New-Object System.Text.UTF8Encoding($false)))
    $ignoredOvCfg = Read-BoxConfig -ConfigPath $baseFile -IgnoreLocalOverride
    Assert-True "Read-BoxConfig -IgnoreLocalOverride ignores adjacent box.local.json" (-not [bool]$ignoredOvCfg.ide.configureRemoteWsl)
} finally {
    if (Test-Path -LiteralPath $tmpCfgDir) {
        Remove-Item -LiteralPath $tmpCfgDir -Recurse -Force
    }
}

# Windows Terminal profile registration tests
$tmpWtDir = Join-Path ([System.IO.Path]::GetTempPath()) ("wsl-box-wt-test-" + [Guid]::NewGuid().ToString('N').Substring(0, 8))
New-Item -ItemType Directory -Path $tmpWtDir -Force | Out-Null
try {
    $wtSettings = Join-Path $tmpWtDir 'settings.json'
    $initialWt = @{
        defaultProfile = '{00000000-0000-0000-0000-000000000001}'
        profiles = @{
            list = @(
                @{ guid = '{00000000-0000-0000-0000-000000000001}'; name = 'PowerShell' }
            )
        }
    }
    [System.IO.File]::WriteAllText($wtSettings, ($initialWt | ConvertTo-Json -Depth 10), (New-Object System.Text.UTF8Encoding($false)))

    [void](Register-WindowsTerminalProfile -Config $baseCfg -SettingsPaths @($wtSettings))
    [void](Register-WindowsTerminalProfile -Config $baseCfg -SettingsPaths @($wtSettings))
    $afterAdd = Get-Content -LiteralPath $wtSettings -Raw | ConvertFrom-Json
    $expectedGuid = Get-DeterministicTerminalProfileGuid -DistroName $baseCfg.distroName
    $matching = @($afterAdd.profiles.list | Where-Object { $_.guid -eq $expectedGuid })
    Assert-True "Register-WindowsTerminalProfile is idempotent (no duplicate profiles)" ($matching.Count -eq 1 -and @($afterAdd.profiles.list).Count -eq 2)
    Assert-True "Register-WindowsTerminalProfile sets wsl.exe commandline" ($matching[0].commandline -eq "wsl.exe -d $($baseCfg.distroName) -u $($baseCfg.agentUser.name) --cd ~")
    Assert-True "Register-WindowsTerminalProfile creates timestamped backup" (@(Get-ChildItem -Path $tmpWtDir -Filter 'settings.json.bak-*').Count -ge 1)

    [void](Register-WindowsTerminalProfile -Config $baseCfg -SettingsPaths @($wtSettings) -Unregister)
    $afterRemove = Get-Content -LiteralPath $wtSettings -Raw | ConvertFrom-Json
    Assert-True "Register-WindowsTerminalProfile -Unregister removes managed profile cleanly" (@($afterRemove.profiles.list).Count -eq 1 -and $afterRemove.profiles.list[0].name -eq 'PowerShell')

    # Finding 3: No-op -Unregister must not create backup or rewrite settings.json
    $noopDir = Join-Path $tmpWtDir 'noop'
    New-Item -ItemType Directory -Path $noopDir -Force | Out-Null
    $noopSettings = Join-Path $noopDir 'settings.json'
    [System.IO.File]::WriteAllText($noopSettings, '{"profiles":{"list":[{"guid":"{00000000-0000-0000-0000-000000000001}","name":"PS"}]}}', (New-Object System.Text.UTF8Encoding($false)))
    $noopUpdated = @(Register-WindowsTerminalProfile -Config $baseCfg -SettingsPaths @($noopSettings) -Unregister)
    Assert-True "No-op -Unregister skips backup and rewrite when profile absent" ($noopUpdated.Count -eq 0 -and @(Get-ChildItem -Path $noopDir -Filter 'settings.json.bak-*').Count -eq 0)

    # Finding 1: JSONC comments (//, /* */), trailing commas, and URL strings
    $jsoncPath = Join-Path $tmpWtDir 'jsonc-settings.json'
    $jsoncText = @"
// Windows Terminal default JSONC header
{
  "`$schema": "https://aka.ms/terminal-profiles-schema", // keep // inside URL
  /* block comment */
  "profiles": {
    "list": [
      {
        "guid": "{00000000-0000-0000-0000-000000000001}",
        "name": "PowerShell",
        "commandline": "pwsh.exe /* literal */",
      },
    ],
  },
}
"@
    [System.IO.File]::WriteAllText($jsoncPath, $jsoncText, (New-Object System.Text.UTF8Encoding($false)))
    [void](Register-WindowsTerminalProfile -Config $baseCfg -SettingsPaths @($jsoncPath))
    $parsedJsonc = Get-Content -LiteralPath $jsoncPath -Raw | ConvertFrom-Json
    Assert-True "Parses JSONC comments, trailing commas, and preserves URL/block-like strings" ($parsedJsonc.'$schema' -eq 'https://aka.ms/terminal-profiles-schema' -and $parsedJsonc.profiles.list[0].commandline -eq 'pwsh.exe /* literal */' -and @($parsedJsonc.profiles.list).Count -eq 2)

    # Finding 4: Re-registering preserves user customizations on matching profile
    $customEntry = $parsedJsonc.profiles.list | Where-Object { $_.guid -eq $expectedGuid } | Select-Object -First 1
    $customEntry | Add-Member -NotePropertyName 'opacity' -NotePropertyValue 85 -Force
    $customEntry | Add-Member -NotePropertyName 'colorScheme' -NotePropertyValue 'One Half Dark' -Force
    $customEntry.tabColor = '#123456'
    [System.IO.File]::WriteAllText($jsoncPath, ($parsedJsonc | ConvertTo-Json -Depth 10), (New-Object System.Text.UTF8Encoding($false)))
    [void](Register-WindowsTerminalProfile -Config $baseCfg -SettingsPaths @($jsoncPath))
    $afterReReg = Get-Content -LiteralPath $jsoncPath -Raw | ConvertFrom-Json
    $reRegMatch = $afterReReg.profiles.list | Where-Object { $_.guid -eq $expectedGuid } | Select-Object -First 1
    Assert-True "Re-running register-terminal preserves opacity, colorScheme, and custom tabColor" ($reRegMatch.opacity -eq 85 -and $reRegMatch.colorScheme -eq 'One Half Dark' -and $reRegMatch.tabColor -eq '#123456')

    # Finding 5: Legacy array-shaped profiles
    $legacyPath = Join-Path $tmpWtDir 'legacy-settings.json'
    [System.IO.File]::WriteAllText($legacyPath, '{"profiles":[{"guid":"{11111111-1111-1111-1111-111111111111}","name":"Legacy"}]}', (New-Object System.Text.UTF8Encoding($false)))
    [void](Register-WindowsTerminalProfile -Config $baseCfg -SettingsPaths @($legacyPath))
    $afterLegacy = Get-Content -LiteralPath $legacyPath -Raw | ConvertFrom-Json
    Assert-True "Handles legacy array-shaped profiles cleanly" ($afterLegacy.profiles -is [System.Array] -and @($afterLegacy.profiles).Count -eq 2)

    # Finding 2: Portable unpackaged Windows Terminal settings path & empty LOCALAPPDATA guard
    $fakeLocalApp = Join-Path $tmpWtDir 'fake-localappdata'
    $portableDir = Join-Path $fakeLocalApp 'Microsoft\Windows Terminal'
    New-Item -ItemType Directory -Path $portableDir -Force | Out-Null
    $portableSettings = Join-Path $portableDir 'settings.json'
    [System.IO.File]::WriteAllText($portableSettings, '{}', (New-Object System.Text.UTF8Encoding($false)))
    $prevLocalApp = $env:LOCALAPPDATA
    try {
        $env:LOCALAPPDATA = $fakeLocalApp
        $discovered = @(Get-WindowsTerminalSettingsPaths)
        Assert-True "Discovers unpackaged/portable Windows Terminal settings.json" ($discovered -contains $portableSettings)
        $env:LOCALAPPDATA = ''
        $emptyDiscovered = @(Get-WindowsTerminalSettingsPaths)
        Assert-True "Handles empty LOCALAPPDATA safely" ($emptyDiscovered.Count -eq 0)
    } finally {
        $env:LOCALAPPDATA = $prevLocalApp
    }
} finally {
    if (Test-Path -LiteralPath $tmpWtDir) {
        Remove-Item -LiteralPath $tmpWtDir -Recurse -Force
    }
}

# Resource quota validation tests
$resOk = Copy-Config $baseCfg
$resOk | Add-Member -NotePropertyName 'resources' -NotePropertyValue ([pscustomobject]@{ memoryMax = '8G'; cpuQuota = '400%'; tasksMax = 512 })
Assert-BoxConfigValid -Config $resOk
Assert-True "Accepts valid systemd resources block" $true

Assert-Throws "Rejects invalid resources.memoryMax format" {
    $c = Copy-Config $baseCfg
    $c | Add-Member -NotePropertyName 'resources' -NotePropertyValue ([pscustomobject]@{ memoryMax = '8GB' })
    Assert-BoxConfigValid -Config $c
} 'Invalid resources\.memoryMax'

Assert-Throws "Rejects zero resources.memoryMax ('0')" {
    $c = Copy-Config $baseCfg
    $c | Add-Member -NotePropertyName 'resources' -NotePropertyValue ([pscustomobject]@{ memoryMax = '0' })
    Assert-BoxConfigValid -Config $c
} 'Invalid resources\.memoryMax'

Assert-Throws "Rejects zero resources.cpuQuota ('0%')" {
    $c = Copy-Config $baseCfg
    $c | Add-Member -NotePropertyName 'resources' -NotePropertyValue ([pscustomobject]@{ cpuQuota = '0%' })
    Assert-BoxConfigValid -Config $c
} 'Invalid resources\.cpuQuota'

Assert-Throws "Rejects unknown property in resources section" {
    $c = Copy-Config $baseCfg
    $c | Add-Member -NotePropertyName 'resources' -NotePropertyValue ([pscustomobject]@{ memoryLimit = '4G' })
    Assert-BoxConfigValid -Config $c
} 'Unknown property'

Assert-Throws "Rejects out-of-range resources.tasksMax" {
    $c = Copy-Config $baseCfg
    $c | Add-Member -NotePropertyName 'resources' -NotePropertyValue ([pscustomobject]@{ tasksMax = 5 })
    Assert-BoxConfigValid -Config $c
} 'must be between 32 and 65536'

# Named profile isolation tests (run in clean temp copy of box.json without box.local.json)
$tmpCleanProfRoot = Join-Path ([System.IO.Path]::GetTempPath()) ("wsl-box-cleanprof-test-" + [Guid]::NewGuid().ToString('N').Substring(0, 8))
try {
    New-Item -ItemType Directory -Path $tmpCleanProfRoot -Force | Out-Null
    Copy-Item -LiteralPath (Join-Path $RepoRoot 'box.json') -Destination (Join-Path $tmpCleanProfRoot 'box.json')
    $profWork = Resolve-BoxProfileConfig -RepoRoot $tmpCleanProfRoot -Profile 'work'
    $profOss = Resolve-BoxProfileConfig -RepoRoot $tmpCleanProfRoot -Profile 'untrusted'
    Assert-True "Profile 'work' derives unique distroName and isolated UID" ($profWork.distroName -eq 'wsl-agent-sandbox-work' -and $profWork.installDir -eq '%LOCALAPPDATA%\WSL\wsl-agent-sandbox-work' -and $profWork.agentUser.uid -ge 26100 -and $profWork.agentUser.uid -ne 26040)
    Assert-True "Distinct profiles allocate non-colliding UIDs" ($profWork.agentUser.uid -ne $profOss.agentUser.uid)
} finally {
    Remove-Item -LiteralPath $tmpCleanProfRoot -Recurse -Force -ErrorAction SilentlyContinue
}

$tmpProfRoot = Join-Path ([System.IO.Path]::GetTempPath()) ("wsl-box-prof-test-" + [Guid]::NewGuid().ToString('N').Substring(0, 8))
try {
    New-Item -ItemType Directory -Path (Join-Path $tmpProfRoot 'profiles') -Force | Out-Null
    Copy-Item -LiteralPath (Join-Path $RepoRoot 'box.json') -Destination (Join-Path $tmpProfRoot 'box.json')
    # Custom box.local.json changes default distroName, installDir, and base uid
    [System.IO.File]::WriteAllText((Join-Path $tmpProfRoot 'box.local.json'), '{"distroName":"custom-box","installDir":"D:\\Boxes\\custom-box","agentUser":{"uid":26050,"gid":26050}}', (New-Object System.Text.UTF8Encoding($false)))
    [System.IO.File]::WriteAllText((Join-Path $tmpProfRoot 'profiles\client-a.json'), '{"network":{"egressMode":"open"}}', (New-Object System.Text.UTF8Encoding($false)))
    # Duplicate entry in box.client-a.json plus invalid uppercase file
    [System.IO.File]::WriteAllText((Join-Path $tmpProfRoot 'box.client-a.json'), '{"network":{"egressMode":"open"}}', (New-Object System.Text.UTF8Encoding($false)))
    [System.IO.File]::WriteAllText((Join-Path $tmpProfRoot 'profiles\UppercaseInvalid.json'), '{}', (New-Object System.Text.UTF8Encoding($false)))
    # Override distroName without installDir -> must isolate installDir!
    [System.IO.File]::WriteAllText((Join-Path $tmpProfRoot 'profiles\client-b.json'), '{"distroName":"isolated-client-b"}', (New-Object System.Text.UTF8Encoding($false)))

    $managedNames = @(Get-ManagedBoxProfileNames -RepoRoot $tmpProfRoot)
    Assert-True "Get-ManagedBoxProfileNames deduplicates and skips uppercase filenames" (($managedNames -join ',') -eq 'client-a,client-b')

    $pA = Resolve-BoxProfileConfig -RepoRoot $tmpProfRoot -Profile 'client-a'
    Assert-True "Profile derives distroName, installDir, and UID even over custom box.local.json" (
        $pA.distroName -eq 'custom-box-client-a' -and
        $pA.installDir -eq 'D:\Boxes\custom-box-client-a' -and
        $pA.agentUser.uid -ne 26050 -and
        $pA.agentUser.uid -ge 26100
    )

    # Force a deterministic hash collision with client-a by setting base uid to Get-DeterministicProfileUid 'client-a'
    $detA = Get-DeterministicProfileUid -ProfileName 'client-a'
    [System.IO.File]::WriteAllText((Join-Path $tmpProfRoot 'box.local.json'), "{""distroName"":""custom-box"",""installDir"":""D:\\Boxes\\custom-box"",""agentUser"":{""uid"":$detA,""gid"":$detA}}", (New-Object System.Text.UTF8Encoding($false)))
    $pACollide = Resolve-BoxProfileConfig -RepoRoot $tmpProfRoot -Profile 'client-a'
    Assert-True "Auto-probing resolves hash/base UID collision deterministically" ($pACollide.agentUser.uid -ne $detA -and $pACollide.agentUser.uid -ge 26100)
    [System.IO.File]::WriteAllText((Join-Path $tmpProfRoot 'box.local.json'), '{"distroName":"custom-box","installDir":"D:\\Boxes\\custom-box","agentUser":{"uid":26050,"gid":26050}}', (New-Object System.Text.UTF8Encoding($false)))

    $pB = Resolve-BoxProfileConfig -RepoRoot $tmpProfRoot -Profile 'client-b'
    Assert-True "Profile overriding distroName without installDir derives isolated installDir" (
        $pB.distroName -eq 'isolated-client-b' -and
        $pB.installDir -eq 'D:\Boxes\isolated-client-b'
    )

    # Explicit UID collision must throw
    [System.IO.File]::WriteAllText((Join-Path $tmpProfRoot 'profiles\dup1.json'), '{"agentUser":{"uid":27001,"gid":27001}}', (New-Object System.Text.UTF8Encoding($false)))
    [System.IO.File]::WriteAllText((Join-Path $tmpProfRoot 'profiles\dup2.json'), '{"agentUser":{"uid":27001,"gid":27001}}', (New-Object System.Text.UTF8Encoding($false)))
    Assert-Throws "Rejects explicit profile UID collision" {
        Resolve-BoxProfileConfig -RepoRoot $tmpProfRoot -Profile 'dup2'
    } 'collides'
} finally {
    Remove-Item -LiteralPath $tmpProfRoot -Recurse -Force -ErrorAction SilentlyContinue
}

# Accept valid docker limits and allowedRegistries
$validLimitsCfg = Copy-Config $baseCfg
$validLimitsCfg.docker | Add-Member -NotePropertyName 'defaultLimits' -NotePropertyValue ([pscustomobject]@{ memoryBytes = [int64]536870912; nanoCpus = [int64]1000000000; pidsLimit = 128 }) -Force
$validLimitsCfg.docker | Add-Member -NotePropertyName 'maxLimits' -NotePropertyValue ([pscustomobject]@{ memoryBytes = [int64]1073741824; nanoCpus = [int64]2000000000; pidsLimit = 256 }) -Force
$validLimitsCfg.docker | Add-Member -NotePropertyName 'allowedRegistries' -NotePropertyValue @('docker.io', 'ghcr.io', 'localhost:5000') -Force
Assert-BoxConfigValid -Config $validLimitsCfg
Assert-True "Accepts valid docker defaultLimits, maxLimits, and allowedRegistries" $true

# Reject docker limit below schema minimum
Assert-Throws "Rejects docker.defaultLimits.memoryBytes below 4MiB schema minimum" {
    $c = Copy-Config $baseCfg
    $c.docker | Add-Member -NotePropertyName 'defaultLimits' -NotePropertyValue ([pscustomobject]@{ memoryBytes = 1024 }) -Force
    Assert-BoxConfigValid -Config $c
} 'must be >='

# Reject defaultLimits > maxLimits
Assert-Throws "Rejects docker.defaultLimits exceeding docker.maxLimits" {
    $c = Copy-Config $baseCfg
    $c.docker | Add-Member -NotePropertyName 'defaultLimits' -NotePropertyValue ([pscustomobject]@{ memoryBytes = [int64]2147483648 }) -Force
    $c.docker | Add-Member -NotePropertyName 'maxLimits' -NotePropertyValue ([pscustomobject]@{ memoryBytes = [int64]1073741824 }) -Force
    Assert-BoxConfigValid -Config $c
} 'exceeds docker.maxLimits'

# Reject malformed docker.allowedRegistries entry
Assert-Throws "Rejects invalid URL/slash in docker.allowedRegistries" {
    $c = Copy-Config $baseCfg
    $c.docker | Add-Member -NotePropertyName 'allowedRegistries' -NotePropertyValue @('https://ghcr.io/org') -Force
    Assert-BoxConfigValid -Config $c
} 'Invalid docker.allowedRegistries'

# Sync-IdeWslScriptlessStartup tests (JSONC support, preservation, idempotency)
$tmpIdeDir = Join-Path ([System.IO.Path]::GetTempPath()) ("wsl-box-ide-test-" + [Guid]::NewGuid().ToString('N').Substring(0, 8))
New-Item -ItemType Directory -Path $tmpIdeDir -Force | Out-Null
try {
    $ideSettings = Join-Path $tmpIdeDir 'settings.json'
    $jsoncMissing = @"
// user settings
{
  /* block comment */
  "editor.fontSize": 14,
  "http.proxy": "https://proxy.example.com:8080", // inline URL comment
}
"@
    [System.IO.File]::WriteAllText($ideSettings, $jsoncMissing, (New-Object System.Text.UTF8Encoding($false)))
    $updated1 = @(Sync-IdeWslScriptlessStartup -SettingsPaths @($ideSettings))
    $written1 = Get-Content -LiteralPath $ideSettings -Raw -Encoding UTF8
    $parsedIde = ConvertFrom-Jsonc -Text $written1
    Assert-True "Sync-IdeWslScriptlessStartup sets remote.WSL.experimental.scriptLessStartup=true and preserves existing settings and comments" (
        $updated1.Count -eq 1 -and
        $parsedIde.'remote.WSL.experimental.scriptLessStartup' -eq $true -and
        $parsedIde.'editor.fontSize' -eq 14 -and
        $parsedIde.'http.proxy' -eq 'https://proxy.example.com:8080' -and
        $written1.Contains('// user settings') -and
        $written1.Contains('/* block comment */') -and
        $written1.Contains('// inline URL comment')
    )
    $updated2 = @(Sync-IdeWslScriptlessStartup -SettingsPaths @($ideSettings))
    Assert-True "Sync-IdeWslScriptlessStartup is idempotent when already enabled" ($updated2.Count -eq 0)

    # Test updating an existing false value while preserving comments
    $ideSettingsFalse = Join-Path $tmpIdeDir 'settings-false.json'
    $jsoncFalse = @"
// top comment
{
  /* keep block */
  "remote.WSL.experimental.scriptLessStartup": false, // disabled by user
  "editor.tabSize": 2
}
"@
    [System.IO.File]::WriteAllText($ideSettingsFalse, $jsoncFalse, (New-Object System.Text.UTF8Encoding($false)))
    $updated3 = @(Sync-IdeWslScriptlessStartup -SettingsPaths @($ideSettingsFalse))
    $written3 = Get-Content -LiteralPath $ideSettingsFalse -Raw -Encoding UTF8
    $parsedIde3 = ConvertFrom-Jsonc -Text $written3
    Assert-True "Sync-IdeWslScriptlessStartup updates existing false value in-place and preserves comments" (
        $updated3.Count -eq 1 -and
        $parsedIde3.'remote.WSL.experimental.scriptLessStartup' -eq $true -and
        $parsedIde3.'editor.tabSize' -eq 2 -and
        $written3.Contains('// top comment') -and
        $written3.Contains('/* keep block */') -and
        $written3.Contains('// disabled by user')
    )

    # Test global Scoop config resolution (AppRoot without .git + StateRoot with box.local.json only)
    $tmpScoopApp = Join-Path $tmpIdeDir 'scoop-app'
    $tmpScoopState = Join-Path $tmpIdeDir 'scoop-state'
    New-Item -ItemType Directory -Path $tmpScoopApp -Force | Out-Null
    New-Item -ItemType Directory -Path $tmpScoopState -Force | Out-Null
    Copy-Item -LiteralPath (Join-Path $RepoRoot 'box.json') -Destination (Join-Path $tmpScoopApp 'box.json') -Force
    [System.IO.File]::WriteAllText(
        (Join-Path $tmpScoopState 'box.local.json'),
        '{"distroName": "scoop-custom-sandbox", "agentUser": {"uid": 26555, "gid": 26555}}',
        (New-Object System.Text.UTF8Encoding($false))
    )
    $scoopCfg = Resolve-BoxProfileConfig -RepoRoot $tmpScoopState -ExplicitConfigPath (Join-Path $tmpScoopApp 'box.json') -LocalOverrideSearchDir $tmpScoopState
    Assert-True "Global Scoop resolution merges StateRoot box.local.json over AppRoot box.json" (
        $scoopCfg.distroName -eq 'scoop-custom-sandbox' -and
        [int]$scoopCfg.agentUser.uid -eq 26555
    )

    Assert-True "Default box.json leaves ide.configureRemoteWsl disabled (opt-in)" (-not (Test-ShouldConfigureIdeRemoteWsl -Config $baseCfg))
    $ideOptInCfg = Copy-Config $baseCfg
    $ideOptInCfg | Add-Member -NotePropertyName 'ide' -NotePropertyValue ([pscustomobject]@{ configureRemoteWsl = $true }) -Force
    Assert-BoxConfigValid -Config $ideOptInCfg
    Assert-True "Test-ShouldConfigureIdeRemoteWsl returns true when ide.configureRemoteWsl is enabled" (Test-ShouldConfigureIdeRemoteWsl -Config $ideOptInCfg)

    Assert-Throws "Rejects non-boolean ide.configureRemoteWsl" {
        $badIdeCfg = Copy-Config $baseCfg
        $badIdeCfg | Add-Member -NotePropertyName 'ide' -NotePropertyValue ([pscustomobject]@{ configureRemoteWsl = 'yes' }) -Force
        Assert-BoxConfigValid -Config $badIdeCfg
    } 'must be a boolean'
} finally {
    if (Test-Path -LiteralPath $tmpIdeDir) {
        Remove-Item -LiteralPath $tmpIdeDir -Recurse -Force
    }
}

# Docker security advisories (host.docker.internal & BuildKit)
$defaultAdvisories = @(Get-DockerSecurityAdvisories -Config $baseCfg)
Assert-True "Default box.json emits host.docker.internal and BuildKit advisories when forceInternalNetwork is unset/false" (
    $defaultAdvisories.Count -eq 2 -and
    ($defaultAdvisories[0] -match 'host\.docker\.internal') -and
    ($defaultAdvisories[1] -match 'BuildKit')
)

$hardenedDockerCfg = Copy-Config $baseCfg
$hardenedDockerCfg.docker | Add-Member -NotePropertyName 'forceInternalNetwork' -NotePropertyValue $true -Force
$hardenedAdvisories = @(Get-DockerSecurityAdvisories -Config $hardenedDockerCfg)
Assert-True "No Docker host/BuildKit advisories when forceInternalNetwork is true" ($hardenedAdvisories.Count -eq 0)

$disabledDockerCfg = Copy-Config $baseCfg
$disabledDockerCfg.docker.enabled = $false
Assert-True "No Docker advisories when docker.enabled is false" (@(Get-DockerSecurityAdvisories -Config $disabledDockerCfg).Count -eq 0)

# Strict unknown-property rejection across all config sections
Assert-Throws "Rejects unknown property at box.json root" {
    $c = Copy-Config $baseCfg
    $c | Add-Member -NotePropertyName 'unknownRootProp' -NotePropertyValue $true -Force
    Assert-BoxConfigValid -Config $c
} 'Unknown property'

Assert-Throws "Rejects unknown property in agentUser" {
    $c = Copy-Config $baseCfg
    $c.agentUser | Add-Member -NotePropertyName 'shell' -NotePropertyValue '/bin/bash' -Force
    Assert-BoxConfigValid -Config $c
} 'Unknown property'

Assert-Throws "Rejects unknown property in image" {
    $c = Copy-Config $baseCfg
    $c.image | Add-Member -NotePropertyName 'distroTag' -NotePropertyValue 'latest' -Force
    Assert-BoxConfigValid -Config $c
} 'Unknown property'

Assert-Throws "Rejects unknown property in sharedFolders[*]" {
    $c = Copy-Config $baseCfg
    $c.sharedFolders = @([pscustomobject]@{ name = 'docs'; windowsPath = 'C:\Users\demo\docs'; mode = 'ro'; extraKey = 'x' })
    Assert-BoxConfigValid -Config $c
} 'Unknown property'

Assert-Throws "Rejects unknown property in network" {
    $c = Copy-Config $baseCfg
    $c.network | Add-Member -NotePropertyName 'allowLan' -NotePropertyValue $false -Force
    Assert-BoxConfigValid -Config $c
} 'Unknown property'

Assert-Throws "Rejects unknown property in network.allowedHostPorts[*]" {
    $c = Copy-Config $baseCfg
    $c.network.allowedHostPorts = @([pscustomobject]@{ port = 8080; protocol = 'tcp'; note = 'typo' })
    Assert-BoxConfigValid -Config $c
} 'Unknown property'

Assert-Throws "Rejects unknown property in docker" {
    $c = Copy-Config $baseCfg
    $c.docker | Add-Member -NotePropertyName 'allowPrivileged' -NotePropertyValue $true -Force
    Assert-BoxConfigValid -Config $c
} 'Unknown property'

Assert-Throws "Rejects unknown property in packages" {
    $c = Copy-Config $baseCfg
    $c.packages | Add-Member -NotePropertyName 'installDocker' -NotePropertyValue $true -Force
    Assert-BoxConfigValid -Config $c
} 'Unknown property'

# Package install* boolean type validation & dotnetChannels validation
Assert-Throws "Rejects non-boolean string packages.installDockerCli = 'false'" {
    $c = Copy-Config $baseCfg
    $c.packages.installDockerCli = 'false'
    Assert-BoxConfigValid -Config $c
} 'must be a boolean'

Assert-Throws "Rejects 1-element array @(`$true) on packages.installDockerCli" {
    $c = Copy-Config $baseCfg
    $c.packages.installDockerCli = @($true)
    Assert-BoxConfigValid -Config $c
} 'must be a boolean'

Assert-Throws "Rejects JSON [true] on packages.installDockerCli" {
    $raw = Get-Content -LiteralPath (Join-Path $RepoRoot 'box.json') -Raw -Encoding UTF8
    $c = $raw | ConvertFrom-Json
    $c.packages.installDockerCli = @($true)
    $c = ($c | ConvertTo-Json -Depth 10 | ConvertFrom-Json)
    Assert-BoxConfigValid -Config $c
} 'must be a boolean'

# Case-sensitive property matching (parity with box.schema.json)
Assert-Throws "Rejects wrong-case root property DistroName" {
    $c = Copy-Config $baseCfg
    $c | Add-Member -NotePropertyName 'DistroName' -NotePropertyValue 'dupe' -Force
    Assert-BoxConfigValid -Config $c
} 'Unknown property'

Assert-Throws "Rejects wrong-case docker.defaultLimits property MemoryBytes" {
    $c = Copy-Config $baseCfg
    $c.docker | Add-Member -NotePropertyName 'defaultLimits' -NotePropertyValue ([pscustomobject]@{ MemoryBytes = 4194304 }) -Force
    Assert-BoxConfigValid -Config $c
} 'Unknown property'

Assert-Throws "Rejects wrong-case secrets property ManifestPath" {
    $c = Copy-Config $baseCfg
    $c | Add-Member -NotePropertyName 'secrets' -NotePropertyValue ([pscustomobject]@{ ManifestPath = 'C:\secrets.json' }) -Force
    Assert-BoxConfigValid -Config $c
} 'only allows non-secret pointer property'

# Non-packages boolean field validation (string 'false' and 1-element array @($true))
Assert-Throws "Rejects string 'false' on network.blockHostAndLan" {
    $c = Copy-Config $baseCfg
    $c.network.blockHostAndLan = 'false'
    Assert-BoxConfigValid -Config $c
} 'network\.blockHostAndLan must be a boolean'

Assert-Throws "Rejects 1-element array @(`$true) on network.blockHostAndLan" {
    $c = Copy-Config $baseCfg
    $c.network.blockHostAndLan = @($true)
    Assert-BoxConfigValid -Config $c
} 'network\.blockHostAndLan must be a boolean'

Assert-Throws "Rejects string 'false' on docker.enabled" {
    $c = Copy-Config $baseCfg
    $c.docker.enabled = 'false'
    Assert-BoxConfigValid -Config $c
} 'docker\.enabled must be a boolean'

Assert-Throws "Rejects 1-element array @(`$true) on docker.enabled" {
    $c = Copy-Config $baseCfg
    $c.docker.enabled = @($true)
    Assert-BoxConfigValid -Config $c
} 'docker\.enabled must be a boolean'

Assert-Throws "Rejects string 'false' on sharedFolders[0].allowDockerBind" {
    $c = Copy-Config $baseCfg
    $c.sharedFolders = @([pscustomobject]@{ name = 'docs'; windowsPath = 'C:\Users\demo\docs'; mode = 'ro'; allowDockerBind = 'false' })
    Assert-BoxConfigValid -Config $c
} 'allowDockerBind must be a boolean'

Assert-Throws "Rejects string 'false' on docker.forceInternalNetwork" {
    $c = Copy-Config $baseCfg
    $c.docker | Add-Member -NotePropertyName 'forceInternalNetwork' -NotePropertyValue 'false' -Force
    Assert-BoxConfigValid -Config $c
} 'docker\.forceInternalNetwork must be a boolean'

$dotnetOkCfg = Copy-Config $baseCfg
$dotnetOkCfg.packages | Add-Member -NotePropertyName 'dotnetChannels' -NotePropertyValue @('8.0', '9.0') -Force
Assert-BoxConfigValid -Config $dotnetOkCfg
Assert-True "Accepts valid packages.dotnetChannels array ['8.0', '9.0']" $true

$dotnetSingleJsonCfg = Copy-Config $baseCfg
$dotnetSingleJsonCfg.packages | Add-Member -NotePropertyName 'dotnetChannels' -NotePropertyValue ([string[]]@('8.0')) -Force
$dotnetSingleJsonCfg = ($dotnetSingleJsonCfg | ConvertTo-Json -Depth 10 | ConvertFrom-Json)
Assert-BoxConfigValid -Config $dotnetSingleJsonCfg
Assert-True "Accepts single-element JSON packages.dotnetChannels array ['8.0']" $true

$dotnetEmptyCfg = Copy-Config $baseCfg
$dotnetEmptyCfg.packages | Add-Member -NotePropertyName 'dotnetChannels' -NotePropertyValue @() -Force
Assert-BoxConfigValid -Config $dotnetEmptyCfg
Assert-True "Accepts empty packages.dotnetChannels array []" $true

Assert-Throws "Rejects scalar string packages.dotnetChannels = '8.0'" {
    $c = Copy-Config $baseCfg
    $c.packages | Add-Member -NotePropertyName 'dotnetChannels' -NotePropertyValue '8.0' -Force
    Assert-BoxConfigValid -Config $c
} 'must be an array'

Assert-Throws "Rejects dictionary packages.dotnetChannels" {
    $c = Copy-Config $baseCfg
    $c.packages | Add-Member -NotePropertyName 'dotnetChannels' -NotePropertyValue @{ channel = '8.0' } -Force
    Assert-BoxConfigValid -Config $c
} 'must be an array'

Assert-Throws "Rejects invalid major-only packages.dotnetChannels entry '8'" {
    $c = Copy-Config $baseCfg
    $c.packages | Add-Member -NotePropertyName 'dotnetChannels' -NotePropertyValue ([string[]]@('8')) -Force
    Assert-BoxConfigValid -Config $c
} 'Invalid packages\.dotnetChannels'

Assert-Throws "Rejects non-numeric packages.dotnetChannels entry 'LTS'" {
    $c = Copy-Config $baseCfg
    $c.packages | Add-Member -NotePropertyName 'dotnetChannels' -NotePropertyValue ([string[]]@('LTS')) -Force
    Assert-BoxConfigValid -Config $c
} 'Invalid packages\.dotnetChannels'

Assert-Throws "Rejects numeric float packages.dotnetChannels entry 8.0" {
    $c = Copy-Config $baseCfg
    $c.packages | Add-Member -NotePropertyName 'dotnetChannels' -NotePropertyValue ([double[]]@(8.0)) -Force
    Assert-BoxConfigValid -Config $c
} 'Invalid packages\.dotnetChannels'

Assert-Throws "Rejects duplicate packages.dotnetChannels entries" {
    $c = Copy-Config $baseCfg
    $c.packages | Add-Member -NotePropertyName 'dotnetChannels' -NotePropertyValue @('8.0', '8.0') -Force
    Assert-BoxConfigValid -Config $c
} 'Duplicate packages\.dotnetChannels'

# Validate all examples/presets/*.local.json merged over box.json
$presetFiles = @(Get-ChildItem -Path (Join-Path $RepoRoot 'examples\presets') -Filter '*.local.json' -File | Sort-Object Name)
Assert-True "Discovers at least one preset under examples/presets/*.local.json" ($presetFiles.Count -gt 0)
foreach ($presetFile in $presetFiles) {
    $mergedPreset = Read-BoxConfig -ConfigPath (Join-Path $RepoRoot 'box.json') -LocalOverridePath $presetFile.FullName -IgnoreLocalOverride
    Assert-True "Preset $($presetFile.Name) merges over box.json and validates cleanly" ($null -ne $mergedPreset -and $mergedPreset.distroName -eq 'wsl-agent-sandbox')
}

# Validate direct [hashtable] (IDictionary) inputs to Assert-BoxConfigValid (no PSObject.Properties bypass or 1-element unrolling)
function Get-ValidHashtableConfig {
    return @{
        distroName    = 'wsl-agent-sandbox'
        installDir    = '%LOCALAPPDATA%\WSL\wsl-agent-sandbox'
        agentUser     = @{ name = 'agent'; uid = 26040; gid = 26040 }
        image         = @{ release = '26.04'; arch = 'amd64'; cacheDir = '%LOCALAPPDATA%\WSL\cache' }
        sharedFolders = @()
        network       = @{
            blockHostAndLan  = $true
            allowedHostPorts = @()
            blockedCidrs     = @('10.0.0.0/8')
            logDrops         = $true
            egressMode       = 'allowlist'
            allowedDomains   = @('api.github.com')
        }
        docker        = @{
            enabled               = $true
            allowBindPrefixes     = @('/home/agent')
            allowBuildKit         = $true
            allowCapAdd           = @()
            allowedPublishedPorts = @(8080)
            forceInternalNetwork  = $false
            defaultLimits         = @{ memoryBytes = [int64]536870912; nanoCpus = [int64]1000000000; pidsLimit = 128 }
            maxLimits             = @{ memoryBytes = [int64]1073741824; nanoCpus = [int64]2000000000; pidsLimit = 256 }
            allowedRegistries     = @('ghcr.io')
        }
        packages      = @{
            apt                      = @('jq')
            installDockerCli         = $true
            dotnetChannels           = @('8.0')
            configureVsCodeRemoteWsl = $false
        }
        secrets       = @{ manifestPath = '%USERPROFILE%\.wsl-agent-sandbox\secrets.json' }
        resources     = @{ memoryMax = '8G'; cpuQuota = '400%'; tasksMax = 512 }
        ide           = @{ configureRemoteWsl = $true }
    }
}

$validHashtableCfg = Get-ValidHashtableConfig
Assert-BoxConfigValid -Config $validHashtableCfg
Assert-True "Accepts valid full [hashtable] config with 1-element arrays" $true
Assert-True "Get-DockerSecurityAdvisories handles [hashtable] config" (@(Get-DockerSecurityAdvisories -Config $validHashtableCfg).Count -eq 1)

Assert-Throws "Rejects [hashtable] network.egressMode = 'bogus'" {
    $h = Get-ValidHashtableConfig
    $h.network.egressMode = 'bogus'
    Assert-BoxConfigValid -Config $h
} 'egressMode'

Assert-Throws "Rejects [hashtable] network.allowedDomains whitespace entry" {
    $h = Get-ValidHashtableConfig
    $h.network.allowedDomains = @('bad domain')
    Assert-BoxConfigValid -Config $h
} 'allowedDomains'

Assert-Throws "Rejects [hashtable] docker.allowedPublishedPorts out of range" {
    $h = Get-ValidHashtableConfig
    $h.docker.allowedPublishedPorts = @(70000)
    Assert-BoxConfigValid -Config $h
} 'allowedPublishedPorts'

Assert-Throws "Rejects [hashtable] docker.defaultLimits.MemoryBytes wrong case" {
    $h = Get-ValidHashtableConfig
    $h.docker.defaultLimits = @{ MemoryBytes = [int64]4194304 }
    Assert-BoxConfigValid -Config $h
} 'Unknown property'

Assert-Throws "Rejects [hashtable] docker.defaultLimits.memoryBytes below minimum" {
    $h = Get-ValidHashtableConfig
    $h.docker.defaultLimits = @{ memoryBytes = 100 }
    Assert-BoxConfigValid -Config $h
} 'must be >='

Assert-Throws "Rejects [hashtable] docker.defaultLimits exceeding maxLimits" {
    $h = Get-ValidHashtableConfig
    $h.docker.defaultLimits = @{ memoryBytes = [int64]16777216 }
    $h.docker.maxLimits = @{ memoryBytes = [int64]8388608 }
    Assert-BoxConfigValid -Config $h
} 'exceeds docker\.maxLimits'

Assert-Throws "Rejects [hashtable] docker.allowedRegistries URL" {
    $h = Get-ValidHashtableConfig
    $h.docker.allowedRegistries = @('https://evil.com/x')
    Assert-BoxConfigValid -Config $h
} 'Invalid docker\.allowedRegistries'

Assert-Throws "Rejects [hashtable] secrets.ManifestPath wrong case" {
    $h = Get-ValidHashtableConfig
    $h.secrets = @{ ManifestPath = 'C:\secrets.json' }
    Assert-BoxConfigValid -Config $h
} 'only allows non-secret pointer property'

Assert-Throws "Rejects [hashtable] secrets.rawToken unknown key" {
    $h = Get-ValidHashtableConfig
    $h.secrets = @{ rawToken = 'abc' }
    Assert-BoxConfigValid -Config $h
} 'only allows non-secret pointer property'

Assert-Throws "Rejects [hashtable] resources.MemoryMax wrong case" {
    $h = Get-ValidHashtableConfig
    $h.resources = @{ MemoryMax = '8G' }
    Assert-BoxConfigValid -Config $h
} 'Unknown property'

Assert-Throws "Rejects [hashtable] resources.memoryMax invalid format" {
    $h = Get-ValidHashtableConfig
    $h.resources = @{ memoryMax = 'bad' }
    Assert-BoxConfigValid -Config $h
} 'Invalid resources\.memoryMax'

Assert-Throws "Rejects [hashtable] resources.cpuQuota invalid format" {
    $h = Get-ValidHashtableConfig
    $h.resources = @{ cpuQuota = 'bad' }
    Assert-BoxConfigValid -Config $h
} 'Invalid resources\.cpuQuota'

Assert-Throws "Rejects [hashtable] resources.tasksMax out of range" {
    $h = Get-ValidHashtableConfig
    $h.resources = @{ tasksMax = 5 }
    Assert-BoxConfigValid -Config $h
} 'between 32 and 65536'

Assert-Throws "Rejects [hashtable] ide.ConfigureRemoteWsl wrong case" {
    $h = Get-ValidHashtableConfig
    $h.ide = @{ ConfigureRemoteWsl = $true }
    Assert-BoxConfigValid -Config $h
} 'Unknown property'

Assert-Throws "Rejects [hashtable] ide.configureRemoteWsl non-boolean" {
    $h = Get-ValidHashtableConfig
    $h.ide = @{ configureRemoteWsl = 'false' }
    Assert-BoxConfigValid -Config $h
} 'ide\.configureRemoteWsl must be a boolean'

Assert-Throws "Rejects [hashtable] packages.installDockerCli 1-element array @(`$true)" {
    $h = Get-ValidHashtableConfig
    $h.packages.installDockerCli = @($true)
    Assert-BoxConfigValid -Config $h
} 'packages\.installDockerCli must be a boolean'

# Deterministic per-UID proxy port allocation
$defaultPorts = Get-DeterministicProxyPorts -Uid 26040
Assert-True "Default UID 26040 resolves proxy ports 3128/3129" ($defaultPorts.EgressPort -eq 3128 -and $defaultPorts.CredentialPort -eq 3129)

$seenProxyPorts = @{}
$seenProxyPorts[3128] = $true
$seenProxyPorts[3129] = $true
$allProfilePortsUnique = $true
$allProfilePortsBelowEphemeral = $true
foreach ($u in 26100..26998) {
    $pp = Get-DeterministicProxyPorts -Uid $u
    if ($pp.EgressPort -ge 32768 -or $pp.CredentialPort -ge 32768 -or $pp.EgressPort -lt 1024) {
        $allProfilePortsBelowEphemeral = $false
        break
    }
    if ($seenProxyPorts.ContainsKey($pp.EgressPort) -or $seenProxyPorts.ContainsKey($pp.CredentialPort) -or $pp.EgressPort -eq $pp.CredentialPort) {
        $allProfilePortsUnique = $false
        break
    }
    $seenProxyPorts[$pp.EgressPort] = $true
    $seenProxyPorts[$pp.CredentialPort] = $true
}
Assert-True "All profile UIDs 26100..26998 resolve unique non-colliding proxy ports" $allProfilePortsUnique
Assert-True "All profile UIDs 26100..26998 resolve proxy ports < 32768" $allProfilePortsBelowEphemeral

$customPorts = Get-DeterministicProxyPorts -Uid 15001
Assert-True "Custom UID 15001 resolves valid proxy port pair in 29100..29999 (< 32768)" ($customPorts.EgressPort -ge 29100 -and $customPorts.CredentialPort -eq ($customPorts.EgressPort + 1) -and $customPorts.CredentialPort -le 29999)

$commonDevPorts = @(3000, 3306, 5432, 6379, 8080, 9200, 11434, 15672, 16686, 18080, 19092, 26257, 27017, 28015, 30000)
$devPortsUnblocked = $true
foreach ($dp in $commonDevPorts) {
    if ($dp -in @(3128, 3129) -or ($dp -ge 29100 -and $dp -le 29999) -or ($dp -ge 30900 -and $dp -le 32697)) {
        $devPortsUnblocked = $false
        break
    }
}
Assert-True "Reserved proxy port ranges leave common localhost DB/broker/NodePort ports unblocked" $devPortsUnblocked

Write-Host ""
Write-Host "=== Config.Tests.ps1 Summary: PASS=$script:Passed FAIL=$script:Failed ==="
if ($script:Failed -gt 0) {
    exit 1
}
exit 0
