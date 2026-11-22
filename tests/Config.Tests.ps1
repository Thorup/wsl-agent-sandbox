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

# Named profile isolation tests
$profWork = Resolve-BoxProfileConfig -RepoRoot $RepoRoot -Profile 'work'
$profOss = Resolve-BoxProfileConfig -RepoRoot $RepoRoot -Profile 'untrusted'
Assert-True "Profile 'work' derives unique distroName and isolated UID" ($profWork.distroName -eq 'wsl-agent-sandbox-work' -and $profWork.installDir -eq '%LOCALAPPDATA%\WSL\wsl-agent-sandbox-work' -and $profWork.agentUser.uid -ge 26100 -and $profWork.agentUser.uid -ne 26040)
Assert-True "Distinct profiles allocate non-colliding UIDs" ($profWork.agentUser.uid -ne $profOss.agentUser.uid)

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

Write-Host ""
Write-Host "=== Config.Tests.ps1 Summary: PASS=$script:Passed FAIL=$script:Failed ==="
if ($script:Failed -gt 0) {
    exit 1
}
exit 0
