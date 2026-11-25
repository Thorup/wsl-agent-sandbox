#Requires -Version 5.1
Set-StrictMode -Version Latest

function Expand-BoxPath {
    param([Parameter(Mandatory)][string]$RawPath, [string]$BaseDir)
    $expanded = [Environment]::ExpandEnvironmentVariables($RawPath)
    if (-not [System.IO.Path]::IsPathRooted($expanded) -and $BaseDir) {
        return [System.IO.Path]::GetFullPath((Join-Path $BaseDir $expanded))
    }
    return [System.IO.Path]::GetFullPath($expanded)
}

function Get-BoxLocalOverridePath {
    param(
        [Parameter(Mandatory)][string]$ConfigPath,
        [string]$SearchDir = ''
    )
    $leaf = Split-Path -Leaf $ConfigPath
    if ($leaf -ne 'box.json') {
        return $null
    }
    $dir = if (-not [string]::IsNullOrWhiteSpace($SearchDir)) {
        $SearchDir
    } else {
        Split-Path -Parent $ConfigPath
    }
    if ([string]::IsNullOrWhiteSpace($dir)) {
        $dir = '.'
    }
    $candidate = Join-Path $dir 'box.local.json'
    if (Test-Path -LiteralPath $candidate -PathType Leaf) {
        return $candidate
    }
    return $null
}

function Get-DeterministicProfileUid {
    param([Parameter(Mandatory)][string]$ProfileName)
    $sha = [System.Security.Cryptography.SHA256]::Create()
    try {
        $bytes = [System.Text.Encoding]::UTF8.GetBytes("wsl-agent-sandbox-profile:$ProfileName")
        $hash = $sha.ComputeHash($bytes)
        $val = [BitConverter]::ToUInt16($hash, 0)
        return 26100 + ($val % 899)
    } finally {
        $sha.Dispose()
    }
}

function Get-DeterministicProxyPorts {
    <#
    .SYNOPSIS
    Derives deterministic, non-colliding localhost proxy ports from agentUser.uid.
    All non-default ports stay strictly below 32768 (Linux default ephemeral range).
    #>
    param([Parameter(Mandatory)][int]$Uid)
    if ($Uid -eq 26040) {
        return [pscustomobject]@{
            EgressPort     = 3128
            CredentialPort = 3129
        }
    }
    if ($Uid -ge 26100 -and $Uid -le 26998) {
        $egress = 13000 + (($Uid - 26100) * 2)
    } else {
        $egress = 15000 + ((($Uid * 31) % 8000) * 2)
    }
    return [pscustomobject]@{
        EgressPort     = $egress
        CredentialPort = $egress + 1
    }
}

function Get-ProfileOverridePath {
    param(
        [Parameter(Mandatory)][string]$RepoRoot,
        [Parameter(Mandatory)][Alias('Profile')][string]$ProfileName
    )
    $candidates = @(
        (Join-Path $RepoRoot "profiles\$ProfileName.json"),
        (Join-Path $RepoRoot "box.$ProfileName.json")
    )
    return ($candidates | Where-Object { Test-Path -LiteralPath $_ -PathType Leaf } | Select-Object -First 1)
}

function Get-ManagedBoxProfileNames {
    param(
        [Parameter(Mandatory)][string]$RepoRoot,
        [switch]$WarnOnInvalid
    )
    $rawFiles = New-Object System.Collections.Generic.List[System.IO.FileInfo]
    $profDir = Join-Path $RepoRoot 'profiles'
    if (Test-Path -LiteralPath $profDir -PathType Container) {
        foreach ($f in (Get-ChildItem -Path $profDir -Filter '*.json' -File | Sort-Object Name)) {
            $rawFiles.Add($f)
        }
    }
    foreach ($f in (Get-ChildItem -Path $RepoRoot -Filter 'box.*.json' -File | Where-Object { $_.Name -notin @('box.schema.json', 'box.local.json') } | Sort-Object Name)) {
        $rawFiles.Add($f)
    }

    $seen = @{}
    $names = New-Object System.Collections.Generic.List[string]
    foreach ($f in $rawFiles) {
        $pName = $f.Name -replace '^box\.|\.json$', ''
        if ($pName -cnotmatch '^[a-z0-9][a-z0-9_-]{0,24}$') {
            if ($WarnOnInvalid) {
                Write-Warning "Skipping invalid profile file '$($f.FullName)': profile name '$pName' must match ^[a-z0-9][a-z0-9_-]{0,24}$ (lowercase)."
            }
            continue
        }
        if (-not $seen.ContainsKey($pName)) {
            $seen[$pName] = $true
            $names.Add($pName)
        }
    }
    return @($names | Sort-Object)
}

function Get-DerivedProfileInstallDir {
    param(
        [string]$BaseInstallDir,
        [Parameter(Mandatory)][string]$DistroName
    )
    if (-not [string]::IsNullOrWhiteSpace($BaseInstallDir) -and $BaseInstallDir -match '^(.*)[\\/][^\\/]+$') {
        return "$($Matches[1])\$DistroName"
    }
    return "%LOCALAPPDATA%\WSL\$DistroName"
}

function Get-ResolvedProfileUidMap {
    param(
        [Parameter(Mandatory)][string]$RepoRoot,
        [Parameter(Mandatory)][int]$BaseUid,
        [string]$IncludeProfile = ''
    )
    $usedUids = @{}
    $usedUids[$BaseUid] = 'default'
    $uidMap = @{}
    $autoProfiles = New-Object System.Collections.Generic.List[string]

    $allProfiles = New-Object System.Collections.Generic.List[string]
    foreach ($p in (Get-ManagedBoxProfileNames -RepoRoot $RepoRoot)) {
        if (-not $allProfiles.Contains($p)) { $allProfiles.Add($p) }
    }
    if (-not [string]::IsNullOrWhiteSpace($IncludeProfile) -and -not $allProfiles.Contains($IncludeProfile)) {
        $allProfiles.Add($IncludeProfile)
    }

    foreach ($p in ($allProfiles | Sort-Object)) {
        $pPath = Get-ProfileOverridePath -RepoRoot $RepoRoot -Profile $p
        $hasExplicitUid = $false
        if ($pPath) {
            $pObj = (Get-Content -LiteralPath $pPath -Raw -Encoding UTF8) | ConvertFrom-Json
            $pAgentUser = $null
            $pUid = $null
            if ((Read-BoxObjectProperty -Object $pObj -Name 'agentUser' -Value ([ref]$pAgentUser)) -and $null -ne $pAgentUser -and
                (Read-BoxObjectProperty -Object $pAgentUser -Name 'uid' -Value ([ref]$pUid)) -and $null -ne $pUid) {
                $hasExplicitUid = $true
                $explicitUid = [int]$pUid
                if ($usedUids.ContainsKey($explicitUid)) {
                    throw "Profile '$p' agentUser.uid ($explicitUid) collides with profile '$($usedUids[$explicitUid])'."
                }
                $usedUids[$explicitUid] = $p
                $uidMap[$p] = $explicitUid
            }
        }
        if (-not $hasExplicitUid) {
            $autoProfiles.Add($p)
        }
    }

    foreach ($p in ($autoProfiles | Sort-Object)) {
        $candidate = Get-DeterministicProfileUid -ProfileName $p
        $attempts = 0
        while ($usedUids.ContainsKey($candidate)) {
            $attempts++
            if ($attempts -ge 899) {
                throw "Exhausted available automatic profile UIDs in range 26100..26998."
            }
            $candidate = 26100 + ((($candidate - 26100) + 1) % 899)
        }
        $usedUids[$candidate] = $p
        $uidMap[$p] = $candidate
    }

    return $uidMap
}

function Resolve-BoxProfileConfig {
    param(
        [Parameter(Mandatory)][string]$RepoRoot,
        [Alias('Profile')][string]$ProfileName = '',
        [string]$ExplicitConfigPath = '',
        [string]$LocalOverrideSearchDir = ''
    )
    $basePath = if (-not [string]::IsNullOrWhiteSpace($ExplicitConfigPath)) {
        $ExplicitConfigPath
    } else {
        Join-Path $RepoRoot 'box.json'
    }
    $baseCfg = Read-BoxConfig -ConfigPath $basePath -LocalOverrideSearchDir $LocalOverrideSearchDir
    $cfg = Read-BoxConfig -ConfigPath $basePath -LocalOverrideSearchDir $LocalOverrideSearchDir

    if (-not [string]::IsNullOrWhiteSpace($ProfileName)) {
        if ($ProfileName -cnotmatch '^[a-z0-9][a-z0-9_-]{0,24}$') {
            throw "Invalid profile name '$ProfileName'. Use lowercase alphanumeric, '-', or '_'."
        }
        $profilePath = Get-ProfileOverridePath -RepoRoot $RepoRoot -ProfileName $ProfileName
        $profObj = $null
        if ($profilePath) {
            $profObj = (Get-Content -LiteralPath $profilePath -Raw -Encoding UTF8) | ConvertFrom-Json
            $cfg = Merge-BoxConfigObject -Base $cfg -Override $profObj
        }

        $profDistroVal = $null
        $profInstallDirVal = $null
        $profAgentUser = $null
        $profUidVal = $null
        $profGidVal = $null
        $profSetsDistro = ((Read-BoxObjectProperty -Object $profObj -Name 'distroName' -Value ([ref]$profDistroVal)) -and -not [string]::IsNullOrWhiteSpace([string]$profDistroVal))
        $profSetsInstallDir = ((Read-BoxObjectProperty -Object $profObj -Name 'installDir' -Value ([ref]$profInstallDirVal)) -and -not [string]::IsNullOrWhiteSpace([string]$profInstallDirVal))
        $hasProfAgentUser = (Read-BoxObjectProperty -Object $profObj -Name 'agentUser' -Value ([ref]$profAgentUser)) -and $null -ne $profAgentUser
        $profSetsUid = ($hasProfAgentUser -and (Read-BoxObjectProperty -Object $profAgentUser -Name 'uid' -Value ([ref]$profUidVal)) -and $null -ne $profUidVal)
        $profSetsGid = ($hasProfAgentUser -and (Read-BoxObjectProperty -Object $profAgentUser -Name 'gid' -Value ([ref]$profGidVal)) -and $null -ne $profGidVal)

        if (-not $profSetsDistro) {
            $baseDistro = [string]$baseCfg.distroName
            $maxBaseLen = [Math]::Max(1, 63 - 1 - $ProfileName.Length)
            if ($baseDistro.Length -gt $maxBaseLen) {
                $baseDistro = $baseDistro.Substring(0, $maxBaseLen)
            }
            $cfg.distroName = "$baseDistro-$ProfileName"
        }
        if (-not $profSetsInstallDir) {
            $cfg.installDir = Get-DerivedProfileInstallDir -BaseInstallDir $baseCfg.installDir -DistroName $cfg.distroName
        }

        $uidMap = Get-ResolvedProfileUidMap -RepoRoot $RepoRoot -BaseUid ([int]$baseCfg.agentUser.uid) -IncludeProfile $ProfileName
        if (-not $profSetsUid) {
            $cfg.agentUser.uid = [int]$uidMap[$ProfileName]
        }
        if (-not $profSetsGid) {
            $cfg.agentUser.gid = [int]$cfg.agentUser.uid
        }
        Assert-BoxConfigValid -Config $cfg
    }
    return $cfg
}

function Test-IsBoxJsonObject {
    param($Value)
    if ($null -eq $Value) { return $false }
    if ($Value -is [System.Collections.IDictionary]) { return $true }
    if ($Value -is [psobject] -and $Value -isnot [string] -and $Value -isnot [System.Collections.IEnumerable] -and $Value.GetType().IsClass) {
        return $true
    }
    return $false
}

function Test-BoxObjectHasProperty {
    param(
        $Object,
        [Parameter(Mandatory)][string]$Name
    )
    if (-not (Test-IsBoxJsonObject $Object)) {
        return $false
    }
    if ($Object -is [System.Collections.IDictionary]) {
        foreach ($k in $Object.Keys) {
            if (([string]$k) -ceq $Name) {
                return $true
            }
        }
        return $false
    }
    foreach ($p in $Object.PSObject.Properties) {
        if ($p.Name -ceq $Name) {
            return $true
        }
    }
    return $false
}

function Read-BoxObjectProperty {
    param(
        $Object,
        [Parameter(Mandatory)][string]$Name,
        [Parameter(Mandatory)][ref]$Value
    )
    $Value.Value = $null
    if (-not (Test-IsBoxJsonObject $Object)) {
        return $false
    }
    if ($Object -is [System.Collections.IDictionary]) {
        foreach ($entry in $Object.GetEnumerator()) {
            if (([string]$entry.Key) -ceq $Name) {
                $Value.Value = $entry.Value
                return $true
            }
        }
        return $false
    }
    foreach ($p in $Object.PSObject.Properties) {
        if ($p.Name -ceq $Name) {
            $Value.Value = $p.Value
            return $true
        }
    }
    return $false
}

function Convert-BoxValueToPsObject {
    param($Value)
    if ($Value -is [System.Collections.IDictionary]) {
        $obj = [pscustomobject]@{}
        foreach ($entry in $Value.GetEnumerator()) {
            $obj | Add-Member -NotePropertyName ([string]$entry.Key) -NotePropertyValue (Convert-BoxValueToPsObject $entry.Value) -Force
        }
        return $obj
    }
    if ($Value -is [System.Collections.IEnumerable] -and $Value -isnot [string]) {
        $items = New-Object System.Collections.Generic.List[object]
        foreach ($item in $Value) {
            $items.Add((Convert-BoxValueToPsObject $item))
        }
        return ,($items.ToArray())
    }
    return $Value
}

function Merge-BoxConfigObject {
    param(
        [Parameter(Mandatory)]$Base,
        [Parameter(Mandatory)]$Override
    )
    if (-not (Test-IsBoxJsonObject $Base) -or -not (Test-IsBoxJsonObject $Override)) {
        throw "Merge-BoxConfigObject requires JSON/object or dictionary inputs."
    }
    $result = if ($Base -is [System.Collections.IDictionary]) {
        Convert-BoxValueToPsObject $Base
    } else {
        $Base | ConvertTo-Json -Depth 20 | ConvertFrom-Json
    }

    $entries = New-Object System.Collections.Generic.List[object]
    if ($Override -is [System.Collections.IDictionary]) {
        foreach ($entry in $Override.GetEnumerator()) {
            $entries.Add(@{ Name = [string]$entry.Key; Value = $entry.Value })
        }
    } else {
        foreach ($prop in $Override.PSObject.Properties) {
            $entries.Add(@{ Name = $prop.Name; Value = $prop.Value })
        }
    }

    foreach ($item in $entries) {
        $name = $item.Name
        $ovVal = $item.Value
        $existingProp = $result.PSObject.Properties | Where-Object { $_.Name -ceq $name } | Select-Object -First 1
        if ($null -ne $existingProp -and (Test-IsBoxJsonObject $existingProp.Value) -and (Test-IsBoxJsonObject $ovVal)) {
            $merged = Merge-BoxConfigObject -Base $existingProp.Value -Override $ovVal
            $existingProp.Value = $merged
        } elseif ($null -ne $existingProp) {
            $existingProp.Value = Convert-BoxValueToPsObject $ovVal
        } else {
            $result | Add-Member -NotePropertyName $name -NotePropertyValue (Convert-BoxValueToPsObject $ovVal) -Force
        }
    }
    return $result
}

function Assert-AllowedProperties {
    param(
        [Parameter(Mandatory)]$Object,
        [Parameter(Mandatory)][string[]]$Allowed,
        [Parameter(Mandatory)][string]$SectionName
    )
    if (-not (Test-IsBoxJsonObject $Object)) {
        throw "$SectionName must be a JSON object."
    }
    $propNames = if ($Object -is [System.Collections.IDictionary]) {
        @($Object.Keys | ForEach-Object { [string]$_ })
    } else {
        @($Object.PSObject.Properties | ForEach-Object { $_.Name })
    }
    foreach ($propName in $propNames) {
        if ($propName -cnotin $Allowed) {
            throw "Unknown property '$propName' in $SectionName. Allowed: $($Allowed -join ', ')."
        }
    }
}

function Read-BoxConfig {
    param(
        [Parameter(Mandatory)][string]$ConfigPath,
        [string]$LocalOverridePath = '',
        [string]$LocalOverrideSearchDir = '',
        [switch]$IgnoreLocalOverride
    )
    if (-not (Test-Path -LiteralPath $ConfigPath -PathType Leaf)) {
        throw "Configuration file not found: $ConfigPath"
    }
    $raw = Get-Content -LiteralPath $ConfigPath -Raw -Encoding UTF8
    try {
        $cfg = $raw | ConvertFrom-Json
    } catch {
        throw "Failed to parse JSON in '$ConfigPath': $($_.Exception.Message)"
    }

    $overrideFile = $null
    if (-not [string]::IsNullOrWhiteSpace($LocalOverridePath)) {
        if (-not (Test-Path -LiteralPath $LocalOverridePath -PathType Leaf)) {
            throw "Local configuration override file not found: $LocalOverridePath"
        }
        $overrideFile = $LocalOverridePath
    } elseif (-not $IgnoreLocalOverride) {
        if (-not [string]::IsNullOrWhiteSpace($LocalOverrideSearchDir)) {
            $overrideFile = Get-BoxLocalOverridePath -ConfigPath $ConfigPath -SearchDir $LocalOverrideSearchDir
        } else {
            $overrideFile = Get-BoxLocalOverridePath -ConfigPath $ConfigPath
        }
    }

    if ($overrideFile) {
        $ovRaw = Get-Content -LiteralPath $overrideFile -Raw -Encoding UTF8
        try {
            $ovCfg = $ovRaw | ConvertFrom-Json
        } catch {
            throw "Failed to parse JSON in '$overrideFile': $($_.Exception.Message)"
        }
        if (-not (Test-IsBoxJsonObject $ovCfg)) {
            throw "Local configuration override '$overrideFile' must be a JSON object."
        }
        $cfg = Merge-BoxConfigObject -Base $cfg -Override $ovCfg
    }

    Assert-BoxConfigValid -Config $cfg
    return $cfg
}

function Assert-BoxConfigValid {
    param(
        [Parameter(Mandatory)]$Config
    )

    Assert-AllowedProperties -Object $Config -Allowed @(
        '$schema', 'distroName', 'installDir', 'agentUser', 'image',
        'sharedFolders', 'network', 'docker', 'packages', 'ide', 'secrets', 'resources'
    ) -SectionName 'box.json root'

    $distroNameVal = $null
    [void](Read-BoxObjectProperty -Object $Config -Name 'distroName' -Value ([ref]$distroNameVal))
    if ($distroNameVal -isnot [string] -or -not $distroNameVal -or $distroNameVal -notmatch '^[A-Za-z0-9][A-Za-z0-9._-]{1,62}$') {
        throw "Invalid distroName '$distroNameVal'. Must match ^[A-Za-z0-9][A-Za-z0-9._-]{1,62}$."
    }

    $installDirVal = $null
    [void](Read-BoxObjectProperty -Object $Config -Name 'installDir' -Value ([ref]$installDirVal))
    if ($installDirVal -isnot [string] -or [string]::IsNullOrWhiteSpace($installDirVal)) {
        throw "installDir must be non-empty."
    }

    $agentUserObj = $null
    if (-not (Read-BoxObjectProperty -Object $Config -Name 'agentUser' -Value ([ref]$agentUserObj)) -or -not $agentUserObj) {
        throw "agentUser section is required."
    }
    Assert-AllowedProperties -Object $agentUserObj -Allowed @('name', 'uid', 'gid') -SectionName 'agentUser'
    $agentUserName = $null
    [void](Read-BoxObjectProperty -Object $agentUserObj -Name 'name' -Value ([ref]$agentUserName))
    if ($agentUserName -isnot [string] -or $agentUserName -notmatch '^[a-z_][a-z0-9_-]{0,31}$' -or $agentUserName -eq 'root') {
        throw "Invalid agentUser.name '$agentUserName'. Must be a valid non-root Linux username."
    }
    $agentUidVal = $null
    $agentGidVal = $null
    [void](Read-BoxObjectProperty -Object $agentUserObj -Name 'uid' -Value ([ref]$agentUidVal))
    [void](Read-BoxObjectProperty -Object $agentUserObj -Name 'gid' -Value ([ref]$agentGidVal))
    $uid = [int]$agentUidVal
    $gid = [int]$agentGidVal
    if ($uid -lt 10000 -or $uid -gt 60000) {
        throw "agentUser.uid ($uid) must be between 10000 and 60000 so per-UID nftables rules do not collide with UID 1000 in other WSL distros."
    }
    if ($gid -lt 10000 -or $gid -gt 60000) {
        throw "agentUser.gid ($gid) must be between 10000 and 60000."
    }

    $imageObj = $null
    if (-not (Read-BoxObjectProperty -Object $Config -Name 'image' -Value ([ref]$imageObj)) -or -not $imageObj) {
        throw "image section is required."
    }
    Assert-AllowedProperties -Object $imageObj -Allowed @('release', 'arch', 'url', 'sha256', 'cacheDir') -SectionName 'image'
    $imageArch = $null
    [void](Read-BoxObjectProperty -Object $imageObj -Name 'arch' -Value ([ref]$imageArch))
    if ($imageArch -isnot [string] -or $imageArch -notin @('amd64', 'arm64')) {
        throw "image.arch must be 'amd64' or 'arm64'."
    }

    # Validate sharedFolders
    $seenNames = @{}
    $sharedFoldersVal = $null
    [void](Read-BoxObjectProperty -Object $Config -Name 'sharedFolders' -Value ([ref]$sharedFoldersVal))
    foreach ($sf in @($sharedFoldersVal)) {
        if ($null -eq $sf) { continue }
        Assert-AllowedProperties -Object $sf -Allowed @('name', 'windowsPath', 'mode', 'allowDockerBind') -SectionName 'sharedFolders[*]'
        $sfName = $null
        [void](Read-BoxObjectProperty -Object $sf -Name 'name' -Value ([ref]$sfName))
        if ($sfName -isnot [string] -or -not $sfName -or $sfName -notmatch '^[A-Za-z0-9][A-Za-z0-9._-]{0,62}$') {
            throw "Invalid sharedFolders entry name '$sfName'."
        }
        if ($seenNames.ContainsKey($sfName.ToLowerInvariant())) {
            throw "Duplicate sharedFolders entry name '$sfName'."
        }
        $seenNames[$sfName.ToLowerInvariant()] = $true

        # Refuse mounting an entire Windows drive root (e.g. C:\ or C:)
        $sfWinPath = $null
        [void](Read-BoxObjectProperty -Object $sf -Name 'windowsPath' -Value ([ref]$sfWinPath))
        if ($sfWinPath -is [string] -and $sfWinPath.TrimEnd('\') -match '^[A-Za-z]:$') {
            throw "Refusing to share entire Windows drive root '$sfWinPath'. Share a specific subdirectory instead."
        }
        if ($sfWinPath -isnot [string] -or -not $sfWinPath -or $sfWinPath -notmatch '^[A-Za-z]:\\.+') {
            throw "sharedFolders '$sfName' windowsPath '$sfWinPath' must be an absolute Windows subdirectory path (e.g. C:\path\to\folder)."
        }
        $sfMode = $null
        [void](Read-BoxObjectProperty -Object $sf -Name 'mode' -Value ([ref]$sfMode))
        if ($sfMode -isnot [string] -or $sfMode -notin @('ro', 'rw')) {
            throw "sharedFolders '$sfName' mode '$sfMode' must be 'ro' or 'rw'."
        }
        $allowDockerBindVal = $null
        if (Read-BoxObjectProperty -Object $sf -Name 'allowDockerBind' -Value ([ref]$allowDockerBindVal)) {
            if ($null -ne $allowDockerBindVal -and $allowDockerBindVal -isnot [bool]) {
                throw "sharedFolders '$sfName' allowDockerBind must be a boolean."
            }
        }
    }

    # Validate network
    $networkObj = $null
    if (-not (Read-BoxObjectProperty -Object $Config -Name 'network' -Value ([ref]$networkObj)) -or -not $networkObj) {
        throw "network section is required."
    }
    Assert-AllowedProperties -Object $networkObj -Allowed @('blockHostAndLan', 'allowedHostPorts', 'blockedCidrs', 'logDrops', 'egressMode', 'allowedDomains') -SectionName 'network'
    foreach ($netBoolProp in @('blockHostAndLan', 'logDrops')) {
        $netBoolVal = $null
        if (Read-BoxObjectProperty -Object $networkObj -Name $netBoolProp -Value ([ref]$netBoolVal)) {
            if ($null -ne $netBoolVal -and $netBoolVal -isnot [bool]) {
                throw "network.$netBoolProp must be a boolean."
            }
        }
    }
    $allowedHostPortsVal = $null
    [void](Read-BoxObjectProperty -Object $networkObj -Name 'allowedHostPorts' -Value ([ref]$allowedHostPortsVal))
    foreach ($hp in @($allowedHostPortsVal)) {
        if ($null -eq $hp) { continue }
        Assert-AllowedProperties -Object $hp -Allowed @('port', 'protocol', 'comment') -SectionName 'network.allowedHostPorts[*]'
        $hpPortVal = $null
        [void](Read-BoxObjectProperty -Object $hp -Name 'port' -Value ([ref]$hpPortVal))
        $port = [int]$hpPortVal
        if ($port -lt 1 -or $port -gt 65535) {
            throw "Invalid allowedHostPorts port '$hpPortVal'. Must be 1-65535."
        }
        $hpProtoVal = $null
        [void](Read-BoxObjectProperty -Object $hp -Name 'protocol' -Value ([ref]$hpProtoVal))
        if ($hpProtoVal -isnot [string] -or $hpProtoVal -notin @('tcp', 'udp')) {
            throw "Invalid allowedHostPorts protocol '$hpProtoVal'. Must be 'tcp' or 'udp'."
        }
    }
    $blockedCidrsVal = $null
    [void](Read-BoxObjectProperty -Object $networkObj -Name 'blockedCidrs' -Value ([ref]$blockedCidrsVal))
    foreach ($cidr in @($blockedCidrsVal)) {
        if (-not $cidr) { continue }
        if ($cidr -isnot [string] -or $cidr -notmatch '^[0-9a-fA-F:.]+/[0-9]{1,3}$') {
            throw "Invalid CIDR in network.blockedCidrs: '$cidr'."
        }
        $parts = $cidr -split '/'
        $ipObj = $null
        if (-not [System.Net.IPAddress]::TryParse($parts[0], [ref]$ipObj)) {
            throw "Invalid IP address in network.blockedCidrs: '$cidr'."
        }
        $prefixLen = [int]$parts[1]
        $maxPrefix = if ($ipObj.AddressFamily -eq [System.Net.Sockets.AddressFamily]::InterNetwork) { 32 } else { 128 }
        if ($prefixLen -lt 0 -or $prefixLen -gt $maxPrefix) {
            throw "Invalid prefix length in network.blockedCidrs: '$cidr'."
        }
    }
    $egressModeVal = $null
    if ((Read-BoxObjectProperty -Object $networkObj -Name 'egressMode' -Value ([ref]$egressModeVal)) -and $null -ne $egressModeVal -and $egressModeVal -ne '') {
        if ($egressModeVal -isnot [string] -or $egressModeVal -notin @('open', 'allowlist')) {
            throw "Invalid network.egressMode '$egressModeVal'. Must be 'open' or 'allowlist'."
        }
    }
    $allowedDomainsVal = $null
    if ((Read-BoxObjectProperty -Object $networkObj -Name 'allowedDomains' -Value ([ref]$allowedDomainsVal)) -and $null -ne $allowedDomainsVal) {
        foreach ($dom in @($allowedDomainsVal)) {
            if ($dom -isnot [string] -or -not $dom -or $dom -match '\s') {
                throw "Invalid network.allowedDomains entry '$dom'."
            }
        }
    }

    # Validate docker
    $dockerObj = $null
    if (-not (Read-BoxObjectProperty -Object $Config -Name 'docker' -Value ([ref]$dockerObj)) -or -not $dockerObj) {
        throw "docker section is required."
    }
    Assert-AllowedProperties -Object $dockerObj -Allowed @(
        'enabled', 'allowBindPrefixes', 'allowBuildKit', 'allowCapAdd', 'denyEndpoints',
        'allowPortBindings', 'forceLoopbackPortBindings', 'allowedPublishedPorts',
        'forceInternalNetwork', 'defaultLimits', 'maxLimits', 'allowedRegistries'
    ) -SectionName 'docker'
    foreach ($dockerBoolProp in @('enabled', 'allowBuildKit', 'allowPortBindings', 'forceLoopbackPortBindings', 'forceInternalNetwork')) {
        $dockerBoolVal = $null
        if (Read-BoxObjectProperty -Object $dockerObj -Name $dockerBoolProp -Value ([ref]$dockerBoolVal)) {
            if ($null -ne $dockerBoolVal -and $dockerBoolVal -isnot [bool]) {
                throw "docker.$dockerBoolProp must be a boolean."
            }
        }
    }
    $allowBindPrefixesVal = $null
    [void](Read-BoxObjectProperty -Object $dockerObj -Name 'allowBindPrefixes' -Value ([ref]$allowBindPrefixesVal))
    foreach ($bp in @($allowBindPrefixesVal)) {
        if (-not $bp) { continue }
        if ($bp -isnot [string] -or -not $bp.StartsWith('/') -or $bp -eq '/' -or $bp -match '^/mnt(/|$)' -or $bp -match '^/run/desktop') {
            throw "Unsafe docker.allowBindPrefixes entry '$bp'."
        }
    }
    $allowedPublishedPortsVal = $null
    if ((Read-BoxObjectProperty -Object $dockerObj -Name 'allowedPublishedPorts' -Value ([ref]$allowedPublishedPortsVal)) -and $null -ne $allowedPublishedPortsVal) {
        foreach ($pp in @($allowedPublishedPortsVal)) {
            $pNum = [int]$pp
            if ($pNum -lt 1 -or $pNum -gt 65535) {
                throw "Invalid docker.allowedPublishedPorts port '$pp'. Must be 1-65535."
            }
        }
    }
    $limitSpecs = @{
        memoryBytes = [int64]4194304
        nanoCpus    = [int64]1000000
        pidsLimit   = [int64]1
    }
    foreach ($sectionName in @('defaultLimits', 'maxLimits')) {
        $secObj = $null
        if ((Read-BoxObjectProperty -Object $dockerObj -Name $sectionName -Value ([ref]$secObj)) -and $null -ne $secObj) {
            Assert-AllowedProperties -Object $secObj -Allowed @('memoryBytes', 'nanoCpus', 'pidsLimit') -SectionName "docker.$sectionName"
            $secPropNames = if ($secObj -is [System.Collections.IDictionary]) {
                @($secObj.Keys | ForEach-Object { [string]$_ })
            } else {
                @($secObj.PSObject.Properties | ForEach-Object { $_.Name })
            }
            foreach ($propName in $secPropNames) {
                $propVal = $null
                [void](Read-BoxObjectProperty -Object $secObj -Name $propName -Value ([ref]$propVal))
                if ($null -eq $propVal) { continue }
                $valNum = [int64]$propVal
                $minVal = $limitSpecs[$propName]
                if ($valNum -lt $minVal) {
                    throw "docker.$sectionName.$propName ($valNum) must be >= $minVal."
                }
            }
        }
    }
    $defLimitsObj = $null
    $maxLimitsObj = $null
    if ((Read-BoxObjectProperty -Object $dockerObj -Name 'defaultLimits' -Value ([ref]$defLimitsObj)) -and $null -ne $defLimitsObj -and
        (Read-BoxObjectProperty -Object $dockerObj -Name 'maxLimits' -Value ([ref]$maxLimitsObj)) -and $null -ne $maxLimitsObj) {
        foreach ($field in $limitSpecs.Keys) {
            $defFieldVal = $null
            $maxFieldVal = $null
            $hasDef = (Read-BoxObjectProperty -Object $defLimitsObj -Name $field -Value ([ref]$defFieldVal)) -and $null -ne $defFieldVal
            $hasMax = (Read-BoxObjectProperty -Object $maxLimitsObj -Name $field -Value ([ref]$maxFieldVal)) -and $null -ne $maxFieldVal
            if ($hasDef -and $hasMax -and ([int64]$defFieldVal -gt [int64]$maxFieldVal)) {
                throw "docker.defaultLimits.$field ($defFieldVal) exceeds docker.maxLimits.$field ($maxFieldVal)."
            }
        }
    }
    $allowedRegistriesVal = $null
    if ((Read-BoxObjectProperty -Object $dockerObj -Name 'allowedRegistries' -Value ([ref]$allowedRegistriesVal)) -and $null -ne $allowedRegistriesVal) {
        foreach ($reg in @($allowedRegistriesVal)) {
            if ($reg -isnot [string] -or [string]::IsNullOrWhiteSpace($reg) -or $reg -match '://|[/\\\s]') {
                throw "Invalid docker.allowedRegistries entry '$reg'. Expected registry host[:port] (e.g., docker.io, ghcr.io, localhost:5000)."
            }
        }
    }

    # Validate packages
    $packagesObj = $null
    if (-not (Read-BoxObjectProperty -Object $Config -Name 'packages' -Value ([ref]$packagesObj)) -or -not $packagesObj) {
        throw "packages section is required."
    }
    $packageInstallFlags = @(
        'installDockerCli', 'installUv', 'installNodeLts', 'installPnpm',
        'installGeminiCli', 'installClaudeCode', 'installKubectl', 'installAwsCli',
        'installGcloudCli', 'installAzureCli', 'installAzureDevopsCli', 'installGithubCli',
        'installJiraCli', 'installUpctl', 'installDotnetSdk', 'installRust',
        'installCodexCli', 'installOpenCode', 'installAider', 'installHelm',
        'installOpenTofu', 'installTerraform', 'installPlaywrightChromium', 'installPlaywrightFirefox'
    )
    $allowedPackageProps = @('apt', 'dotnetChannels', 'configureVsCodeRemoteWsl') + $packageInstallFlags
    Assert-AllowedProperties -Object $packagesObj -Allowed $allowedPackageProps -SectionName 'packages'

    foreach ($flagName in $packageInstallFlags) {
        $flagVal = $null
        if (Read-BoxObjectProperty -Object $packagesObj -Name $flagName -Value ([ref]$flagVal)) {
            if ($null -ne $flagVal -and $flagVal -isnot [bool]) {
                throw "packages.$flagName must be a boolean."
            }
        }
    }

    $channels = $null
    if (Read-BoxObjectProperty -Object $packagesObj -Name 'dotnetChannels' -Value ([ref]$channels)) {
        if ($null -ne $channels) {
            if (($channels -is [string]) -or ($channels -isnot [System.Collections.IEnumerable]) -or ($channels -is [System.Collections.IDictionary])) {
                throw "packages.dotnetChannels must be an array of 'major.minor' strings (e.g., ['8.0'])."
            }
            $seenChannels = @{}
            foreach ($ch in $channels) {
                if ($ch -isnot [string] -or $ch -notmatch '^[0-9]+\.[0-9]+$') {
                    throw "Invalid packages.dotnetChannels entry '$ch'. Expected 'major.minor' string (e.g., '8.0')."
                }
                if ($seenChannels.ContainsKey($ch)) {
                    throw "Duplicate packages.dotnetChannels entry '$ch'."
                }
                $seenChannels[$ch] = $true
            }
        }
    }

    $aptVal = $null
    [void](Read-BoxObjectProperty -Object $packagesObj -Name 'apt' -Value ([ref]$aptVal))
    foreach ($pkg in @($aptVal)) {
        if (-not $pkg) { continue }
        if ($pkg -isnot [string] -or $pkg -notmatch '^[a-z0-9][a-z0-9+.-]+$') {
            throw "Invalid apt package name '$pkg'."
        }
    }

    # Validate optional non-secret 'secrets' pointer
    $secretsObj = $null
    if ((Read-BoxObjectProperty -Object $Config -Name 'secrets' -Value ([ref]$secretsObj)) -and $null -ne $secretsObj) {
        if (-not (Test-IsBoxJsonObject $secretsObj)) {
            throw "secrets must be a JSON object."
        }
        $allowedSecretProps = @('manifestPath')
        $secPropNames = if ($secretsObj -is [System.Collections.IDictionary]) {
            @($secretsObj.Keys | ForEach-Object { [string]$_ })
        } else {
            @($secretsObj.PSObject.Properties | ForEach-Object { $_.Name })
        }
        foreach ($propName in $secPropNames) {
            if ($propName -cnotin $allowedSecretProps) {
                throw "box.json 'secrets' section only allows non-secret pointer property 'manifestPath' (found '$propName'). Store credentials in your central Windows secrets.json instead."
            }
        }
        $mpVal = $null
        if ((Read-BoxObjectProperty -Object $secretsObj -Name 'manifestPath' -Value ([ref]$mpVal)) -and $null -ne $mpVal) {
            if ($mpVal -isnot [string]) {
                throw "secrets.manifestPath must be a string."
            }
            $mp = [string]$mpVal
            if ($mp.Length -gt 0 -and [string]::IsNullOrWhiteSpace($mp)) {
                throw "secrets.manifestPath cannot be whitespace."
            }
            if ($mp -and $mp.TrimEnd('\') -match '^[A-Za-z]:$') {
                throw "secrets.manifestPath '$mp' must point to a JSON file, not a drive root."
            }
        }
    }

    # Validate optional 'resources' systemd per-UID quotas
    $resourcesObj = $null
    if ((Read-BoxObjectProperty -Object $Config -Name 'resources' -Value ([ref]$resourcesObj)) -and $null -ne $resourcesObj) {
        $allowedResProps = @('memoryMax', 'cpuQuota', 'tasksMax')
        Assert-AllowedProperties -Object $resourcesObj -Allowed $allowedResProps -SectionName 'resources'
        $memoryMaxVal = $null
        if ((Read-BoxObjectProperty -Object $resourcesObj -Name 'memoryMax' -Value ([ref]$memoryMaxVal)) -and $null -ne $memoryMaxVal) {
            if ($memoryMaxVal -isnot [string] -or $memoryMaxVal -notmatch '^[1-9][0-9]*[KMGTP]?$') {
                throw "Invalid resources.memoryMax '$memoryMaxVal'. Expected positive size e.g. '8G' or '4096M'."
            }
        }
        $cpuQuotaVal = $null
        if ((Read-BoxObjectProperty -Object $resourcesObj -Name 'cpuQuota' -Value ([ref]$cpuQuotaVal)) -and $null -ne $cpuQuotaVal) {
            if ($cpuQuotaVal -isnot [string] -or $cpuQuotaVal -notmatch '^[1-9][0-9]*%$') {
                throw "Invalid resources.cpuQuota '$cpuQuotaVal'. Expected positive percentage e.g. '400%'."
            }
        }
        $tasksMaxVal = $null
        if ((Read-BoxObjectProperty -Object $resourcesObj -Name 'tasksMax' -Value ([ref]$tasksMaxVal)) -and $null -ne $tasksMaxVal) {
            $tm = [int]$tasksMaxVal
            if ($tm -lt 32 -or $tm -gt 65536) {
                throw "resources.tasksMax ($tm) must be between 32 and 65536."
            }
        }
    }

    # Validate optional 'ide' Remote-WSL settings
    $ideObj = $null
    if ((Read-BoxObjectProperty -Object $Config -Name 'ide' -Value ([ref]$ideObj)) -and $null -ne $ideObj) {
        $allowedIdeProps = @('configureRemoteWsl')
        Assert-AllowedProperties -Object $ideObj -Allowed $allowedIdeProps -SectionName 'ide'
        $ideBoolVal = $null
        if (Read-BoxObjectProperty -Object $ideObj -Name 'configureRemoteWsl' -Value ([ref]$ideBoolVal)) {
            if ($null -ne $ideBoolVal -and $ideBoolVal -isnot [bool]) {
                throw "ide.configureRemoteWsl must be a boolean."
            }
        }
    }
    $vsCodeBoolVal = $null
    if (Read-BoxObjectProperty -Object $packagesObj -Name 'configureVsCodeRemoteWsl' -Value ([ref]$vsCodeBoolVal)) {
        if ($null -ne $vsCodeBoolVal -and $vsCodeBoolVal -isnot [bool]) {
            throw "packages.configureVsCodeRemoteWsl must be a boolean."
        }
    }
}

function Get-WindowsHostIPs {
    $ips = New-Object System.Collections.Generic.List[string]
    try {
        $addrs = Get-NetIPAddress -ErrorAction Stop | Where-Object {
            $_.IPAddress -and
            $_.IPAddress -ne '127.0.0.1' -and
            $_.IPAddress -ne '::1' -and
            $_.AddressState -eq 'Preferred'
        }
        foreach ($a in $addrs) {
            $clean = ($a.IPAddress -split '%')[0]
            if (-not $ips.Contains($clean)) {
                $ips.Add($clean)
            }
        }
    } catch {
        # Fallback if Get-NetIPAddress is unavailable in restricted environments
        Write-Verbose "Get-NetIPAddress unavailable: $($_.Exception.Message)"
    }
    return $ips.ToArray()
}

function Get-DockerSecurityAdvisories {
    param([Parameter(Mandatory)]$Config)
    $advisories = New-Object System.Collections.Generic.List[string]
    $dockerObj = $null
    $dockerEnabled = $null
    if (-not $Config -or -not (Read-BoxObjectProperty -Object $Config -Name 'docker' -Value ([ref]$dockerObj)) -or -not $dockerObj -or
        -not (Read-BoxObjectProperty -Object $dockerObj -Name 'enabled' -Value ([ref]$dockerEnabled)) -or -not [bool]$dockerEnabled) {
        return @()
    }
    $forceInternalVal = $null
    $forceInternal = ((Read-BoxObjectProperty -Object $dockerObj -Name 'forceInternalNetwork' -Value ([ref]$forceInternalVal)) -and [bool]$forceInternalVal)
    $allowBuildKitVal = $null
    $allowBuildKit = ((Read-BoxObjectProperty -Object $dockerObj -Name 'allowBuildKit' -Value ([ref]$allowBuildKitVal)) -and [bool]$allowBuildKitVal)
    $allowedRegistries = @()
    $allowedRegistriesVal = $null
    if ((Read-BoxObjectProperty -Object $dockerObj -Name 'allowedRegistries' -Value ([ref]$allowedRegistriesVal)) -and $null -ne $allowedRegistriesVal) {
        $allowedRegistries = @($allowedRegistriesVal)
    }
    $networkObj = $null
    $hasNetwork = (Read-BoxObjectProperty -Object $Config -Name 'network' -Value ([ref]$networkObj)) -and $null -ne $networkObj
    $blockHostVal = $null
    $blockHostAndLan = ($hasNetwork -and (Read-BoxObjectProperty -Object $networkObj -Name 'blockHostAndLan' -Value ([ref]$blockHostVal)) -and [bool]$blockHostVal)
    $egressModeVal = $null
    $egressAllowlist = ($hasNetwork -and (Read-BoxObjectProperty -Object $networkObj -Name 'egressMode' -Value ([ref]$egressModeVal)) -and ($egressModeVal -eq 'allowlist'))

    if ((-not $forceInternal) -and ($blockHostAndLan -or $egressAllowlist)) {
        $egressDesc = if ($egressAllowlist) { 'allowlist' } else { 'open' }
        $advisories.Add("Docker is enabled with forceInternalNetwork=false while strict network isolation is active (blockHostAndLan=$($blockHostAndLan.ToString().ToLowerInvariant()), egressMode=$egressDesc). Containers can reach Windows host ports via host.docker.internal and bypass WSL egress rules unless docker.forceInternalNetwork is set to true.")
        if ($allowBuildKit -and @($allowedRegistries).Count -eq 0) {
            $advisories.Add("Docker BuildKit (allowBuildKit=true) is active without docker.forceInternalNetwork=true; 'docker buildx build' RUN steps execute on Docker Desktop's default network and can reach host.docker.internal/external internet.")
        }
    }
    return $advisories.ToArray()
}
