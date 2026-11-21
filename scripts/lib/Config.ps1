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

function Read-BoxConfig {
    param(
        [Parameter(Mandatory)][string]$ConfigPath
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
    Assert-BoxConfigValid -Config $cfg
    return $cfg
}

function Assert-BoxConfigValid {
    param(
        [Parameter(Mandatory)]$Config
    )

    if (-not $Config.distroName -or $Config.distroName -notmatch '^[A-Za-z0-9][A-Za-z0-9._-]{1,62}$') {
        throw "Invalid distroName '$($Config.distroName)'. Must match ^[A-Za-z0-9][A-Za-z0-9._-]{1,62}$."
    }

    if (-not $Config.installDir -or [string]::IsNullOrWhiteSpace($Config.installDir)) {
        throw "installDir must be non-empty."
    }

    if (-not $Config.agentUser) {
        throw "agentUser section is required."
    }
    if ($Config.agentUser.name -notmatch '^[a-z_][a-z0-9_-]{0,31}$' -or $Config.agentUser.name -eq 'root') {
        throw "Invalid agentUser.name '$($Config.agentUser.name)'. Must be a valid non-root Linux username."
    }
    $uid = [int]$Config.agentUser.uid
    $gid = [int]$Config.agentUser.gid
    if ($uid -lt 10000 -or $uid -gt 60000) {
        throw "agentUser.uid ($uid) must be between 10000 and 60000 so per-UID nftables rules do not collide with UID 1000 in other WSL distros."
    }
    if ($gid -lt 10000 -or $gid -gt 60000) {
        throw "agentUser.gid ($gid) must be between 10000 and 60000."
    }

    if (-not $Config.image -or $Config.image.arch -notin @('amd64', 'arm64')) {
        throw "image.arch must be 'amd64' or 'arm64'."
    }

    # Validate sharedFolders
    $seenNames = @{}
    foreach ($sf in @($Config.sharedFolders)) {
        if (-not $sf) { continue }
        if (-not $sf.name -or $sf.name -notmatch '^[A-Za-z0-9][A-Za-z0-9._-]{0,62}$') {
            throw "Invalid sharedFolders entry name '$($sf.name)'."
        }
        if ($seenNames.ContainsKey($sf.name.ToLowerInvariant())) {
            throw "Duplicate sharedFolders entry name '$($sf.name)'."
        }
        $seenNames[$sf.name.ToLowerInvariant()] = $true

        # Refuse mounting an entire Windows drive root (e.g. C:\ or C:)
        if ($sf.windowsPath -and $sf.windowsPath.TrimEnd('\') -match '^[A-Za-z]:$') {
            throw "Refusing to share entire Windows drive root '$($sf.windowsPath)'. Share a specific subdirectory instead."
        }
        if (-not $sf.windowsPath -or $sf.windowsPath -notmatch '^[A-Za-z]:\\.+') {
            throw "sharedFolders '$($sf.name)' windowsPath '$($sf.windowsPath)' must be an absolute Windows subdirectory path (e.g. C:\path\to\folder)."
        }
        if ($sf.mode -notin @('ro', 'rw')) {
            throw "sharedFolders '$($sf.name)' mode '$($sf.mode)' must be 'ro' or 'rw'."
        }
    }

    # Validate network
    if (-not $Config.network) {
        throw "network section is required."
    }
    foreach ($hp in @($Config.network.allowedHostPorts)) {
        if (-not $hp) { continue }
        $port = [int]$hp.port
        if ($port -lt 1 -or $port -gt 65535) {
            throw "Invalid allowedHostPorts port '$($hp.port)'. Must be 1-65535."
        }
        if ($hp.protocol -notin @('tcp', 'udp')) {
            throw "Invalid allowedHostPorts protocol '$($hp.protocol)'. Must be 'tcp' or 'udp'."
        }
    }
    foreach ($cidr in @($Config.network.blockedCidrs)) {
        if (-not $cidr) { continue }
        if ($cidr -notmatch '^[0-9a-fA-F:.]+/[0-9]{1,3}$') {
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

    # Validate docker
    if (-not $Config.docker) {
        throw "docker section is required."
    }
    foreach ($bp in @($Config.docker.allowBindPrefixes)) {
        if (-not $bp) { continue }
        if (-not $bp.StartsWith('/') -or $bp -eq '/' -or $bp -match '^/mnt(/|$)' -or $bp -match '^/run/desktop') {
            throw "Unsafe docker.allowBindPrefixes entry '$bp'."
        }
    }

    # Validate packages
    if (-not $Config.packages) {
        throw "packages section is required."
    }
    foreach ($pkg in @($Config.packages.apt)) {
        if (-not $pkg) { continue }
        if ($pkg -notmatch '^[a-z0-9][a-z0-9+.-]+$') {
            throw "Invalid apt package name '$pkg'."
        }
    }

    # Validate optional non-secret 'secrets' pointer
    if ($Config.PSObject.Properties['secrets'] -and $null -ne $Config.secrets) {
        $allowedSecretProps = @('manifestPath')
        foreach ($prop in $Config.secrets.PSObject.Properties) {
            if ($prop.Name -notin $allowedSecretProps) {
                throw "box.json 'secrets' section only allows non-secret pointer property 'manifestPath' (found '$($prop.Name)'). Store credentials in your central Windows secrets.json instead."
            }
        }
        if ($Config.secrets.PSObject.Properties['manifestPath'] -and $null -ne $Config.secrets.manifestPath) {
            $mp = [string]$Config.secrets.manifestPath
            if ($mp.Length -gt 0 -and [string]::IsNullOrWhiteSpace($mp)) {
                throw "secrets.manifestPath cannot be whitespace."
            }
            if ($mp -and $mp.TrimEnd('\') -match '^[A-Za-z]:$') {
                throw "secrets.manifestPath '$mp' must point to a JSON file, not a drive root."
            }
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
    }
    return $ips.ToArray()
}
