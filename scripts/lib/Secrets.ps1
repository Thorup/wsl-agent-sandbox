#Requires -Version 5.1
Set-StrictMode -Version Latest

$script:SupportedSecretServices = @(
    'github',
    'git',
    'aws',
    'gcloud',
    'azure',
    'azureDevops',
    'jira',
    'upcloud',
    'kubectl',
    'gemini',
    'claude',
    'ssh',
    'env',
    'files'
)

$script:ForbiddenEnvVars = @(
    'PATH',
    'HOME',
    'USER',
    'LOGNAME',
    'SHELL',
    'DOCKER_HOST',
    'DOTNET_ROOT',
    'LD_PRELOAD',
    'LD_LIBRARY_PATH',
    'IFS',
    'BASH_ENV',
    'ENV',
    'WSL_INTEROP',
    'DISPLAY',
    'WAYLAND_DISPLAY',
    'PULSE_SERVER'
)

function Get-SupportedSecretServices {
    return @($script:SupportedSecretServices)
}

function Test-ObjectHasProperty {
    param(
        [Parameter(Mandatory)]$Object,
        [Parameter(Mandatory)][string]$Name
    )
    if ($null -eq $Object) { return $false }
    if ($Object -is [System.Collections.IDictionary]) {
        return $Object.Contains($Name)
    }
    return ($null -ne $Object.PSObject.Properties[$Name])
}

function Get-ObjectProperty {
    param(
        [Parameter(Mandatory)]$Object,
        [Parameter(Mandatory)][string]$Name,
        $Default = $null
    )
    if (-not (Test-ObjectHasProperty -Object $Object -Name $Name)) {
        return $Default
    }
    if ($Object -is [System.Collections.IDictionary]) {
        $val = $Object[$Name]
    } else {
        $val = $Object.PSObject.Properties[$Name].Value
    }
    if ($null -eq $val) {
        return $Default
    }
    return $val
}

function Get-ObjectPropertyNames {
    param([Parameter(Mandatory)]$Object)
    if ($Object -is [System.Collections.IDictionary]) {
        return @($Object.Keys)
    }
    return @($Object.PSObject.Properties | ForEach-Object { $_.Name })
}

function Resolve-SecretsManifestPath {
    param(
        [string]$ExplicitPath = '',
        $Config = $null,
        [string]$RepoRoot = ''
    )
    if (-not [string]::IsNullOrWhiteSpace($ExplicitPath)) {
        return Expand-BoxPath -RawPath $ExplicitPath -BaseDir (Get-Location).Path
    }

    $envPath = [Environment]::GetEnvironmentVariable('WSL_AGENT_SANDBOX_SECRETS_PATH')
    if (-not [string]::IsNullOrWhiteSpace($envPath)) {
        return Expand-BoxPath -RawPath $envPath -BaseDir (Get-Location).Path
    }

    if ($null -ne $Config -and (Test-ObjectHasProperty -Object $Config -Name 'secrets')) {
        $secCfg = Get-ObjectProperty -Object $Config -Name 'secrets'
        if ($null -ne $secCfg) {
            $cfgPath = [string](Get-ObjectProperty -Object $secCfg -Name 'manifestPath' -Default '')
            if (-not [string]::IsNullOrWhiteSpace($cfgPath)) {
                return Expand-BoxPath -RawPath $cfgPath -BaseDir $RepoRoot
            }
        }
    }

    return Expand-BoxPath -RawPath '%USERPROFILE%\.wsl-agent-sandbox\secrets.json'
}

function Resolve-SecretFileContent {
    param(
        [Parameter(Mandatory)][string]$RawPath,
        [Parameter(Mandatory)][string]$BaseDir,
        [Parameter(Mandatory)][string]$Context,
        [switch]$AsBytes
    )
    if ([string]::IsNullOrWhiteSpace($RawPath)) {
        throw "$Context path must be non-empty."
    }
    $resolved = Expand-BoxPath -RawPath $RawPath -BaseDir $BaseDir
    if (-not (Test-Path -LiteralPath $resolved -PathType Leaf)) {
        throw "$Context file not found: '$resolved'."
    }
    if ($AsBytes) {
        return [System.IO.File]::ReadAllBytes($resolved)
    }
    $text = [System.IO.File]::ReadAllText($resolved, [System.Text.Encoding]::UTF8)
    # Strip optional UTF-8 BOM and normalize CRLF -> LF
    if ($text.Length -gt 0 -and $text[0] -eq [char]0xFEFF) {
        $text = $text.Substring(1)
    }
    return (($text -replace "`r`n", "`n") -replace "`r", "`n")
}

$script:VaultResolverHook = $null
$script:CurrentServiceVaultSources = $null

function Invoke-VaultCliProcess {
    param(
        [Parameter(Mandatory)][string]$FileName,
        [Parameter(Mandatory)][string[]]$Arguments,
        [Parameter(Mandatory)][string]$Context,
        [Parameter(Mandatory)][string]$Uri
    )
    $cmd = Get-Command $FileName -ErrorAction SilentlyContinue
    if (-not $cmd) {
        throw "${Context}: CLI '$FileName' not found on Windows PATH to resolve '$Uri'."
    }
    $psi = New-Object System.Diagnostics.ProcessStartInfo
    $psi.FileName = $cmd.Source
    $quotedArgs = foreach ($a in $Arguments) {
        if ($a.Length -eq 0 -or $a -match '[\s"]') {
            '"' + ($a -replace '(\\*)"', '$1$1\"' -replace '(\\+)$', '$1$1') + '"'
        } else {
            $a
        }
    }
    $psi.Arguments = ($quotedArgs -join ' ')
    $psi.UseShellExecute = $false
    $psi.RedirectStandardOutput = $true
    $psi.RedirectStandardError = $true
    $psi.CreateNoWindow = $true

    $proc = [System.Diagnostics.Process]::Start($psi)
    try {
        $stdoutTask = $proc.StandardOutput.ReadToEndAsync()
        $stderrTask = $proc.StandardError.ReadToEndAsync()
        $proc.WaitForExit()
        $stdout = $stdoutTask.GetAwaiter().GetResult()
        $stderr = $stderrTask.GetAwaiter().GetResult()
        if ($proc.ExitCode -ne 0) {
            $errLine = (($stderr -split '\r?\n' | Where-Object { -not [string]::IsNullOrWhiteSpace($_) } | Select-Object -First 1) -join '').Trim()
            $suffix = if ($errLine) { ": $errLine" } else { " (exit code $($proc.ExitCode))" }
            throw "${Context}: '$FileName' lookup failed for '$Uri'${suffix}"
        }
        $val = if ($null -ne $stdout) { $stdout.Trim() } else { '' }
        if ([string]::IsNullOrWhiteSpace($val)) {
            throw "${Context}: '$FileName' returned an empty secret for '$Uri'."
        }
        return $val
    } finally {
        $proc.Dispose()
    }
}

function Resolve-VaultSecretUri {
    param(
        [Parameter(Mandatory)][string]$Uri,
        [Parameter(Mandatory)][string]$BaseDir,
        [Parameter(Mandatory)][string]$Context
    )
    if ($Uri.Contains("`0") -or $Uri.Contains("`r") -or $Uri.Contains("`n")) {
        throw "${Context}: vault URI contains invalid newline or control characters."
    }
    if ($Uri -notmatch '^([a-zA-Z][a-zA-Z0-9+.-]*)://(.+)$') {
        throw "${Context}: invalid vault URI '$Uri'. Expected scheme like op://, bw://, dpapi://, azkv://, awssm://, or gcpsm://."
    }
    $scheme = $Matches[1].ToLowerInvariant()
    $target = $Matches[2].Trim()
    if ([string]::IsNullOrWhiteSpace($target) -or $target.StartsWith('-')) {
        throw "${Context}: invalid vault URI target in '$Uri' (target must be non-empty and cannot start with '-')."
    }

    switch ($scheme) {
        'op' {
            $opSegments = @($target.Trim('/') -split '/')
            if ($opSegments.Count -lt 2 -or ($opSegments | Where-Object { [string]::IsNullOrWhiteSpace($_) -or $_.StartsWith('-') })) {
                throw "${Context}: op:// URI must be op://<vault>/<item>[/<section>]/<field> with non-empty segments."
            }
        }
        'bw' {
            # Validated non-empty and non-flag above
        }
        'dpapi' {
            # Validated non-empty above
        }
        'azkv' {
            $parts = $target -split '/', 2
            if ($parts.Count -ne 2 -or [string]::IsNullOrWhiteSpace($parts[0]) -or [string]::IsNullOrWhiteSpace($parts[1]) -or
                $parts[0].StartsWith('-') -or $parts[1].StartsWith('-') -or $parts[1].Contains('/')) {
                throw "${Context}: azkv:// URI must be azkv://<vault>/<secret> with non-empty vault and secret names."
            }
        }
        'awssm' {
            # Validated non-empty and non-flag above
        }
        'gcpsm' {
            $parts = $target -split '/', 2
            if ($parts.Count -ne 2 -or [string]::IsNullOrWhiteSpace($parts[0]) -or [string]::IsNullOrWhiteSpace($parts[1]) -or
                $parts[0].StartsWith('-') -or $parts[1].StartsWith('-') -or $parts[1].Contains('/')) {
                throw "${Context}: gcpsm:// URI must be gcpsm://<project>/<secret> with non-empty project and secret names."
            }
        }
        default {
            throw "${Context}: unsupported vault URI scheme '${scheme}://' in '$Uri'."
        }
    }

    if ($null -ne $script:CurrentServiceVaultSources) {
        $schemeTag = "${scheme}://"
        if (-not $script:CurrentServiceVaultSources.Contains($schemeTag)) {
            $script:CurrentServiceVaultSources.Add($schemeTag)
        }
    }

    if ($null -ne $script:VaultResolverHook) {
        $hookVal = [string](& $script:VaultResolverHook $Uri $BaseDir $Context)
        if ([string]::IsNullOrWhiteSpace($hookVal)) {
            throw "${Context}: vault resolver returned an empty secret for '$Uri'."
        }
        return $hookVal
    }

    switch ($scheme) {
        'op' {
            return (Invoke-VaultCliProcess -FileName 'op' -Arguments @('read', $Uri) -Context $Context -Uri $Uri)
        }
        'bw' {
            return (Invoke-VaultCliProcess -FileName 'bw' -Arguments @('get', 'password', '--', $target) -Context $Context -Uri $Uri)
        }
        'dpapi' {
            if (-not ('System.Security.Cryptography.ProtectedData' -as [type])) {
                try { Add-Type -AssemblyName 'System.Security' -ErrorAction Stop } catch { Write-Verbose $_.Exception.Message }
            }
            if (-not ('System.Security.Cryptography.ProtectedData' -as [type])) {
                try { Add-Type -AssemblyName 'System.Security.Cryptography.ProtectedData' -ErrorAction Stop } catch { Write-Verbose $_.Exception.Message }
            }
            if (-not ('System.Security.Cryptography.ProtectedData' -as [type])) {
                throw "${Context}: System.Security.Cryptography.ProtectedData is unavailable in this PowerShell runtime."
            }
            $filePath = Expand-BoxPath -RawPath $target -BaseDir $BaseDir
            if (-not (Test-Path -LiteralPath $filePath -PathType Leaf)) {
                throw "${Context}: DPAPI secret file not found: '$filePath'."
            }
            $encBytes = [System.IO.File]::ReadAllBytes($filePath)
            $decBytes = [System.Security.Cryptography.ProtectedData]::Unprotect($encBytes, $null, [System.Security.Cryptography.DataProtectionScope]::CurrentUser)
            $val = [System.Text.Encoding]::UTF8.GetString($decBytes).Trim()
            if ([string]::IsNullOrWhiteSpace($val)) {
                throw "${Context}: DPAPI secret file '$filePath' decrypted to an empty value."
            }
            return $val
        }
        'azkv' {
            $parts = $target -split '/', 2
            return (Invoke-VaultCliProcess -FileName 'az' -Arguments @('keyvault', 'secret', 'show', '--vault-name', $parts[0], '--name', $parts[1], '--query', 'value', '-o', 'tsv') -Context $Context -Uri $Uri)
        }
        'awssm' {
            return (Invoke-VaultCliProcess -FileName 'aws' -Arguments @('secretsmanager', 'get-secret-value', '--secret-id', $target, '--query', 'SecretString', '--output', 'text') -Context $Context -Uri $Uri)
        }
        'gcpsm' {
            $parts = $target -split '/', 2
            return (Invoke-VaultCliProcess -FileName 'gcloud' -Arguments @('secrets', 'versions', 'access', 'latest', "--project=$($parts[0])", "--secret=$($parts[1])") -Context $Context -Uri $Uri)
        }
    }
}

function Resolve-SecretValue {
    param(
        [Parameter(Mandatory)]$Object,
        [Parameter(Mandatory)][string]$BaseName,
        [Parameter(Mandatory)][string]$BaseDir,
        [Parameter(Mandatory)][string]$Context,
        [switch]$Required
    )
    $fileProp = "${BaseName}File"
    $envProp = "${BaseName}Env"
    $vaultProp = "${BaseName}Vault"

    $hasDirect = (Test-ObjectHasProperty -Object $Object -Name $BaseName) -and -not [string]::IsNullOrEmpty([string](Get-ObjectProperty -Object $Object -Name $BaseName -Default ''))
    $hasFile = (Test-ObjectHasProperty -Object $Object -Name $fileProp) -and -not [string]::IsNullOrWhiteSpace([string](Get-ObjectProperty -Object $Object -Name $fileProp -Default ''))
    $hasEnv = (Test-ObjectHasProperty -Object $Object -Name $envProp) -and -not [string]::IsNullOrWhiteSpace([string](Get-ObjectProperty -Object $Object -Name $envProp -Default ''))
    $hasVault = (Test-ObjectHasProperty -Object $Object -Name $vaultProp) -and -not [string]::IsNullOrWhiteSpace([string](Get-ObjectProperty -Object $Object -Name $vaultProp -Default ''))

    $sourceCount = @($hasDirect, $hasFile, $hasEnv, $hasVault | Where-Object { $_ }).Count
    if ($sourceCount -gt 1) {
        throw "${Context}: specify only one of '$BaseName', '$fileProp', '$envProp', or '$vaultProp'."
    }
    if ($sourceCount -eq 0) {
        if ($Required) {
            throw "${Context}: missing required secret ('$BaseName', '$fileProp', '$envProp', or '$vaultProp')."
        }
        return ''
    }

    if ($hasVault) {
        $uri = [string](Get-ObjectProperty -Object $Object -Name $vaultProp)
        return (Resolve-VaultSecretUri -Uri $uri -BaseDir $BaseDir -Context "${Context}.${vaultProp}")
    }

    if ($hasDirect) {
        $val = [string](Get-ObjectProperty -Object $Object -Name $BaseName)
        if ([string]::IsNullOrWhiteSpace($val)) {
            throw "${Context}: '$BaseName' cannot be empty or whitespace."
        }
        return $val
    }
    if ($hasFile) {
        $rawPath = [string](Get-ObjectProperty -Object $Object -Name $fileProp)
        $text = (Resolve-SecretFileContent -RawPath $rawPath -BaseDir $BaseDir -Context "${Context}.${fileProp}").Trim()
        if ([string]::IsNullOrWhiteSpace($text)) {
            throw "${Context}: file referenced by '$fileProp' is empty."
        }
        return $text
    }
    if ($hasEnv) {
        $envName = [string](Get-ObjectProperty -Object $Object -Name $envProp)
        if ($envName -notmatch '^[A-Za-z_][A-Za-z0-9_]*$') {
            throw "${Context}: invalid environment variable name '$envName' in '$envProp'."
        }
        $val = [Environment]::GetEnvironmentVariable($envName)
        if ([string]::IsNullOrWhiteSpace($val)) {
            throw "${Context}: Windows environment variable '$envName' (referenced by '$envProp') is not set or empty."
        }
        return $val
    }
    return ''
}

function Resolve-RequestedServiceFilter {
    param([string[]]$Services = @())
    if (-not $Services -or $Services.Count -eq 0) {
        return @()
    }
    $canonicalMap = @{}
    foreach ($svc in $script:SupportedSecretServices) {
        $canonicalMap[$svc.ToLowerInvariant()] = $svc
    }
    $result = New-Object System.Collections.Generic.List[string]
    foreach ($raw in $Services) {
        if ([string]::IsNullOrWhiteSpace($raw)) { continue }
        foreach ($part in ($raw -split ',')) {
            $trimmed = $part.Trim()
            if ([string]::IsNullOrWhiteSpace($trimmed)) { continue }
            $key = $trimmed.ToLowerInvariant()
            if (-not $canonicalMap.ContainsKey($key)) {
                $allowed = $script:SupportedSecretServices -join ', '
                throw "Unknown service '$trimmed'. Supported services: $allowed."
            }
            $canon = $canonicalMap[$key]
            if (-not $result.Contains($canon)) {
                $result.Add($canon)
            }
        }
    }
    return $result.ToArray()
}

function Assert-ValidHttpUrl {
    param(
        [Parameter(Mandatory)][string]$Url,
        [Parameter(Mandatory)][string]$Context
    )
    $uri = $null
    if (-not [System.Uri]::TryCreate($Url, [System.UriKind]::Absolute, [ref]$uri) -or ($uri.Scheme -notin @('http', 'https'))) {
        throw "${Context} must be a valid http:// or https:// URL."
    }
}

function Assert-SafeAgentTargetPath {
    param(
        [Parameter(Mandatory)][string]$TargetPath,
        [Parameter(Mandatory)][string]$AgentName,
        [Parameter(Mandatory)][string]$Context
    )
    $homePrefix = "/home/$AgentName"
    $normalized = $TargetPath.Trim()
    if ($normalized.StartsWith('~/')) {
        $normalized = "$homePrefix/$($normalized.Substring(2))"
    }
    if (-not $normalized.StartsWith("$homePrefix/")) {
        throw "${Context}: targetPath '$TargetPath' must be inside '$homePrefix/' (or start with '~/')."
    }
    if ($normalized.Contains("`0") -or $normalized.Contains("`n") -or $normalized.Contains("`r")) {
        throw "${Context}: targetPath contains invalid control characters."
    }
    $segments = $normalized -split '/'
    foreach ($seg in $segments) {
        if ($seg -eq '..' -or $seg -eq '.') {
            throw "${Context}: targetPath '$TargetPath' cannot contain relative segments ('.' or '..')."
        }
    }
    if ($normalized.EndsWith('/')) {
        throw "${Context}: targetPath '$TargetPath' must point to a file, not a directory."
    }
    return $normalized
}

function Resolve-SshPrivateKey {
    param(
        [Parameter(Mandatory)]$Object,
        [Parameter(Mandatory)][string]$BaseDir,
        [Parameter(Mandatory)][string]$Context,
        [switch]$Required
    )
    $raw = Resolve-SecretValue -Object $Object -BaseName 'privateKey' -BaseDir $BaseDir -Context $Context -Required:$Required
    if ([string]::IsNullOrEmpty($raw)) {
        return ''
    }
    $norm = (($raw -replace "`r`n", "`n") -replace "`r", "`n").Trim("`n", "`r", ' ', "`t") + "`n"
    if ($norm -notmatch '(?s)^-----BEGIN [A-Z0-9 ]*PRIVATE KEY-----\n.+\n-----END [A-Z0-9 ]*PRIVATE KEY-----\n$') {
        throw "${Context}: invalid SSH private key format (expected PEM or OpenSSH private key block starting with '-----BEGIN ... PRIVATE KEY-----')."
    }
    return $norm
}

function Resolve-SshPublicMaterial {
    param(
        [Parameter(Mandatory)]$Object,
        [Parameter(Mandatory)][string]$BaseName,
        [Parameter(Mandatory)][string]$BaseDir,
        [Parameter(Mandatory)][string]$Context
    )
    $raw = Resolve-SecretValue -Object $Object -BaseName $BaseName -BaseDir $BaseDir -Context $Context
    if ([string]::IsNullOrEmpty($raw)) {
        return ''
    }
    $norm = (($raw -replace "`r`n", "`n") -replace "`r", "`n").Trim()
    if ($norm -match 'PRIVATE KEY-----') {
        throw "${Context}: '$BaseName' appears to contain a private key; use 'privateKey*' instead."
    }
    if ($norm.Contains("`n")) {
        throw "${Context}: '$BaseName' must be a single-line OpenSSH public key or certificate."
    }
    return ($norm + "`n")
}

function Assert-SafeSshConfigValue {
    param(
        [Parameter(Mandatory)][string]$Value,
        [Parameter(Mandatory)][string]$Pattern,
        [Parameter(Mandatory)][string]$Context
    )
    if ($Value.Contains("`0") -or $Value.Contains("`n") -or $Value.Contains("`r")) {
        throw "${Context}: contains invalid newline or control characters."
    }
    if ($Value -notmatch $Pattern) {
        throw "${Context}: value '$Value' contains unsupported characters."
    }
}

function Add-ValidatedKnownHostLines {
    param(
        [Parameter(Mandatory)][string]$RawText,
        [Parameter(Mandatory)][string]$Context,
        [Parameter(Mandatory)][AllowEmptyCollection()][System.Collections.Generic.List[string]]$TargetList,
        [Parameter(Mandatory)][hashtable]$SeenSet
    )
    $norm = ($RawText -replace "`r`n", "`n") -replace "`r", "`n"
    foreach ($line in ($norm -split "`n")) {
        $trimmed = $line.Trim()
        if ([string]::IsNullOrWhiteSpace($trimmed) -or $trimmed.StartsWith('#')) {
            continue
        }
        if ($trimmed -match '[\x00-\x08\x0B-\x1F\x7F]') {
            throw "${Context}: known_hosts entry contains invalid control characters."
        }
        $parts = @($trimmed -split '\s+' | Where-Object { $_ -ne '' })
        if ($parts.Count -lt 3) {
            throw "${Context}: invalid known_hosts entry (expected '<host> <key-type> <base64-key>')."
        }
        if (-not $SeenSet.ContainsKey($trimmed)) {
            $SeenSet[$trimmed] = $true
            $TargetList.Add($trimmed)
        }
    }
}

function Assert-SafeGitConfigValue {
    param(
        [Parameter(Mandatory)][string]$Value,
        [Parameter(Mandatory)][string]$Context
    )
    if ($Value -match '[\x00-\x1F\x7F]') {
        throw "${Context}: contains invalid newline or control characters."
    }
}

function Add-ValidatedAllowedSignerLines {
    param(
        [Parameter(Mandatory)][string]$RawText,
        [Parameter(Mandatory)][string]$Context,
        [Parameter(Mandatory)][AllowEmptyCollection()][System.Collections.Generic.List[string]]$TargetList,
        [Parameter(Mandatory)][hashtable]$SeenSet
    )
    $norm = ($RawText -replace "`r`n", "`n") -replace "`r", "`n"
    foreach ($line in ($norm -split "`n")) {
        $trimmed = $line.Trim()
        if ([string]::IsNullOrWhiteSpace($trimmed) -or $trimmed.StartsWith('#')) {
            continue
        }
        if ($trimmed -match '[\x00-\x08\x0B-\x1F\x7F]') {
            throw "${Context}: allowed_signers entry contains invalid control characters."
        }
        if ($trimmed -match 'PRIVATE KEY-----') {
            throw "${Context}: allowed_signers entry appears to contain a private key."
        }
        $parts = @($trimmed -split '\s+' | Where-Object { $_ -ne '' })
        if ($parts.Count -lt 3) {
            throw "${Context}: invalid allowed_signers entry (expected '<principal> [options] <key-type> <base64-key>')."
        }
        if (-not $SeenSet.ContainsKey($trimmed)) {
            $SeenSet[$trimmed] = $true
            $TargetList.Add($trimmed)
        }
    }
}

function Get-ProxyPlaceholderToken {
    param([Parameter(Mandatory)][string]$ServicePrefix)
    $bytes = New-Object byte[] 24
    $rng = [System.Security.Cryptography.RandomNumberGenerator]::Create()
    try {
        $rng.GetBytes($bytes)
    } finally {
        if ($rng -is [IDisposable]) { $rng.Dispose() }
    }
    $hex = -join ($bytes | ForEach-Object { $_.ToString('x2') })
    return "sandbox-proxy-$ServicePrefix-$hex"
}

function ConvertTo-TtlSeconds {
    param([Parameter(Mandatory)][string]$Ttl)
    $trimmed = $Ttl.Trim().ToLowerInvariant()
    if ($trimmed -notmatch '^([0-9]+)\s*([smhd])$') {
        throw "Invalid -Ttl '$Ttl'. Expected duration like '30m', '2h', '1d', or '90s'."
    }
    [int64]$num = 0
    if (-not [int64]::TryParse($Matches[1], [ref]$num) -or $num -le 0) {
        throw "TTL duration must be a positive integer between 1s and 365d (got '$Ttl')."
    }
    $mult = switch ($Matches[2]) {
        's' { 1 }
        'm' { 60 }
        'h' { 3600 }
        'd' { 86400 }
    }
    $maxSeconds = [int64]31536000 # 365 days
    if ($num -gt [int64]($maxSeconds / $mult)) {
        throw "TTL duration '$Ttl' exceeds maximum allowed 365d (31536000s)."
    }
    return [int64]($num * $mult)
}

function Build-SeedSecretsPayload {
    param(
        [Parameter(Mandatory)][string]$ManifestPath,
        [Parameter(Mandatory)][string]$AgentName,
        [string[]]$Services = @(),
        [switch]$Prune,
        [string]$Ttl = ''
    )

    if (-not (Test-Path -LiteralPath $ManifestPath -PathType Leaf)) {
        throw "Secrets manifest not found at '$ManifestPath'. Create it from 'examples\secrets.example.json' (default path: %USERPROFILE%\.wsl-agent-sandbox\secrets.json) or pass -SecretsPath."
    }
    $ttlSeconds = 0
    if (-not [string]::IsNullOrWhiteSpace($Ttl)) {
        $ttlSeconds = ConvertTo-TtlSeconds -Ttl $Ttl
    }

    $rawJson = Get-Content -LiteralPath $ManifestPath -Raw -Encoding UTF8
    try {
        $manifest = $rawJson | ConvertFrom-Json
    } catch {
        throw "Failed to parse JSON in secrets manifest '$ManifestPath': $($_.Exception.Message)"
    }
    if ($null -eq $manifest) {
        throw "Secrets manifest '$ManifestPath' is empty."
    }

    $baseDir = Split-Path -Parent ([System.IO.Path]::GetFullPath($ManifestPath))

    # Reject unknown top-level keys to catch typos early
    foreach ($key in (Get-ObjectPropertyNames -Object $manifest)) {
        if ($key -eq '$schema') { continue }
        if ($key -notin $script:SupportedSecretServices) {
            $allowed = $script:SupportedSecretServices -join ', '
            throw "Unknown top-level service '$key' in '$ManifestPath'. Supported services: $allowed."
        }
    }

    $filterServices = @(Resolve-RequestedServiceFilter -Services $Services)
    $resolvedServices = [ordered]@{}
    $proxyRoutes = [ordered]@{}
    $serviceTtls = [ordered]@{}
    $summary = New-Object System.Collections.Generic.List[string]
    $skippedDisabled = New-Object System.Collections.Generic.List[string]

    $servicesToInspect = if ($filterServices.Count -gt 0) { $filterServices } else { $script:SupportedSecretServices }

    foreach ($svcName in $servicesToInspect) {
        if (-not (Test-ObjectHasProperty -Object $manifest -Name $svcName)) {
            if ($filterServices.Count -gt 0) {
                throw "Requested service '$svcName' is not configured in '$ManifestPath'."
            }
            continue
        }
        $entry = Get-ObjectProperty -Object $manifest -Name $svcName
        if ($null -eq $entry) { continue }

        # Check 'enabled' flag on object services
        if ($svcName -notin @('env', 'files')) {
            $enabled = [bool](Get-ObjectProperty -Object $entry -Name 'enabled' -Default $true)
            if (-not $enabled) {
                $skippedDisabled.Add($svcName)
                continue
            }
        }

        $summaryCountBefore = $summary.Count
        $script:CurrentServiceVaultSources = New-Object System.Collections.Generic.List[string]
        switch ($svcName) {
            'github' {
                $hostname = [string](Get-ObjectProperty -Object $entry -Name 'hostname' -Default 'github.com')
                if ($hostname -notmatch '^[A-Za-z0-9.-]+$') {
                    throw "github.hostname '$hostname' is invalid."
                }
                $gitProtocol = [string](Get-ObjectProperty -Object $entry -Name 'gitProtocol' -Default 'https')
                if ($gitProtocol -notin @('https', 'ssh')) {
                    throw "github.gitProtocol must be 'https' or 'ssh'."
                }
                $token = Resolve-SecretValue -Object $entry -BaseName 'token' -BaseDir $baseDir -Context 'github' -Required
                $user = [string](Get-ObjectProperty -Object $entry -Name 'user' -Default '')
                $setupGit = [bool](Get-ObjectProperty -Object $entry -Name 'setupGit' -Default $true)
                $exportEnv = [bool](Get-ObjectProperty -Object $entry -Name 'exportEnv' -Default $true)
                $loginOnline = [bool](Get-ObjectProperty -Object $entry -Name 'loginOnline' -Default $false)
                $proxyInject = [bool](Get-ObjectProperty -Object $entry -Name 'proxyInject' -Default $false)
                $agentToken = $token
                $proxyBaseUrl = ''
                if ($proxyInject) {
                    $upstreamUrl = if ($hostname -eq 'github.com') { 'https://api.github.com' } else { "https://$hostname/api/v3" }
                    $agentToken = Get-ProxyPlaceholderToken -ServicePrefix 'github'
                    $proxyBaseUrl = 'http://127.0.0.1:3129/github'
                    $proxyRoutes['github'] = [ordered]@{
                        upstreamBaseUrl = $upstreamUrl
                        expectedToken   = $agentToken
                        injectHeaders   = [ordered]@{ Authorization = "Bearer $token" }
                    }
                }

                $resolvedServices['github'] = [ordered]@{
                    hostname     = $hostname
                    token        = $agentToken
                    user         = $user
                    gitProtocol  = $gitProtocol
                    setupGit     = $setupGit
                    exportEnv    = $exportEnv
                    loginOnline  = $loginOnline
                    proxyBaseUrl = $proxyBaseUrl
                }
                $summary.Add("github (host=$hostname, setupGit=$setupGit, exportEnv=$exportEnv)")
            }

            'git' {
                $keysOut = New-Object System.Collections.Generic.List[object]
                $seenKeys = @{}
                $hostsOut = New-Object System.Collections.Generic.List[object]
                $seenHosts = @{}
                $knownHostsList = New-Object System.Collections.Generic.List[string]
                $seenKnownHosts = @{}

                $userName = [string](Get-ObjectProperty -Object $entry -Name 'userName' -Default '')
                if (-not [string]::IsNullOrWhiteSpace($userName)) {
                    Assert-SafeGitConfigValue -Value $userName -Context 'git.userName'
                }
                $userEmail = [string](Get-ObjectProperty -Object $entry -Name 'userEmail' -Default '')
                if (-not [string]::IsNullOrWhiteSpace($userEmail)) {
                    Assert-SafeGitConfigValue -Value $userEmail -Context 'git.userEmail'
                }

                $defaultUser = [string](Get-ObjectProperty -Object $entry -Name 'user' -Default 'git')
                if ([string]::IsNullOrWhiteSpace($defaultUser)) {
                    $defaultUser = 'git'
                }
                Assert-SafeSshConfigValue -Value $defaultUser -Pattern '^[A-Za-z0-9._@+-]+$' -Context 'git.user'

                $globalRewriteHttps = [bool](Get-ObjectProperty -Object $entry -Name 'rewriteHttpsToSsh' -Default $false)
                $strictHostKeyChecking = [string](Get-ObjectProperty -Object $entry -Name 'strictHostKeyChecking' -Default '')
                if (-not [string]::IsNullOrWhiteSpace($strictHostKeyChecking) -and $strictHostKeyChecking -notin @('yes', 'accept-new', 'no')) {
                    throw "git.strictHostKeyChecking '$strictHostKeyChecking' must be 'yes', 'accept-new', or 'no'."
                }
                $identitiesOnly = [bool](Get-ObjectProperty -Object $entry -Name 'identitiesOnly' -Default $true)
                $forwardAgent = [bool](Get-ObjectProperty -Object $entry -Name 'forwardAgent' -Default $false)

                $serverAliveInterval = Get-ObjectProperty -Object $entry -Name 'serverAliveInterval' -Default $null
                if ($null -ne $serverAliveInterval) {
                    $aliveVal = [int]$serverAliveInterval
                    if ($aliveVal -lt 0 -or $aliveVal -gt 3600) {
                        throw "git.serverAliveInterval ($aliveVal) must be between 0 and 3600."
                    }
                    $serverAliveInterval = $aliveVal
                }

                $connectTimeout = Get-ObjectProperty -Object $entry -Name 'connectTimeout' -Default $null
                if ($null -ne $connectTimeout) {
                    $toVal = [int]$connectTimeout
                    if ($toVal -lt 1 -or $toVal -gt 600) {
                        throw "git.connectTimeout ($toVal) must be between 1 and 600."
                    }
                    $connectTimeout = $toVal
                }

                $batchMode = $true
                if (Test-ObjectHasProperty -Object $entry -Name 'batchMode') {
                    $bmRaw = Get-ObjectProperty -Object $entry -Name 'batchMode' -Default $null
                    if ($null -ne $bmRaw) {
                        $batchMode = [bool]$bmRaw
                    }
                }

                # 1. Top-level shorthand key vs named keys[]
                $topPriv = Resolve-SshPrivateKey -Object $entry -BaseDir $baseDir -Context 'git'
                $topPub = Resolve-SshPublicMaterial -Object $entry -BaseName 'publicKey' -BaseDir $baseDir -Context 'git'
                $topCert = Resolve-SshPublicMaterial -Object $entry -BaseName 'certificate' -BaseDir $baseDir -Context 'git'
                $hasTopPriv = -not [string]::IsNullOrWhiteSpace($topPriv)

                if ((-not $hasTopPriv) -and ((-not [string]::IsNullOrWhiteSpace($topPub)) -or (-not [string]::IsNullOrWhiteSpace($topCert)))) {
                    throw "git: top-level 'publicKey*' and 'certificate*' require top-level 'privateKey*' (or configure them on a key in git.keys)."
                }

                $rawKeys = Get-ObjectProperty -Object $entry -Name 'keys' -Default $null
                $hasRawKeys = ($null -ne $rawKeys -and @($rawKeys).Count -gt 0)
                if ($hasTopPriv -and $hasRawKeys) {
                    throw "git: specify either top-level 'privateKey*' shorthand or 'keys', not both."
                }

                $defaultKey = [string](Get-ObjectProperty -Object $entry -Name 'defaultKey' -Default '')
                if ($hasTopPriv) {
                    if (-not [string]::IsNullOrWhiteSpace($defaultKey)) {
                        throw "git: cannot specify both top-level 'privateKey*' shorthand and 'defaultKey'."
                    }
                    $seenKeys['default'] = 'default'
                    $keysOut.Add([ordered]@{
                        name        = 'default'
                        privateKey  = $topPriv
                        publicKey   = $topPub
                        certificate = $topCert
                    })
                    $defaultKey = 'default'
                } elseif ($null -ne $rawKeys) {
                    foreach ($k in @($rawKeys)) {
                        if ($null -eq $k) { continue }
                        $kName = [string](Get-ObjectProperty -Object $k -Name 'name' -Default '')
                        if ($kName -notmatch '^[A-Za-z0-9][A-Za-z0-9._-]{0,62}$') {
                            throw "git.keys entry has invalid name '$kName'."
                        }
                        if ($kName -in @('known_hosts', 'config', 'allowed_signers')) {
                            throw "git.keys entry name '$kName' is reserved."
                        }
                        if ($seenKeys.ContainsKey($kName.ToLowerInvariant())) {
                            throw "git.keys contains duplicate key name '$kName'."
                        }
                        $seenKeys[$kName.ToLowerInvariant()] = $kName
                        $privKey = Resolve-SshPrivateKey -Object $k -BaseDir $baseDir -Context "git.keys[$kName]" -Required
                        $pubKey = Resolve-SshPublicMaterial -Object $k -BaseName 'publicKey' -BaseDir $baseDir -Context "git.keys[$kName]"
                        $cert = Resolve-SshPublicMaterial -Object $k -BaseName 'certificate' -BaseDir $baseDir -Context "git.keys[$kName]"
                        $keysOut.Add([ordered]@{
                            name        = $kName
                            privateKey  = $privKey
                            publicKey   = $pubKey
                            certificate = $cert
                        })
                    }
                    if (-not [string]::IsNullOrWhiteSpace($defaultKey)) {
                        if (-not $seenKeys.ContainsKey($defaultKey.ToLowerInvariant())) {
                            throw "git.defaultKey '$defaultKey' does not match any key defined in git.keys."
                        }
                        $defaultKey = $seenKeys[$defaultKey.ToLowerInvariant()]
                    }
                } elseif (-not [string]::IsNullOrWhiteSpace($defaultKey)) {
                    throw "git.defaultKey '$defaultKey' does not match any key defined in git.keys."
                }

                # 2. Top-level knownHosts & knownHostsFile
                $rawKnownHosts = Get-ObjectProperty -Object $entry -Name 'knownHosts' -Default $null
                if ($null -ne $rawKnownHosts) {
                    foreach ($kh in @($rawKnownHosts)) {
                        if ($null -eq $kh) { continue }
                        Add-ValidatedKnownHostLines -RawText ([string]$kh) -Context 'git.knownHosts' -TargetList $knownHostsList -SeenSet $seenKnownHosts
                    }
                }
                $knownHostsFile = [string](Get-ObjectProperty -Object $entry -Name 'knownHostsFile' -Default '')
                if (-not [string]::IsNullOrWhiteSpace($knownHostsFile)) {
                    $khContent = Resolve-SecretFileContent -RawPath $knownHostsFile -BaseDir $baseDir -Context 'git.knownHostsFile'
                    Add-ValidatedKnownHostLines -RawText $khContent -Context 'git.knownHostsFile' -TargetList $knownHostsList -SeenSet $seenKnownHosts
                }

                # 3. Git SSH hosts (shorthand host + privateKey* OR structured hosts[])
                $hasExplicitHost = Test-ObjectHasProperty -Object $entry -Name 'host'
                $hasExplicitPort = Test-ObjectHasProperty -Object $entry -Name 'port'
                $rawHosts = Get-ObjectProperty -Object $entry -Name 'hosts' -Default $null
                $hasRawHosts = ($null -ne $rawHosts -and @($rawHosts).Count -gt 0)

                if ($hasExplicitHost -and $hasRawHosts) {
                    throw "git: specify either top-level 'host' shorthand or 'hosts', not both."
                }
                if ($hasExplicitPort -and $hasRawHosts) {
                    throw "git: specify either top-level 'port' shorthand or 'hosts', not both."
                }

                if ($hasRawHosts) {
                    foreach ($h in @($rawHosts)) {
                        if ($null -eq $h) { continue }
                        $hName = [string](Get-ObjectProperty -Object $h -Name 'name' -Default '')
                        if ([string]::IsNullOrWhiteSpace($hName)) {
                            throw "git.hosts entry is missing required 'name'."
                        }
                        Assert-SafeSshConfigValue -Value $hName -Pattern '^[A-Za-z0-9._*?@:-]+$' -Context "git.hosts[$hName].name"
                        if ($hName -eq '*') {
                            throw "git.hosts entry name cannot be '*' (specify explicit Git hostnames or aliases such as 'github.com')."
                        }
                        if ($seenHosts.ContainsKey($hName.ToLowerInvariant())) {
                            throw "git.hosts contains duplicate host name '$hName'."
                        }
                        $seenHosts[$hName.ToLowerInvariant()] = $true

                        $hostName = [string](Get-ObjectProperty -Object $h -Name 'hostName' -Default '')
                        if ([string]::IsNullOrWhiteSpace($hostName)) {
                            $hostName = $hName
                        }
                        Assert-SafeSshConfigValue -Value $hostName -Pattern '^[A-Za-z0-9._:%\[\]-]+$' -Context "git.hosts[$hName].hostName"

                        $hUser = [string](Get-ObjectProperty -Object $h -Name 'user' -Default '')
                        if ([string]::IsNullOrWhiteSpace($hUser)) {
                            $hUser = $defaultUser
                        }
                        Assert-SafeSshConfigValue -Value $hUser -Pattern '^[A-Za-z0-9._@+-]+$' -Context "git.hosts[$hName].user"

                        $hPort = $null
                        if (Test-ObjectHasProperty -Object $h -Name 'port') {
                            $pRaw = Get-ObjectProperty -Object $h -Name 'port' -Default $null
                            if ($null -ne $pRaw) {
                                $pInt = [int]$pRaw
                                if ($pInt -lt 1 -or $pInt -gt 65535) {
                                    throw "git.hosts[$hName].port ($pInt) must be between 1 and 65535."
                                }
                                $hPort = $pInt
                            }
                        }

                        $hKeyRef = [string](Get-ObjectProperty -Object $h -Name 'key' -Default '')
                        $hInlinePriv = Resolve-SshPrivateKey -Object $h -BaseDir $baseDir -Context "git.hosts[$hName]"
                        $hInlinePub = Resolve-SshPublicMaterial -Object $h -BaseName 'publicKey' -BaseDir $baseDir -Context "git.hosts[$hName]"
                        $hInlineCert = Resolve-SshPublicMaterial -Object $h -BaseName 'certificate' -BaseDir $baseDir -Context "git.hosts[$hName]"

                        $hasKeyRef = -not [string]::IsNullOrWhiteSpace($hKeyRef)
                        $hasInlinePriv = -not [string]::IsNullOrWhiteSpace($hInlinePriv)

                        if ($hasKeyRef -and $hasInlinePriv) {
                            throw "git.hosts[$hName]: specify either 'key' or 'privateKey*', not both."
                        }
                        if ((-not $hasInlinePriv) -and ((-not [string]::IsNullOrWhiteSpace($hInlinePub)) -or (-not [string]::IsNullOrWhiteSpace($hInlineCert)))) {
                            throw "git.hosts[$hName]: 'publicKey*' and 'certificate*' on a host require an inline 'privateKey*' (or configure them on the named key in git.keys)."
                        }

                        $resolvedKeyName = ''
                        if ($hasKeyRef) {
                            if (-not $seenKeys.ContainsKey($hKeyRef.ToLowerInvariant())) {
                                throw "git.hosts[$hName].key '$hKeyRef' does not match any key defined in git.keys."
                            }
                            $resolvedKeyName = $seenKeys[$hKeyRef.ToLowerInvariant()]
                        } elseif ($hasInlinePriv) {
                            $safeBase = 'host-' + (($hName -replace '[^A-Za-z0-9._-]', '_').Trim('_'))
                            if ($safeBase.Length -gt 55) {
                                $safeBase = $safeBase.Substring(0, 55)
                            }
                            $candidate = $safeBase
                            $suffix = 2
                            while ($seenKeys.ContainsKey($candidate.ToLowerInvariant())) {
                                $candidate = "${safeBase}-${suffix}"
                                $suffix++
                            }
                            $seenKeys[$candidate.ToLowerInvariant()] = $candidate
                            $keysOut.Add([ordered]@{
                                name        = $candidate
                                privateKey  = $hInlinePriv
                                publicKey   = $hInlinePub
                                certificate = $hInlineCert
                            })
                            $resolvedKeyName = $candidate
                        } elseif (-not [string]::IsNullOrWhiteSpace($defaultKey)) {
                            $resolvedKeyName = $defaultKey
                        }

                        $hProxyJump = [string](Get-ObjectProperty -Object $h -Name 'proxyJump' -Default '')
                        if (-not [string]::IsNullOrWhiteSpace($hProxyJump)) {
                            Assert-SafeSshConfigValue -Value $hProxyJump -Pattern '^[A-Za-z0-9._@:%\[\],-]+$' -Context "git.hosts[$hName].proxyJump"
                        }

                        $hShkc = [string](Get-ObjectProperty -Object $h -Name 'strictHostKeyChecking' -Default '')
                        if (-not [string]::IsNullOrWhiteSpace($hShkc) -and $hShkc -notin @('yes', 'accept-new', 'no')) {
                            throw "git.hosts[$hName].strictHostKeyChecking '$hShkc' must be 'yes', 'accept-new', or 'no'."
                        }

                        $hIdentitiesOnly = $null
                        if (Test-ObjectHasProperty -Object $h -Name 'identitiesOnly') {
                            $v = Get-ObjectProperty -Object $h -Name 'identitiesOnly' -Default $null
                            if ($null -ne $v) { $hIdentitiesOnly = [bool]$v }
                        }

                        $hForwardAgent = $null
                        if (Test-ObjectHasProperty -Object $h -Name 'forwardAgent') {
                            $v = Get-ObjectProperty -Object $h -Name 'forwardAgent' -Default $null
                            if ($null -ne $v) { $hForwardAgent = [bool]$v }
                        }

                        $hAlive = $null
                        if (Test-ObjectHasProperty -Object $h -Name 'serverAliveInterval') {
                            $v = Get-ObjectProperty -Object $h -Name 'serverAliveInterval' -Default $null
                            if ($null -ne $v) {
                                $aInt = [int]$v
                                if ($aInt -lt 0 -or $aInt -gt 3600) {
                                    throw "git.hosts[$hName].serverAliveInterval ($aInt) must be between 0 and 3600."
                                }
                                $hAlive = $aInt
                            }
                        }

                        $hTimeout = $null
                        if (Test-ObjectHasProperty -Object $h -Name 'connectTimeout') {
                            $v = Get-ObjectProperty -Object $h -Name 'connectTimeout' -Default $null
                            if ($null -ne $v) {
                                $tInt = [int]$v
                                if ($tInt -lt 1 -or $tInt -gt 600) {
                                    throw "git.hosts[$hName].connectTimeout ($tInt) must be between 1 and 600."
                                }
                                $hTimeout = $tInt
                            }
                        }

                        $hBatch = $null
                        if (Test-ObjectHasProperty -Object $h -Name 'batchMode') {
                            $v = Get-ObjectProperty -Object $h -Name 'batchMode' -Default $null
                            if ($null -ne $v) { $hBatch = [bool]$v }
                        }

                        $hRewrite = $globalRewriteHttps
                        if (Test-ObjectHasProperty -Object $h -Name 'rewriteHttpsToSsh') {
                            $v = Get-ObjectProperty -Object $h -Name 'rewriteHttpsToSsh' -Default $null
                            if ($null -ne $v) { $hRewrite = [bool]$v }
                        }
                        if ($hRewrite -and ($hName.Contains('*') -or $hName.Contains('?'))) {
                            throw "git.hosts[$hName]: 'rewriteHttpsToSsh' cannot be used with wildcard host patterns."
                        }

                        $hHasPinnedKh = $false
                        $hKnownHost = [string](Get-ObjectProperty -Object $h -Name 'knownHost' -Default '')
                        if (-not [string]::IsNullOrWhiteSpace($hKnownHost)) {
                            Add-ValidatedKnownHostLines -RawText $hKnownHost -Context "git.hosts[$hName].knownHost" -TargetList $knownHostsList -SeenSet $seenKnownHosts
                            $hHasPinnedKh = $true
                        }
                        $hKnownHostFile = [string](Get-ObjectProperty -Object $h -Name 'knownHostFile' -Default '')
                        if (-not [string]::IsNullOrWhiteSpace($hKnownHostFile)) {
                            $hkhContent = Resolve-SecretFileContent -RawPath $hKnownHostFile -BaseDir $baseDir -Context "git.hosts[$hName].knownHostFile"
                            Add-ValidatedKnownHostLines -RawText $hkhContent -Context "git.hosts[$hName].knownHostFile" -TargetList $knownHostsList -SeenSet $seenKnownHosts
                            $hHasPinnedKh = $true
                        }

                        $hostsOut.Add([ordered]@{
                            name                  = $hName
                            hostName              = $hostName
                            user                  = $hUser
                            port                  = $hPort
                            key                   = $resolvedKeyName
                            proxyJump             = $hProxyJump
                            identitiesOnly        = $hIdentitiesOnly
                            forwardAgent          = $hForwardAgent
                            strictHostKeyChecking = $hShkc
                            serverAliveInterval   = $hAlive
                            connectTimeout        = $hTimeout
                            batchMode             = $hBatch
                            rewriteHttpsToSsh     = $hRewrite
                            hasPinnedKnownHost    = $hHasPinnedKh
                        })
                    }
                } elseif ($hasTopPriv -or $hasExplicitHost) {
                    $shorthandHost = [string](Get-ObjectProperty -Object $entry -Name 'host' -Default 'github.com')
                    if ([string]::IsNullOrWhiteSpace($shorthandHost)) {
                        $shorthandHost = 'github.com'
                    }
                    Assert-SafeSshConfigValue -Value $shorthandHost -Pattern '^[A-Za-z0-9._-]+$' -Context 'git.host'
                    $shorthandPort = $null
                    if ($hasExplicitPort) {
                        $pRaw = Get-ObjectProperty -Object $entry -Name 'port' -Default $null
                        if ($null -ne $pRaw) {
                            $pInt = [int]$pRaw
                            if ($pInt -lt 1 -or $pInt -gt 65535) {
                                throw "git.port ($pInt) must be between 1 and 65535."
                            }
                            $shorthandPort = $pInt
                        }
                    }
                    $hostsOut.Add([ordered]@{
                        name                  = $shorthandHost
                        hostName              = $shorthandHost
                        user                  = $defaultUser
                        port                  = $shorthandPort
                        key                   = $defaultKey
                        proxyJump             = ''
                        identitiesOnly        = $null
                        forwardAgent          = $null
                        strictHostKeyChecking = ''
                        serverAliveInterval   = $null
                        connectTimeout        = $null
                        batchMode             = $null
                        rewriteHttpsToSsh     = $globalRewriteHttps
                        hasPinnedKnownHost    = $false
                    })
                }

                # 4. Optional SSH commit/tag signing
                $signingOut = $null
                if (Test-ObjectHasProperty -Object $entry -Name 'signing') {
                    $sObj = Get-ObjectProperty -Object $entry -Name 'signing' -Default $null
                    if ($null -ne $sObj) {
                        $sEnabled = [bool](Get-ObjectProperty -Object $sObj -Name 'enabled' -Default $true)
                        if ($sEnabled) {
                            $sKeyRef = [string](Get-ObjectProperty -Object $sObj -Name 'key' -Default '')
                            $sInlinePriv = Resolve-SshPrivateKey -Object $sObj -BaseDir $baseDir -Context 'git.signing'
                            $sInlinePub = Resolve-SshPublicMaterial -Object $sObj -BaseName 'publicKey' -BaseDir $baseDir -Context 'git.signing'
                            $hasSKeyRef = -not [string]::IsNullOrWhiteSpace($sKeyRef)
                            $hasSInlinePriv = -not [string]::IsNullOrWhiteSpace($sInlinePriv)

                            if ($hasSKeyRef -and $hasSInlinePriv) {
                                throw "git.signing: specify either 'key' or 'privateKey*', not both."
                            }
                            if ((-not $hasSInlinePriv) -and (-not [string]::IsNullOrWhiteSpace($sInlinePub))) {
                                throw "git.signing: 'publicKey*' requires an inline 'privateKey*' (or configure it on the referenced key in git.keys)."
                            }

                            $resolvedSigningKey = ''
                            if ($hasSKeyRef) {
                                if (-not $seenKeys.ContainsKey($sKeyRef.ToLowerInvariant())) {
                                    throw "git.signing.key '$sKeyRef' does not match any key defined in git.keys."
                                }
                                $resolvedSigningKey = $seenKeys[$sKeyRef.ToLowerInvariant()]
                            } elseif ($hasSInlinePriv) {
                                $candidate = 'signing'
                                $suffix = 2
                                while ($seenKeys.ContainsKey($candidate.ToLowerInvariant())) {
                                    $candidate = "signing-${suffix}"
                                    $suffix++
                                }
                                $seenKeys[$candidate.ToLowerInvariant()] = $candidate
                                $keysOut.Add([ordered]@{
                                    name        = $candidate
                                    privateKey  = $sInlinePriv
                                    publicKey   = $sInlinePub
                                    certificate = ''
                                })
                                $resolvedSigningKey = $candidate
                            } elseif (-not [string]::IsNullOrWhiteSpace($defaultKey)) {
                                $resolvedSigningKey = $defaultKey
                            } else {
                                throw "git.signing: specify 'key' (referencing git.keys) or 'privateKey*'."
                            }

                            $allowedSignersList = New-Object System.Collections.Generic.List[string]
                            $seenSigners = @{}
                            $rawSigners = Get-ObjectProperty -Object $sObj -Name 'allowedSigners' -Default $null
                            if ($null -ne $rawSigners) {
                                foreach ($as in @($rawSigners)) {
                                    if ($null -eq $as) { continue }
                                    Add-ValidatedAllowedSignerLines -RawText ([string]$as) -Context 'git.signing.allowedSigners' -TargetList $allowedSignersList -SeenSet $seenSigners
                                }
                            }
                            $allowedSignersFile = [string](Get-ObjectProperty -Object $sObj -Name 'allowedSignersFile' -Default '')
                            if (-not [string]::IsNullOrWhiteSpace($allowedSignersFile)) {
                                $asContent = Resolve-SecretFileContent -RawPath $allowedSignersFile -BaseDir $baseDir -Context 'git.signing.allowedSignersFile'
                                Add-ValidatedAllowedSignerLines -RawText $asContent -Context 'git.signing.allowedSignersFile' -TargetList $allowedSignersList -SeenSet $seenSigners
                            }

                            $signingOut = [ordered]@{
                                key            = $resolvedSigningKey
                                signCommits    = [bool](Get-ObjectProperty -Object $sObj -Name 'signCommits' -Default $true)
                                signTags       = [bool](Get-ObjectProperty -Object $sObj -Name 'signTags' -Default $false)
                                allowedSigners = @($allowedSignersList.ToArray())
                            }
                        }
                    }
                }

                if ($keysOut.Count -eq 0 -and $hostsOut.Count -eq 0 -and $knownHostsList.Count -eq 0 -and $null -eq $signingOut -and [string]::IsNullOrWhiteSpace($userName) -and [string]::IsNullOrWhiteSpace($userEmail)) {
                    throw "git: specify at least one of 'privateKey*', 'keys', 'hosts', 'knownHosts', 'signing', 'userName', or 'userEmail'."
                }

                $gitMode = [string](Get-ObjectProperty -Object $entry -Name 'mode' -Default 'files')
                if ($gitMode -eq 'file') { $gitMode = 'files' }
                if ($gitMode -notin @('files', 'agent-proxy')) {
                    throw "git.mode '$gitMode' must be 'files' or 'agent-proxy'."
                }
                $resolvedServices['git'] = [ordered]@{
                    mode                  = $gitMode
                    userName              = $userName
                    userEmail             = $userEmail
                    keys                  = @($keysOut.ToArray())
                    hosts                 = @($hostsOut.ToArray())
                    knownHosts            = @($knownHostsList.ToArray())
                    strictHostKeyChecking = $strictHostKeyChecking
                    identitiesOnly        = $identitiesOnly
                    forwardAgent          = $forwardAgent
                    serverAliveInterval   = $serverAliveInterval
                    connectTimeout        = $connectTimeout
                    batchMode             = $batchMode
                    signing               = $signingOut
                }

                $sumParts = New-Object System.Collections.Generic.List[string]
                if ($keysOut.Count -gt 0) {
                    $kNames = ($keysOut | ForEach-Object { $_.name }) -join ', '
                    $sumParts.Add("keys=$kNames")
                }
                if ($hostsOut.Count -gt 0) {
                    $hNames = ($hostsOut | ForEach-Object { $_.name }) -join ', '
                    $sumParts.Add("hosts=$hNames")
                }
                if ($knownHostsList.Count -gt 0) {
                    $sumParts.Add("knownHosts=$($knownHostsList.Count)")
                }
                if ($null -ne $signingOut) {
                    $sumParts.Add("signing=$($signingOut.key)")
                }
                if (-not [string]::IsNullOrWhiteSpace($userEmail)) {
                    $sumParts.Add("email=$userEmail")
                }
                $summary.Add("git ($($sumParts -join '; '))")
            }

            'aws' {
                $profilesOut = New-Object System.Collections.Generic.List[object]
                $seenProfiles = @{}
                $rawProfiles = Get-ObjectProperty -Object $entry -Name 'profiles' -Default $null

                if ($null -ne $rawProfiles -and @($rawProfiles).Count -gt 0) {
                    foreach ($p in @($rawProfiles)) {
                        $pName = [string](Get-ObjectProperty -Object $p -Name 'name' -Default '')
                        if ($pName -notmatch '^[A-Za-z0-9._-]+$') {
                            throw "aws.profiles entry has invalid profile name '$pName'."
                        }
                        if ($seenProfiles.ContainsKey($pName)) {
                            throw "aws.profiles contains duplicate profile name '$pName'."
                        }
                        $seenProfiles[$pName] = $true
                        $ak = Resolve-SecretValue -Object $p -BaseName 'accessKeyId' -BaseDir $baseDir -Context "aws.profiles[$pName]" -Required
                        $sk = Resolve-SecretValue -Object $p -BaseName 'secretAccessKey' -BaseDir $baseDir -Context "aws.profiles[$pName]" -Required
                        $st = Resolve-SecretValue -Object $p -BaseName 'sessionToken' -BaseDir $baseDir -Context "aws.profiles[$pName]"
                        $region = [string](Get-ObjectProperty -Object $p -Name 'region' -Default '')
                        $output = [string](Get-ObjectProperty -Object $p -Name 'output' -Default '')
                        if ($output -and $output -notin @('json', 'yaml', 'yaml-stream', 'text', 'table')) {
                            throw "aws.profiles[$pName].output '$output' is invalid."
                        }
                        $profilesOut.Add([ordered]@{
                            name            = $pName
                            accessKeyId     = $ak
                            secretAccessKey = $sk
                            sessionToken    = $st
                            region          = $region
                            output          = $output
                        })
                    }
                } else {
                    $pName = [string](Get-ObjectProperty -Object $entry -Name 'profile' -Default 'default')
                    if ($pName -notmatch '^[A-Za-z0-9._-]+$') {
                        throw "aws.profile '$pName' is invalid."
                    }
                    $ak = Resolve-SecretValue -Object $entry -BaseName 'accessKeyId' -BaseDir $baseDir -Context 'aws' -Required
                    $sk = Resolve-SecretValue -Object $entry -BaseName 'secretAccessKey' -BaseDir $baseDir -Context 'aws' -Required
                    $st = Resolve-SecretValue -Object $entry -BaseName 'sessionToken' -BaseDir $baseDir -Context 'aws'
                    $region = [string](Get-ObjectProperty -Object $entry -Name 'region' -Default '')
                    $output = [string](Get-ObjectProperty -Object $entry -Name 'output' -Default '')
                    if ($output -and $output -notin @('json', 'yaml', 'yaml-stream', 'text', 'table')) {
                        throw "aws.output '$output' is invalid."
                    }
                    $profilesOut.Add([ordered]@{
                        name            = $pName
                        accessKeyId     = $ak
                        secretAccessKey = $sk
                        sessionToken    = $st
                        region          = $region
                        output          = $output
                    })
                }

                $defaultProfile = [string](Get-ObjectProperty -Object $entry -Name 'defaultProfile' -Default '')
                if ($defaultProfile -and $defaultProfile -notmatch '^[A-Za-z0-9._-]+$') {
                    throw "aws.defaultProfile '$defaultProfile' is invalid."
                }

                $resolvedServices['aws'] = [ordered]@{
                    profiles       = @($profilesOut.ToArray())
                    defaultProfile = $defaultProfile
                }
                $pNames = ($profilesOut | ForEach-Object { $_.name }) -join ', '
                $summary.Add("aws (profiles=$pNames)")
            }

            'gcloud' {
                $resolveGcloudEntry = {
                    param($obj, [string]$ctx, [string]$fallbackRegion, [string]$fallbackZone, [bool]$isMulti)
                    $hasKeyJson = (Test-ObjectHasProperty -Object $obj -Name 'serviceAccountKeyJson') -and ($null -ne (Get-ObjectProperty -Object $obj -Name 'serviceAccountKeyJson'))
                    $hasKeyFile = (Test-ObjectHasProperty -Object $obj -Name 'serviceAccountKeyFile') -and -not [string]::IsNullOrWhiteSpace([string](Get-ObjectProperty -Object $obj -Name 'serviceAccountKeyFile' -Default ''))
                    $hasKeyEnv = (Test-ObjectHasProperty -Object $obj -Name 'serviceAccountKeyEnv') -and -not [string]::IsNullOrWhiteSpace([string](Get-ObjectProperty -Object $obj -Name 'serviceAccountKeyEnv' -Default ''))
                    $hasKeyVault = (Test-ObjectHasProperty -Object $obj -Name 'serviceAccountKeyVault') -and -not [string]::IsNullOrWhiteSpace([string](Get-ObjectProperty -Object $obj -Name 'serviceAccountKeyVault' -Default ''))
                    $keySourceCount = @($hasKeyJson, $hasKeyFile, $hasKeyEnv, $hasKeyVault | Where-Object { $_ }).Count
                    if ($keySourceCount -gt 1) {
                        throw "${ctx}: specify only one of 'serviceAccountKeyFile', 'serviceAccountKeyJson', 'serviceAccountKeyEnv', or 'serviceAccountKeyVault'."
                    }
                    if ($keySourceCount -eq 0) {
                        throw "${ctx}: missing required 'serviceAccountKeyFile', 'serviceAccountKeyJson', 'serviceAccountKeyEnv', or 'serviceAccountKeyVault'."
                    }
                    if ($hasKeyJson) {
                        $rawKey = Get-ObjectProperty -Object $obj -Name 'serviceAccountKeyJson'
                        if ($rawKey -is [string]) {
                            $keyJsonText = $rawKey
                        } else {
                            $keyJsonText = ($rawKey | ConvertTo-Json -Depth 10)
                        }
                    } else {
                        $keyJsonText = Resolve-SecretValue -Object $obj -BaseName 'serviceAccountKey' -BaseDir $baseDir -Context $ctx -Required
                    }
                    try {
                        $parsedSa = $keyJsonText | ConvertFrom-Json
                    } catch {
                        throw "${ctx}: service account key is not valid JSON."
                    }
                    $saType = [string](Get-ObjectProperty -Object $parsedSa -Name 'type' -Default '')
                    $saEmail = [string](Get-ObjectProperty -Object $parsedSa -Name 'client_email' -Default '')
                    $saPrivKey = [string](Get-ObjectProperty -Object $parsedSa -Name 'private_key' -Default '')
                    if ($saType -ne 'service_account' -or [string]::IsNullOrWhiteSpace($saEmail) -or [string]::IsNullOrWhiteSpace($saPrivKey)) {
                        throw "${ctx}: service account key JSON must have type='service_account', client_email, and private_key."
                    }
                    $proj = [string](Get-ObjectProperty -Object $obj -Name 'project' -Default '')
                    if ([string]::IsNullOrWhiteSpace($proj)) {
                        $proj = [string](Get-ObjectProperty -Object $parsedSa -Name 'project_id' -Default '')
                    }
                    $cfgName = [string](Get-ObjectProperty -Object $obj -Name 'name' -Default '')
                    if ([string]::IsNullOrWhiteSpace($cfgName)) {
                        if ($isMulti) {
                            $cfgName = if (-not [string]::IsNullOrWhiteSpace($proj)) { $proj.ToLowerInvariant() } else { '' }
                        } else {
                            $cfgName = 'default'
                        }
                    }
                    if ([string]::IsNullOrWhiteSpace($cfgName) -or $cfgName -notmatch '^[a-z0-9][-a-z0-9]{0,62}$') {
                        throw "${ctx}: configuration name '$cfgName' is invalid (must match '^[a-z0-9][-a-z0-9]{0,62}$', lowercase letters, digits, and hyphens)."
                    }
                    $reg = [string](Get-ObjectProperty -Object $obj -Name 'region' -Default '')
                    if ([string]::IsNullOrWhiteSpace($reg)) { $reg = $fallbackRegion }
                    $zn = [string](Get-ObjectProperty -Object $obj -Name 'zone' -Default '')
                    if ([string]::IsNullOrWhiteSpace($zn)) { $zn = $fallbackZone }

                    return [ordered]@{
                        name                  = $cfgName
                        project               = $proj
                        clientEmail           = $saEmail
                        serviceAccountKeyJson = $keyJsonText
                        region                = $reg
                        zone                  = $zn
                    }
                }

                $topRegion = [string](Get-ObjectProperty -Object $entry -Name 'region' -Default '')
                $topZone = [string](Get-ObjectProperty -Object $entry -Name 'zone' -Default '')
                $setAdc = [bool](Get-ObjectProperty -Object $entry -Name 'setApplicationDefaultCredentials' -Default $true)
                $skipActivate = [bool](Get-ObjectProperty -Object $entry -Name 'skipActivate' -Default $false)

                $rawProjects = Get-ObjectProperty -Object $entry -Name 'projects' -Default $null
                $rawProfiles = Get-ObjectProperty -Object $entry -Name 'profiles' -Default $null
                $hasProjects = ($null -ne $rawProjects) -and (@($rawProjects).Count -gt 0)
                $hasProfiles = ($null -ne $rawProfiles) -and (@($rawProfiles).Count -gt 0)
                if ($hasProjects -and $hasProfiles) {
                    throw "gcloud: specify either 'projects' or 'profiles', not both."
                }
                $multiList = @(if ($hasProjects) { @($rawProjects) } elseif ($hasProfiles) { @($rawProfiles) })

                $hasTopKey = ((Test-ObjectHasProperty -Object $entry -Name 'serviceAccountKeyJson') -and ($null -ne (Get-ObjectProperty -Object $entry -Name 'serviceAccountKeyJson'))) -or
                             (-not [string]::IsNullOrWhiteSpace([string](Get-ObjectProperty -Object $entry -Name 'serviceAccountKeyFile' -Default ''))) -or
                             (-not [string]::IsNullOrWhiteSpace([string](Get-ObjectProperty -Object $entry -Name 'serviceAccountKeyEnv' -Default ''))) -or
                             (-not [string]::IsNullOrWhiteSpace([string](Get-ObjectProperty -Object $entry -Name 'serviceAccountKeyVault' -Default '')))

                $projectsOut = New-Object System.Collections.Generic.List[object]
                if ($multiList.Count -gt 0) {
                    if ($hasTopKey) {
                        throw "gcloud: cannot combine top-level 'serviceAccountKey*' with 'projects'/'profiles'."
                    }
                    $seenCfgNames = @{}
                    for ($idx = 0; $idx -lt $multiList.Count; $idx++) {
                        $pItem = $multiList[$idx]
                        $resolvedItem = & $resolveGcloudEntry $pItem "gcloud.projects[$idx]" $topRegion $topZone $true
                        if ($seenCfgNames.ContainsKey($resolvedItem.name)) {
                            throw "gcloud.projects contains duplicate configuration/project name '$($resolvedItem.name)'."
                        }
                        $seenCfgNames[$resolvedItem.name] = $true
                        $projectsOut.Add($resolvedItem)
                    }
                } else {
                    $singleItem = & $resolveGcloudEntry $entry 'gcloud' $topRegion $topZone $false
                    $projectsOut.Add($singleItem)
                }

                $defProjProp = [string](Get-ObjectProperty -Object $entry -Name 'defaultProject' -Default '')
                $defProfProp = [string](Get-ObjectProperty -Object $entry -Name 'defaultProfile' -Default '')
                if ($defProjProp -and $defProfProp -and ($defProjProp -ne $defProfProp)) {
                    throw "gcloud: specify either 'defaultProject' or 'defaultProfile', not both with different values."
                }
                $requestedDefault = if ($defProjProp) { $defProjProp } else { $defProfProp }

                $activeEntry = $projectsOut[0]
                if (-not [string]::IsNullOrWhiteSpace($requestedDefault)) {
                    $matched = $projectsOut | Where-Object { $_.name -eq $requestedDefault -or $_.project -eq $requestedDefault } | Select-Object -First 1
                    if ($null -eq $matched) {
                        throw "gcloud.defaultProject '$requestedDefault' does not match any configured project name or project ID."
                    }
                    $activeEntry = $matched
                }

                $resolvedServices['gcloud'] = [ordered]@{
                    serviceAccountKeyJson            = $activeEntry.serviceAccountKeyJson
                    clientEmail                      = $activeEntry.clientEmail
                    project                          = $activeEntry.project
                    region                           = $activeEntry.region
                    zone                             = $activeEntry.zone
                    defaultProject                   = $activeEntry.name
                    projects                         = @($projectsOut.ToArray())
                    setApplicationDefaultCredentials = $setAdc
                    skipActivate                     = $skipActivate
                }
                if ($multiList.Count -gt 0) {
                    $pLabels = ($projectsOut | ForEach-Object {
                        if ($_.name -eq $_.project -or [string]::IsNullOrWhiteSpace($_.project)) { $_.name } else { "$($_.name):$($_.project)" }
                    }) -join ', '
                    $summary.Add("gcloud (projects=$pLabels; default=$($activeEntry.name))")
                } else {
                    $summary.Add("gcloud (account=$($activeEntry.clientEmail), project=$($activeEntry.project))")
                }
            }

            'azure' {
                $clientId = [string](Get-ObjectProperty -Object $entry -Name 'clientId' -Default '')
                $tenantId = [string](Get-ObjectProperty -Object $entry -Name 'tenantId' -Default '')
                if ([string]::IsNullOrWhiteSpace($clientId)) {
                    throw "azure.clientId is required."
                }
                if ([string]::IsNullOrWhiteSpace($tenantId)) {
                    throw "azure.tenantId is required."
                }
                $certFile = [string](Get-ObjectProperty -Object $entry -Name 'certificateFile' -Default '')
                $hasCert = -not [string]::IsNullOrWhiteSpace($certFile)
                $clientSecret = Resolve-SecretValue -Object $entry -BaseName 'clientSecret' -BaseDir $baseDir -Context 'azure'
                $hasSecret = -not [string]::IsNullOrWhiteSpace($clientSecret)
                if ($hasCert -and $hasSecret) {
                    throw "azure: specify either clientSecret* or certificateFile, not both."
                }
                if (-not $hasCert -and -not $hasSecret) {
                    throw "azure: missing required clientSecret/clientSecretFile/clientSecretEnv or certificateFile."
                }
                $certPem = ''
                if ($hasCert) {
                    $certPem = Resolve-SecretFileContent -RawPath $certFile -BaseDir $baseDir -Context 'azure.certificateFile'
                }
                $subscription = [string](Get-ObjectProperty -Object $entry -Name 'subscription' -Default '')
                $allowNoSubs = [bool](Get-ObjectProperty -Object $entry -Name 'allowNoSubscriptions' -Default $false)
                $exportEnv = [bool](Get-ObjectProperty -Object $entry -Name 'exportEnv' -Default $true)
                $skipLogin = [bool](Get-ObjectProperty -Object $entry -Name 'skipLogin' -Default $false)

                $resolvedServices['azure'] = [ordered]@{
                    clientId             = $clientId
                    tenantId             = $tenantId
                    clientSecret         = $clientSecret
                    certificatePem       = $certPem
                    subscription         = $subscription
                    allowNoSubscriptions = $allowNoSubs
                    exportEnv            = $exportEnv
                    skipLogin            = $skipLogin
                }
                $authKind = if ($hasCert) { 'certificate' } else { 'clientSecret' }
                $summary.Add("azure (clientId=$clientId, auth=$authKind)")
            }

            'azureDevops' {
                $org = [string](Get-ObjectProperty -Object $entry -Name 'organization' -Default '')
                if ([string]::IsNullOrWhiteSpace($org)) {
                    throw "azureDevops.organization is required."
                }
                Assert-ValidHttpUrl -Url $org -Context 'azureDevops.organization'
                $project = [string](Get-ObjectProperty -Object $entry -Name 'project' -Default '')
                $pat = Resolve-SecretValue -Object $entry -BaseName 'pat' -BaseDir $baseDir -Context 'azureDevops' -Required

                $resolvedServices['azureDevops'] = [ordered]@{
                    organization = $org
                    project      = $project
                    pat          = $pat
                }
                $summary.Add("azureDevops (org=$org)")
            }

            'jira' {
                $server = [string](Get-ObjectProperty -Object $entry -Name 'server' -Default '')
                $login = [string](Get-ObjectProperty -Object $entry -Name 'login' -Default '')
                if ([string]::IsNullOrWhiteSpace($server)) {
                    throw "jira.server is required."
                }
                Assert-ValidHttpUrl -Url $server -Context 'jira.server'
                if ([string]::IsNullOrWhiteSpace($login)) {
                    throw "jira.login is required."
                }
                $apiToken = Resolve-SecretValue -Object $entry -BaseName 'apiToken' -BaseDir $baseDir -Context 'jira' -Required
                $installation = [string](Get-ObjectProperty -Object $entry -Name 'installation' -Default 'cloud')
                if ($installation -notin @('cloud', 'local')) {
                    throw "jira.installation must be 'cloud' or 'local'."
                }
                $authType = [string](Get-ObjectProperty -Object $entry -Name 'authType' -Default 'basic')
                if ($authType -notin @('basic', 'bearer', 'mtls')) {
                    throw "jira.authType must be 'basic', 'bearer', or 'mtls'."
                }
                $proxyInject = [bool](Get-ObjectProperty -Object $entry -Name 'proxyInject' -Default $false)
                $agentJiraToken = $apiToken
                $agentJiraServer = $server
                if ($proxyInject) {
                    if ($authType -eq 'mtls') {
                        throw "jira: proxyInject cannot be used with authType 'mtls'."
                    }
                    $agentJiraToken = Get-ProxyPlaceholderToken -ServicePrefix 'jira'
                    $authHeader = if ($authType -eq 'basic') {
                        $pairBytes = [System.Text.Encoding]::UTF8.GetBytes("${login}:${apiToken}")
                        'Basic ' + [Convert]::ToBase64String($pairBytes)
                    } else {
                        "Bearer $apiToken"
                    }
                    $proxyRoutes['jira'] = [ordered]@{
                        upstreamBaseUrl = $server.TrimEnd('/')
                        expectedToken   = $agentJiraToken
                        injectHeaders   = [ordered]@{ Authorization = $authHeader }
                    }
                    $agentJiraServer = 'http://127.0.0.1:3129/jira'
                }

                $jiraOut = [ordered]@{
                    server       = $agentJiraServer
                    login        = $login
                    apiToken     = $agentJiraToken
                    installation = $installation
                    authType     = $authType
                    projectKey   = [string](Get-ObjectProperty -Object $entry -Name 'projectKey' -Default '')
                    projectType  = [string](Get-ObjectProperty -Object $entry -Name 'projectType' -Default '')
                    boardId      = (Get-ObjectProperty -Object $entry -Name 'boardId' -Default $null)
                    boardName    = [string](Get-ObjectProperty -Object $entry -Name 'boardName' -Default '')
                    boardType    = [string](Get-ObjectProperty -Object $entry -Name 'boardType' -Default '')
                }
                $resolvedServices['jira'] = $jiraOut
                $summary.Add("jira (server=$server, login=$login)")
            }

            'upcloud' {
                $token = Resolve-SecretValue -Object $entry -BaseName 'token' -BaseDir $baseDir -Context 'upcloud'
                $username = [string](Get-ObjectProperty -Object $entry -Name 'username' -Default '')
                $password = Resolve-SecretValue -Object $entry -BaseName 'password' -BaseDir $baseDir -Context 'upcloud'
                $hasToken = -not [string]::IsNullOrWhiteSpace($token)
                $hasUserPass = (-not [string]::IsNullOrWhiteSpace($username)) -or (-not [string]::IsNullOrWhiteSpace($password))

                if ($hasToken -and $hasUserPass) {
                    throw "upcloud: specify either token* or username+password*, not both."
                }
                if (-not $hasToken -and -not $hasUserPass) {
                    throw "upcloud: specify token/tokenFile/tokenEnv (recommended) or username + password*."
                }
                if ($hasUserPass -and ([string]::IsNullOrWhiteSpace($username) -or [string]::IsNullOrWhiteSpace($password))) {
                    throw "upcloud: both username and password* are required when not using token."
                }
                $exportEnv = [bool](Get-ObjectProperty -Object $entry -Name 'exportEnv' -Default $true)

                $resolvedServices['upcloud'] = [ordered]@{
                    token     = $token
                    username  = $username
                    password  = $password
                    exportEnv = $exportEnv
                }
                $mode = if ($hasToken) { 'token' } else { 'username/password' }
                $summary.Add("upcloud (auth=$mode, exportEnv=$exportEnv)")
            }

            'kubectl' {
                $kcFile = [string](Get-ObjectProperty -Object $entry -Name 'kubeconfigFile' -Default '')
                $server = [string](Get-ObjectProperty -Object $entry -Name 'server' -Default '')
                $hasKc = -not [string]::IsNullOrWhiteSpace($kcFile)
                $hasServer = -not [string]::IsNullOrWhiteSpace($server)
                if ($hasKc -and $hasServer) {
                    throw "kubectl: specify either 'kubeconfigFile' or 'server'+token, not both."
                }
                if (-not $hasKc -and -not $hasServer) {
                    throw "kubectl: specify either 'kubeconfigFile' or 'server' + token*."
                }
                $context = [string](Get-ObjectProperty -Object $entry -Name 'context' -Default '')
                if ($hasKc) {
                    $kcContent = Resolve-SecretFileContent -RawPath $kcFile -BaseDir $baseDir -Context 'kubectl.kubeconfigFile'
                    $resolvedServices['kubectl'] = [ordered]@{
                        mode              = 'file'
                        kubeconfigContent = $kcContent
                        context           = $context
                    }
                    $summary.Add("kubectl (mode=kubeconfigFile)")
                } else {
                    Assert-ValidHttpUrl -Url $server -Context 'kubectl.server'
                    $token = Resolve-SecretValue -Object $entry -BaseName 'token' -BaseDir $baseDir -Context 'kubectl' -Required
                    $caCertFile = [string](Get-ObjectProperty -Object $entry -Name 'caCertFile' -Default '')
                    $caCertData = [string](Get-ObjectProperty -Object $entry -Name 'caCertData' -Default '')
                    if (-not [string]::IsNullOrWhiteSpace($caCertFile) -and -not [string]::IsNullOrWhiteSpace($caCertData)) {
                        throw "kubectl: specify either caCertFile or caCertData, not both."
                    }
                    if (-not [string]::IsNullOrWhiteSpace($caCertFile)) {
                        $caBytes = Resolve-SecretFileContent -RawPath $caCertFile -BaseDir $baseDir -Context 'kubectl.caCertFile' -AsBytes
                        $caCertData = [Convert]::ToBase64String($caBytes)
                    }
                    $resolvedServices['kubectl'] = [ordered]@{
                        mode                  = 'token'
                        server                = $server
                        token                 = $token
                        caCertData            = $caCertData
                        insecureSkipTlsVerify = [bool](Get-ObjectProperty -Object $entry -Name 'insecureSkipTlsVerify' -Default $false)
                        namespace             = [string](Get-ObjectProperty -Object $entry -Name 'namespace' -Default 'default')
                        clusterName           = [string](Get-ObjectProperty -Object $entry -Name 'clusterName' -Default 'sandbox')
                        userName              = [string](Get-ObjectProperty -Object $entry -Name 'userName' -Default 'sandbox-sa')
                        contextName           = [string](Get-ObjectProperty -Object $entry -Name 'contextName' -Default 'sandbox')
                        context               = $context
                    }
                    $summary.Add("kubectl (mode=serviceAccountToken, server=$server)")
                }
            }

            'gemini' {
                $apiKey = Resolve-SecretValue -Object $entry -BaseName 'apiKey' -BaseDir $baseDir -Context 'gemini'
                $gcpProject = [string](Get-ObjectProperty -Object $entry -Name 'googleCloudProject' -Default '')
                $gcpLoc = [string](Get-ObjectProperty -Object $entry -Name 'googleCloudLocation' -Default '')
                $useVertex = [bool](Get-ObjectProperty -Object $entry -Name 'useVertexAi' -Default $false)
                if ([string]::IsNullOrWhiteSpace($apiKey) -and [string]::IsNullOrWhiteSpace($gcpProject) -and -not $useVertex) {
                    throw "gemini: specify apiKey* and/or Vertex AI settings (googleCloudProject / useVertexAi)."
                }
                $proxyInject = [bool](Get-ObjectProperty -Object $entry -Name 'proxyInject' -Default $false)
                $agentApiKey = $apiKey
                $proxyBaseUrl = ''
                if ($proxyInject -and $apiKey) {
                    $agentApiKey = Get-ProxyPlaceholderToken -ServicePrefix 'gemini'
                    $proxyBaseUrl = 'http://127.0.0.1:3129/gemini'
                    $proxyRoutes['gemini'] = [ordered]@{
                        upstreamBaseUrl = 'https://generativelanguage.googleapis.com'
                        expectedToken   = $agentApiKey
                        injectHeaders   = [ordered]@{ 'x-goog-api-key' = $apiKey }
                    }
                }
                $resolvedServices['gemini'] = [ordered]@{
                    apiKey              = $agentApiKey
                    googleCloudProject  = $gcpProject
                    googleCloudLocation = $gcpLoc
                    useVertexAi         = $useVertex
                    proxyBaseUrl        = $proxyBaseUrl
                }
                $summary.Add("gemini (apiKey=$(-not [string]::IsNullOrWhiteSpace($apiKey)), vertex=$useVertex)")
            }

            'claude' {
                $apiKey = Resolve-SecretValue -Object $entry -BaseName 'apiKey' -BaseDir $baseDir -Context 'claude'
                $oauthToken = Resolve-SecretValue -Object $entry -BaseName 'oauthToken' -BaseDir $baseDir -Context 'claude'
                if ([string]::IsNullOrWhiteSpace($apiKey) -and [string]::IsNullOrWhiteSpace($oauthToken)) {
                    throw "claude: specify apiKey* and/or oauthToken*."
                }
                $proxyInject = [bool](Get-ObjectProperty -Object $entry -Name 'proxyInject' -Default $false)
                $agentClaudeKey = $apiKey
                $agentOauth = $oauthToken
                $proxyBaseUrl = ''
                if ($proxyInject) {
                    $injectHeaders = [ordered]@{}
                    $expectedTokens = New-Object System.Collections.Generic.List[string]
                    if (-not [string]::IsNullOrWhiteSpace($apiKey)) {
                        $agentClaudeKey = Get-ProxyPlaceholderToken -ServicePrefix 'claude'
                        $injectHeaders['x-api-key'] = $apiKey
                        $expectedTokens.Add($agentClaudeKey)
                    }
                    if (-not [string]::IsNullOrWhiteSpace($oauthToken)) {
                        $agentOauth = Get-ProxyPlaceholderToken -ServicePrefix 'claude-oauth'
                        $injectHeaders['Authorization'] = "Bearer $oauthToken"
                        $expectedTokens.Add($agentOauth)
                    }
                    $proxyBaseUrl = 'http://127.0.0.1:3129/claude'
                    $proxyRoutes['claude'] = [ordered]@{
                        upstreamBaseUrl = 'https://api.anthropic.com'
                        expectedTokens  = $expectedTokens.ToArray()
                        injectHeaders   = $injectHeaders
                    }
                }
                $resolvedServices['claude'] = [ordered]@{
                    apiKey       = $agentClaudeKey
                    oauthToken   = $agentOauth
                    proxyBaseUrl = $proxyBaseUrl
                }
                $summary.Add("claude (apiKey=$(-not [string]::IsNullOrWhiteSpace($apiKey)), oauthToken=$(-not [string]::IsNullOrWhiteSpace($oauthToken)))")
            }

            'ssh' {
                $keysOut = New-Object System.Collections.Generic.List[object]
                $seenKeys = @{}
                $hostsOut = New-Object System.Collections.Generic.List[object]
                $seenHosts = @{}
                $knownHostsList = New-Object System.Collections.Generic.List[string]
                $seenKnownHosts = @{}

                # 1. Named SSH keys
                $rawKeys = Get-ObjectProperty -Object $entry -Name 'keys' -Default $null
                if ($null -ne $rawKeys) {
                    foreach ($k in @($rawKeys)) {
                        if ($null -eq $k) { continue }
                        $kName = [string](Get-ObjectProperty -Object $k -Name 'name' -Default '')
                        if ($kName -notmatch '^[A-Za-z0-9][A-Za-z0-9._-]{0,62}$') {
                            throw "ssh.keys entry has invalid name '$kName'."
                        }
                        if ($kName -in @('known_hosts', 'config')) {
                            throw "ssh.keys entry name '$kName' is reserved."
                        }
                        if ($seenKeys.ContainsKey($kName.ToLowerInvariant())) {
                            throw "ssh.keys contains duplicate key name '$kName'."
                        }
                        $seenKeys[$kName.ToLowerInvariant()] = $kName
                        $privKey = Resolve-SshPrivateKey -Object $k -BaseDir $baseDir -Context "ssh.keys[$kName]" -Required
                        $pubKey = Resolve-SshPublicMaterial -Object $k -BaseName 'publicKey' -BaseDir $baseDir -Context "ssh.keys[$kName]"
                        $cert = Resolve-SshPublicMaterial -Object $k -BaseName 'certificate' -BaseDir $baseDir -Context "ssh.keys[$kName]"
                        $keysOut.Add([ordered]@{
                            name        = $kName
                            privateKey  = $privKey
                            publicKey   = $pubKey
                            certificate = $cert
                        })
                    }
                }

                # 2. Top-level defaults & validation
                $defaultKey = [string](Get-ObjectProperty -Object $entry -Name 'defaultKey' -Default '')
                if (-not [string]::IsNullOrWhiteSpace($defaultKey)) {
                    if (-not $seenKeys.ContainsKey($defaultKey.ToLowerInvariant())) {
                        throw "ssh.defaultKey '$defaultKey' does not match any key defined in ssh.keys."
                    }
                    $defaultKey = $seenKeys[$defaultKey.ToLowerInvariant()]
                }

                $strictHostKeyChecking = [string](Get-ObjectProperty -Object $entry -Name 'strictHostKeyChecking' -Default '')
                if (-not [string]::IsNullOrWhiteSpace($strictHostKeyChecking) -and $strictHostKeyChecking -notin @('yes', 'accept-new', 'no')) {
                    throw "ssh.strictHostKeyChecking '$strictHostKeyChecking' must be 'yes', 'accept-new', or 'no'."
                }

                $identitiesOnly = [bool](Get-ObjectProperty -Object $entry -Name 'identitiesOnly' -Default $true)
                $forwardAgent = [bool](Get-ObjectProperty -Object $entry -Name 'forwardAgent' -Default $false)

                $serverAliveInterval = Get-ObjectProperty -Object $entry -Name 'serverAliveInterval' -Default $null
                if ($null -ne $serverAliveInterval) {
                    $aliveVal = [int]$serverAliveInterval
                    if ($aliveVal -lt 0 -or $aliveVal -gt 3600) {
                        throw "ssh.serverAliveInterval ($aliveVal) must be between 0 and 3600."
                    }
                    $serverAliveInterval = $aliveVal
                }

                $connectTimeout = Get-ObjectProperty -Object $entry -Name 'connectTimeout' -Default $null
                if ($null -ne $connectTimeout) {
                    $toVal = [int]$connectTimeout
                    if ($toVal -lt 1 -or $toVal -gt 600) {
                        throw "ssh.connectTimeout ($toVal) must be between 1 and 600."
                    }
                    $connectTimeout = $toVal
                }

                $batchMode = $null
                if (Test-ObjectHasProperty -Object $entry -Name 'batchMode') {
                    $bmRaw = Get-ObjectProperty -Object $entry -Name 'batchMode' -Default $null
                    if ($null -ne $bmRaw) {
                        $batchMode = [bool]$bmRaw
                    }
                }

                # 3. Top-level knownHosts & knownHostsFile
                $rawKnownHosts = Get-ObjectProperty -Object $entry -Name 'knownHosts' -Default $null
                if ($null -ne $rawKnownHosts) {
                    foreach ($kh in @($rawKnownHosts)) {
                        if ($null -eq $kh) { continue }
                        Add-ValidatedKnownHostLines -RawText ([string]$kh) -Context 'ssh.knownHosts' -TargetList $knownHostsList -SeenSet $seenKnownHosts
                    }
                }
                $knownHostsFile = [string](Get-ObjectProperty -Object $entry -Name 'knownHostsFile' -Default '')
                if (-not [string]::IsNullOrWhiteSpace($knownHostsFile)) {
                    $khContent = Resolve-SecretFileContent -RawPath $knownHostsFile -BaseDir $baseDir -Context 'ssh.knownHostsFile'
                    Add-ValidatedKnownHostLines -RawText $khContent -Context 'ssh.knownHostsFile' -TargetList $knownHostsList -SeenSet $seenKnownHosts
                }

                # 4. Remote server Host entries
                $rawHosts = Get-ObjectProperty -Object $entry -Name 'hosts' -Default $null
                if ($null -ne $rawHosts) {
                    foreach ($h in @($rawHosts)) {
                        if ($null -eq $h) { continue }
                        $hName = [string](Get-ObjectProperty -Object $h -Name 'name' -Default '')
                        if ([string]::IsNullOrWhiteSpace($hName)) {
                            throw "ssh.hosts entry is missing required 'name'."
                        }
                        Assert-SafeSshConfigValue -Value $hName -Pattern '^[A-Za-z0-9._*?@:-]+$' -Context "ssh.hosts[$hName].name"
                        if ($hName -eq '*') {
                            throw "ssh.hosts entry name cannot be '*' (use top-level ssh.defaultKey and ssh defaults instead)."
                        }
                        if ($seenHosts.ContainsKey($hName.ToLowerInvariant())) {
                            throw "ssh.hosts contains duplicate host name '$hName'."
                        }
                        $seenHosts[$hName.ToLowerInvariant()] = $true

                        $hostName = [string](Get-ObjectProperty -Object $h -Name 'hostName' -Default '')
                        if ([string]::IsNullOrWhiteSpace($hostName)) {
                            throw "ssh.hosts[$hName].hostName is required."
                        }
                        Assert-SafeSshConfigValue -Value $hostName -Pattern '^[A-Za-z0-9._:%\[\]-]+$' -Context "ssh.hosts[$hName].hostName"

                        $hUser = [string](Get-ObjectProperty -Object $h -Name 'user' -Default '')
                        if (-not [string]::IsNullOrWhiteSpace($hUser)) {
                            Assert-SafeSshConfigValue -Value $hUser -Pattern '^[A-Za-z0-9._@+-]+$' -Context "ssh.hosts[$hName].user"
                        }

                        $hPort = $null
                        if (Test-ObjectHasProperty -Object $h -Name 'port') {
                            $pRaw = Get-ObjectProperty -Object $h -Name 'port' -Default $null
                            if ($null -ne $pRaw) {
                                $pInt = [int]$pRaw
                                if ($pInt -lt 1 -or $pInt -gt 65535) {
                                    throw "ssh.hosts[$hName].port ($pInt) must be between 1 and 65535."
                                }
                                $hPort = $pInt
                            }
                        }

                        $hKeyRef = [string](Get-ObjectProperty -Object $h -Name 'key' -Default '')
                        $hInlinePriv = Resolve-SshPrivateKey -Object $h -BaseDir $baseDir -Context "ssh.hosts[$hName]"
                        $hInlinePub = Resolve-SshPublicMaterial -Object $h -BaseName 'publicKey' -BaseDir $baseDir -Context "ssh.hosts[$hName]"
                        $hInlineCert = Resolve-SshPublicMaterial -Object $h -BaseName 'certificate' -BaseDir $baseDir -Context "ssh.hosts[$hName]"

                        $hasKeyRef = -not [string]::IsNullOrWhiteSpace($hKeyRef)
                        $hasInlinePriv = -not [string]::IsNullOrWhiteSpace($hInlinePriv)

                        if ($hasKeyRef -and $hasInlinePriv) {
                            throw "ssh.hosts[$hName]: specify either 'key' or 'privateKey*', not both."
                        }
                        if ((-not $hasInlinePriv) -and ((-not [string]::IsNullOrWhiteSpace($hInlinePub)) -or (-not [string]::IsNullOrWhiteSpace($hInlineCert)))) {
                            throw "ssh.hosts[$hName]: 'publicKey*' and 'certificate*' on a host require an inline 'privateKey*' (or configure them on the named key in ssh.keys)."
                        }

                        $resolvedKeyName = ''
                        if ($hasKeyRef) {
                            if (-not $seenKeys.ContainsKey($hKeyRef.ToLowerInvariant())) {
                                throw "ssh.hosts[$hName].key '$hKeyRef' does not match any key defined in ssh.keys."
                            }
                            $resolvedKeyName = $seenKeys[$hKeyRef.ToLowerInvariant()]
                        } elseif ($hasInlinePriv) {
                            $safeBase = 'host-' + (($hName -replace '[^A-Za-z0-9._-]', '_').Trim('_'))
                            if ($safeBase.Length -gt 55) {
                                $safeBase = $safeBase.Substring(0, 55)
                            }
                            $candidate = $safeBase
                            $suffix = 2
                            while ($seenKeys.ContainsKey($candidate.ToLowerInvariant())) {
                                $candidate = "${safeBase}-${suffix}"
                                $suffix++
                            }
                            $seenKeys[$candidate.ToLowerInvariant()] = $candidate
                            $keysOut.Add([ordered]@{
                                name        = $candidate
                                privateKey  = $hInlinePriv
                                publicKey   = $hInlinePub
                                certificate = $hInlineCert
                            })
                            $resolvedKeyName = $candidate
                        }

                        $hProxyJump = [string](Get-ObjectProperty -Object $h -Name 'proxyJump' -Default '')
                        if (-not [string]::IsNullOrWhiteSpace($hProxyJump)) {
                            Assert-SafeSshConfigValue -Value $hProxyJump -Pattern '^[A-Za-z0-9._@:%\[\],-]+$' -Context "ssh.hosts[$hName].proxyJump"
                        }

                        $hShkc = [string](Get-ObjectProperty -Object $h -Name 'strictHostKeyChecking' -Default '')
                        if (-not [string]::IsNullOrWhiteSpace($hShkc) -and $hShkc -notin @('yes', 'accept-new', 'no')) {
                            throw "ssh.hosts[$hName].strictHostKeyChecking '$hShkc' must be 'yes', 'accept-new', or 'no'."
                        }

                        $hIdentitiesOnly = $null
                        if (Test-ObjectHasProperty -Object $h -Name 'identitiesOnly') {
                            $v = Get-ObjectProperty -Object $h -Name 'identitiesOnly' -Default $null
                            if ($null -ne $v) { $hIdentitiesOnly = [bool]$v }
                        }

                        $hForwardAgent = $null
                        if (Test-ObjectHasProperty -Object $h -Name 'forwardAgent') {
                            $v = Get-ObjectProperty -Object $h -Name 'forwardAgent' -Default $null
                            if ($null -ne $v) { $hForwardAgent = [bool]$v }
                        }

                        $hAlive = $null
                        if (Test-ObjectHasProperty -Object $h -Name 'serverAliveInterval') {
                            $v = Get-ObjectProperty -Object $h -Name 'serverAliveInterval' -Default $null
                            if ($null -ne $v) {
                                $aInt = [int]$v
                                if ($aInt -lt 0 -or $aInt -gt 3600) {
                                    throw "ssh.hosts[$hName].serverAliveInterval ($aInt) must be between 0 and 3600."
                                }
                                $hAlive = $aInt
                            }
                        }

                        $hTimeout = $null
                        if (Test-ObjectHasProperty -Object $h -Name 'connectTimeout') {
                            $v = Get-ObjectProperty -Object $h -Name 'connectTimeout' -Default $null
                            if ($null -ne $v) {
                                $tInt = [int]$v
                                if ($tInt -lt 1 -or $tInt -gt 600) {
                                    throw "ssh.hosts[$hName].connectTimeout ($tInt) must be between 1 and 600."
                                }
                                $hTimeout = $tInt
                            }
                        }

                        $hBatch = $null
                        if (Test-ObjectHasProperty -Object $h -Name 'batchMode') {
                            $v = Get-ObjectProperty -Object $h -Name 'batchMode' -Default $null
                            if ($null -ne $v) { $hBatch = [bool]$v }
                        }

                        $hKnownHost = [string](Get-ObjectProperty -Object $h -Name 'knownHost' -Default '')
                        if (-not [string]::IsNullOrWhiteSpace($hKnownHost)) {
                            Add-ValidatedKnownHostLines -RawText $hKnownHost -Context "ssh.hosts[$hName].knownHost" -TargetList $knownHostsList -SeenSet $seenKnownHosts
                        }
                        $hKnownHostFile = [string](Get-ObjectProperty -Object $h -Name 'knownHostFile' -Default '')
                        if (-not [string]::IsNullOrWhiteSpace($hKnownHostFile)) {
                            $hkhContent = Resolve-SecretFileContent -RawPath $hKnownHostFile -BaseDir $baseDir -Context "ssh.hosts[$hName].knownHostFile"
                            Add-ValidatedKnownHostLines -RawText $hkhContent -Context "ssh.hosts[$hName].knownHostFile" -TargetList $knownHostsList -SeenSet $seenKnownHosts
                        }

                        $hostsOut.Add([ordered]@{
                            name                  = $hName
                            hostName              = $hostName
                            user                  = $hUser
                            port                  = $hPort
                            key                   = $resolvedKeyName
                            proxyJump             = $hProxyJump
                            identitiesOnly        = $hIdentitiesOnly
                            forwardAgent          = $hForwardAgent
                            strictHostKeyChecking = $hShkc
                            serverAliveInterval   = $hAlive
                            connectTimeout        = $hTimeout
                            batchMode             = $hBatch
                        })
                    }
                }

                if ($keysOut.Count -eq 0 -and $hostsOut.Count -eq 0 -and $knownHostsList.Count -eq 0) {
                    throw "ssh: specify at least one of 'keys', 'hosts', 'knownHosts', or 'knownHostsFile'."
                }

                $sshMode = [string](Get-ObjectProperty -Object $entry -Name 'mode' -Default 'files')
                if ($sshMode -eq 'file') { $sshMode = 'files' }
                if ($sshMode -notin @('files', 'agent-proxy')) {
                    throw "ssh.mode '$sshMode' must be 'files' or 'agent-proxy'."
                }
                $resolvedServices['ssh'] = [ordered]@{
                    mode                  = $sshMode
                    keys                  = @($keysOut.ToArray())
                    hosts                 = @($hostsOut.ToArray())
                    knownHosts            = @($knownHostsList.ToArray())
                    defaultKey            = $defaultKey
                    strictHostKeyChecking = $strictHostKeyChecking
                    identitiesOnly        = $identitiesOnly
                    forwardAgent          = $forwardAgent
                    serverAliveInterval   = $serverAliveInterval
                    connectTimeout        = $connectTimeout
                    batchMode             = $batchMode
                }

                $sumParts = New-Object System.Collections.Generic.List[string]
                if ($keysOut.Count -gt 0) {
                    $kNames = ($keysOut | ForEach-Object { $_.name }) -join ', '
                    $sumParts.Add("keys=$kNames")
                }
                if ($hostsOut.Count -gt 0) {
                    $hNames = ($hostsOut | ForEach-Object { $_.name }) -join ', '
                    $sumParts.Add("hosts=$hNames")
                }
                if ($knownHostsList.Count -gt 0) {
                    $sumParts.Add("knownHosts=$($knownHostsList.Count)")
                }
                $summary.Add("ssh ($($sumParts -join '; '))")
            }

            'env' {
                $envMap = [ordered]@{}
                foreach ($varName in (Get-ObjectPropertyNames -Object $entry)) {
                    if ($varName -notmatch '^[A-Za-z_][A-Za-z0-9_]*$') {
                        throw "env: invalid environment variable name '$varName'."
                    }
                    if ($varName.ToUpperInvariant() -in $script:ForbiddenEnvVars) {
                        throw "env: refusing to override protected system environment variable '$varName'."
                    }
                    $valSpec = Get-ObjectProperty -Object $entry -Name $varName
                    if ($valSpec -is [string]) {
                        if ([string]::IsNullOrEmpty($valSpec)) {
                            throw "env.$varName cannot be empty."
                        }
                        $envMap[$varName] = $valSpec
                    } elseif ($null -ne $valSpec) {
                        $envMap[$varName] = Resolve-SecretValue -Object $valSpec -BaseName 'value' -BaseDir $baseDir -Context "env.$varName" -Required
                    } else {
                        throw "env.$varName cannot be null."
                    }
                }
                if ($envMap.Count -gt 0) {
                    $resolvedServices['env'] = $envMap
                    $summary.Add("env (keys=$($envMap.Keys -join ', '))")
                }
            }

            'files' {
                $filesOut = New-Object System.Collections.Generic.List[object]
                $seenNames = @{}
                foreach ($f in @($entry)) {
                    if ($null -eq $f) { continue }
                    $fEnabled = [bool](Get-ObjectProperty -Object $f -Name 'enabled' -Default $true)
                    if (-not $fEnabled) { continue }
                    $fName = [string](Get-ObjectProperty -Object $f -Name 'name' -Default '')
                    if ($fName -notmatch '^[A-Za-z0-9][A-Za-z0-9._-]{0,62}$') {
                        throw "files entry has invalid name '$fName'."
                    }
                    if ($seenNames.ContainsKey($fName.ToLowerInvariant())) {
                        throw "files contains duplicate entry name '$fName'."
                    }
                    $seenNames[$fName.ToLowerInvariant()] = $true
                    $src = [string](Get-ObjectProperty -Object $f -Name 'sourcePath' -Default '')
                    $dst = [string](Get-ObjectProperty -Object $f -Name 'targetPath' -Default '')
                    $mode = [string](Get-ObjectProperty -Object $f -Name 'mode' -Default '0600')
                    if ($mode -notmatch '^0?[0-7]{3}$') {
                        throw "files[$fName].mode '$mode' must be a 3- or 4-digit octal permission (e.g. '0600')."
                    }
                    $safeTarget = Assert-SafeAgentTargetPath -TargetPath $dst -AgentName $AgentName -Context "files[$fName]"
                    $bytes = Resolve-SecretFileContent -RawPath $src -BaseDir $baseDir -Context "files[$fName].sourcePath" -AsBytes
                    $filesOut.Add([ordered]@{
                        name          = $fName
                        targetPath    = $safeTarget
                        mode          = $mode
                        contentBase64 = [Convert]::ToBase64String($bytes)
                    })
                }
                if ($filesOut.Count -gt 0) {
                    $resolvedServices['files'] = @($filesOut.ToArray())
                    $fNames = ($filesOut | ForEach-Object { $_.name }) -join ', '
                    $summary.Add("files ($fNames)")
                }
            }
        }

        $svcVaultSources = @()
        if ($null -ne $script:CurrentServiceVaultSources -and $script:CurrentServiceVaultSources.Count -gt 0) {
            $svcVaultSources = @($script:CurrentServiceVaultSources.ToArray())
        }
        $script:CurrentServiceVaultSources = $null

        if ($resolvedServices.Contains($svcName)) {
            if ($svcVaultSources.Count -gt 0 -and $summary.Count -gt $summaryCountBefore) {
                $lastIdx = $summary.Count - 1
                $summary[$lastIdx] = "$($summary[$lastIdx]) [vault=$($svcVaultSources -join ',')]"
            }
            $effSvcTtl = [int64]0
            if ($ttlSeconds -gt 0) {
                $effSvcTtl = $ttlSeconds
            } elseif ($svcName -notin @('env', 'files') -and (Test-ObjectHasProperty -Object $entry -Name 'ttl')) {
                $rawSvcTtl = [string](Get-ObjectProperty -Object $entry -Name 'ttl' -Default '')
                if (-not [string]::IsNullOrWhiteSpace($rawSvcTtl)) {
                    $effSvcTtl = ConvertTo-TtlSeconds -Ttl $rawSvcTtl
                }
            }
            if ($effSvcTtl -gt 0) {
                $serviceTtls[$svcName] = [int64]$effSvcTtl
                if ($summary.Count -gt $summaryCountBefore) {
                    $lastIdx = $summary.Count - 1
                    $summary[$lastIdx] = "$($summary[$lastIdx]) [ttl=${effSvcTtl}s]"
                }
            }
        }
    }

    $payload = [ordered]@{
        services       = $resolvedServices
        proxyRoutes    = $proxyRoutes
        serviceTtls    = $serviceTtls
        filterServices = @($filterServices)
        prune          = [bool]$Prune
        ttlSeconds     = [int64]$ttlSeconds
    }

    return [pscustomobject]@{
        ManifestPath    = $ManifestPath
        Payload         = $payload
        Summary         = @($summary.ToArray())
        SkippedDisabled = @($skippedDisabled.ToArray())
    }
}

function Invoke-WslRootStdinCommand {
    param(
        [Parameter(Mandatory)][string]$DistroName,
        [Parameter(Mandatory)][string]$RemoteCommand,
        [string]$StdinText = ''
    )
    $psi = New-Object System.Diagnostics.ProcessStartInfo
    $psi.FileName = 'wsl.exe'
    $psi.Arguments = "-d $DistroName -u root -- $RemoteCommand"
    $psi.UseShellExecute = $false
    $psi.RedirectStandardInput = $true
    $psi.RedirectStandardOutput = $true
    $psi.RedirectStandardError = $true

    $proc = [System.Diagnostics.Process]::Start($psi)
    try {
        if ($StdinText.Length -gt 0) {
            $utf8NoBom = New-Object System.Text.UTF8Encoding($false)
            $bytes = $utf8NoBom.GetBytes($StdinText)
            $proc.StandardInput.BaseStream.Write($bytes, 0, $bytes.Length)
            $proc.StandardInput.BaseStream.Flush()
        }
        $proc.StandardInput.Close()

        $stdoutTask = $proc.StandardOutput.ReadToEndAsync()
        $stderrTask = $proc.StandardError.ReadToEndAsync()
        $proc.WaitForExit()

        $stdout = $stdoutTask.GetAwaiter().GetResult()
        $stderr = $stderrTask.GetAwaiter().GetResult()

        if (-not [string]::IsNullOrEmpty($stdout)) {
            Write-Host ($stdout.TrimEnd("`r", "`n"))
        }
        if (-not [string]::IsNullOrEmpty($stderr)) {
            [Console]::Error.WriteLine($stderr.TrimEnd("`r", "`n"))
        }
        if ($proc.ExitCode -ne 0) {
            throw "WSL command failed with exit code $($proc.ExitCode)."
        }
    } finally {
        $proc.Dispose()
    }
}
