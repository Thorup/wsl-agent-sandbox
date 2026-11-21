#Requires -Version 5.1
Set-StrictMode -Version Latest

$script:SupportedSecretServices = @(
    'github',
    'aws',
    'gcloud',
    'azure',
    'azureDevops',
    'jira',
    'upcloud',
    'kubectl',
    'gemini',
    'claude',
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

    $hasDirect = (Test-ObjectHasProperty -Object $Object -Name $BaseName) -and -not [string]::IsNullOrEmpty([string](Get-ObjectProperty -Object $Object -Name $BaseName -Default ''))
    $hasFile = (Test-ObjectHasProperty -Object $Object -Name $fileProp) -and -not [string]::IsNullOrWhiteSpace([string](Get-ObjectProperty -Object $Object -Name $fileProp -Default ''))
    $hasEnv = (Test-ObjectHasProperty -Object $Object -Name $envProp) -and -not [string]::IsNullOrWhiteSpace([string](Get-ObjectProperty -Object $Object -Name $envProp -Default ''))

    $sourceCount = @($hasDirect, $hasFile, $hasEnv | Where-Object { $_ }).Count
    if ($sourceCount -gt 1) {
        throw "${Context}: specify only one of '$BaseName', '$fileProp', or '$envProp'."
    }
    if ($sourceCount -eq 0) {
        if ($Required) {
            throw "${Context}: missing required secret ('$BaseName', '$fileProp', or '$envProp')."
        }
        return ''
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

function Build-SeedSecretsPayload {
    param(
        [Parameter(Mandatory)][string]$ManifestPath,
        [Parameter(Mandatory)][string]$AgentName,
        [string[]]$Services = @(),
        [switch]$Prune
    )

    if (-not (Test-Path -LiteralPath $ManifestPath -PathType Leaf)) {
        throw "Secrets manifest not found at '$ManifestPath'. Create it from 'examples\secrets.example.json' (default path: %USERPROFILE%\.wsl-agent-sandbox\secrets.json) or pass -SecretsPath."
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

                $resolvedServices['github'] = [ordered]@{
                    hostname    = $hostname
                    token       = $token
                    user        = $user
                    gitProtocol = $gitProtocol
                    setupGit    = $setupGit
                    exportEnv   = $exportEnv
                    loginOnline = $loginOnline
                }
                $summary.Add("github (host=$hostname, setupGit=$setupGit, exportEnv=$exportEnv)")
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
                $keyFile = [string](Get-ObjectProperty -Object $entry -Name 'serviceAccountKeyFile' -Default '')
                $hasKeyFile = -not [string]::IsNullOrWhiteSpace($keyFile)
                $hasKeyJson = (Test-ObjectHasProperty -Object $entry -Name 'serviceAccountKeyJson') -and ($null -ne (Get-ObjectProperty -Object $entry -Name 'serviceAccountKeyJson'))
                if ($hasKeyFile -and $hasKeyJson) {
                    throw "gcloud: specify only one of 'serviceAccountKeyFile' or 'serviceAccountKeyJson'."
                }
                if (-not $hasKeyFile -and -not $hasKeyJson) {
                    throw "gcloud: missing required 'serviceAccountKeyFile' or 'serviceAccountKeyJson'."
                }
                if ($hasKeyFile) {
                    $keyJsonText = Resolve-SecretFileContent -RawPath $keyFile -BaseDir $baseDir -Context 'gcloud.serviceAccountKeyFile'
                } else {
                    $rawKey = Get-ObjectProperty -Object $entry -Name 'serviceAccountKeyJson'
                    if ($rawKey -is [string]) {
                        $keyJsonText = $rawKey
                    } else {
                        $keyJsonText = ($rawKey | ConvertTo-Json -Depth 10)
                    }
                }
                try {
                    $parsedSa = $keyJsonText | ConvertFrom-Json
                } catch {
                    throw "gcloud: service account key is not valid JSON."
                }
                $saType = [string](Get-ObjectProperty -Object $parsedSa -Name 'type' -Default '')
                $saEmail = [string](Get-ObjectProperty -Object $parsedSa -Name 'client_email' -Default '')
                $saPrivKey = [string](Get-ObjectProperty -Object $parsedSa -Name 'private_key' -Default '')
                if ($saType -ne 'service_account' -or [string]::IsNullOrWhiteSpace($saEmail) -or [string]::IsNullOrWhiteSpace($saPrivKey)) {
                    throw "gcloud: service account key JSON must have type='service_account', client_email, and private_key."
                }
                $project = [string](Get-ObjectProperty -Object $entry -Name 'project' -Default '')
                if ([string]::IsNullOrWhiteSpace($project)) {
                    $project = [string](Get-ObjectProperty -Object $parsedSa -Name 'project_id' -Default '')
                }
                $region = [string](Get-ObjectProperty -Object $entry -Name 'region' -Default '')
                $zone = [string](Get-ObjectProperty -Object $entry -Name 'zone' -Default '')
                $setAdc = [bool](Get-ObjectProperty -Object $entry -Name 'setApplicationDefaultCredentials' -Default $true)
                $skipActivate = [bool](Get-ObjectProperty -Object $entry -Name 'skipActivate' -Default $false)

                $resolvedServices['gcloud'] = [ordered]@{
                    serviceAccountKeyJson            = $keyJsonText
                    clientEmail                      = $saEmail
                    project                          = $project
                    region                           = $region
                    zone                             = $zone
                    setApplicationDefaultCredentials = $setAdc
                    skipActivate                     = $skipActivate
                }
                $summary.Add("gcloud (account=$saEmail, project=$project)")
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

                $jiraOut = [ordered]@{
                    server       = $server
                    login        = $login
                    apiToken     = $apiToken
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
                $resolvedServices['gemini'] = [ordered]@{
                    apiKey              = $apiKey
                    googleCloudProject  = $gcpProject
                    googleCloudLocation = $gcpLoc
                    useVertexAi         = $useVertex
                }
                $summary.Add("gemini (apiKey=$(-not [string]::IsNullOrWhiteSpace($apiKey)), vertex=$useVertex)")
            }

            'claude' {
                $apiKey = Resolve-SecretValue -Object $entry -BaseName 'apiKey' -BaseDir $baseDir -Context 'claude'
                $oauthToken = Resolve-SecretValue -Object $entry -BaseName 'oauthToken' -BaseDir $baseDir -Context 'claude'
                if ([string]::IsNullOrWhiteSpace($apiKey) -and [string]::IsNullOrWhiteSpace($oauthToken)) {
                    throw "claude: specify apiKey* and/or oauthToken*."
                }
                $resolvedServices['claude'] = [ordered]@{
                    apiKey     = $apiKey
                    oauthToken = $oauthToken
                }
                $summary.Add("claude (apiKey=$(-not [string]::IsNullOrWhiteSpace($apiKey)), oauthToken=$(-not [string]::IsNullOrWhiteSpace($oauthToken)))")
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
    }

    $payload = [ordered]@{
        services       = $resolvedServices
        filterServices = @($filterServices)
        prune          = [bool]$Prune
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
