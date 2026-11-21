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

function Assert-Throws {
    param([string]$Name, [scriptblock]$Block, [string]$ExpectedPattern = '', [string]$MustNotContain = '')
    try {
        & $Block
        Write-Host "  [FAIL] $Name (expected exception, none thrown)"
        $script:Failed++
    } catch {
        $msg = $_.Exception.Message
        if ($ExpectedPattern -and $msg -notmatch $ExpectedPattern) {
            Write-Host "  [FAIL] $Name (unexpected error: $msg)"
            $script:Failed++
        } elseif ($MustNotContain -and $msg.Contains($MustNotContain)) {
            Write-Host "  [FAIL] $Name (error message leaked sensitive string!)"
            $script:Failed++
        } else {
            Write-Host "  [PASS] $Name"
            $script:Passed++
        }
    }
}

Write-Host "=== Running Secrets.ps1 Automated Tests ==="

# Validate JSON schema & example manifest parse cleanly
$schemaRaw = Get-Content -LiteralPath (Join-Path $RepoRoot 'secrets.schema.json') -Raw -Encoding UTF8
$schemaObj = $schemaRaw | ConvertFrom-Json
Assert-True "secrets.schema.json parses as valid JSON" ($null -ne $schemaObj.properties.github -and $null -ne $schemaObj.properties.gcloud -and $null -ne $schemaObj.properties.ssh)

$exampleRaw = Get-Content -LiteralPath (Join-Path $RepoRoot 'examples\secrets.example.json') -Raw -Encoding UTF8
$exampleObj = $exampleRaw | ConvertFrom-Json
Assert-True "examples/secrets.example.json parses as valid JSON" ($null -ne $exampleObj.github -and $null -ne $exampleObj.jira -and $null -ne $exampleObj.ssh)

# Create isolated temp directory for manifest/file fixture tests
$tmpDir = Join-Path ([System.IO.Path]::GetTempPath()) ("wsl-box-secrets-test-" + [Guid]::NewGuid().ToString('N').Substring(0, 8))
New-Item -ItemType Directory -Path $tmpDir -Force | Out-Null
New-Item -ItemType Directory -Path (Join-Path $tmpDir 'keys') -Force | Out-Null
New-Item -ItemType Directory -Path (Join-Path $tmpDir 'tokens') -Force | Out-Null

$prevEnvManifest = [Environment]::GetEnvironmentVariable('WSL_AGENT_SANDBOX_SECRETS_PATH')
$prevTestToken = [Environment]::GetEnvironmentVariable('TEST_SANDBOX_GH_TOKEN')
$prevTestGemini = [Environment]::GetEnvironmentVariable('TEST_SANDBOX_GEMINI_KEY')
$prevTestSshKey = [Environment]::GetEnvironmentVariable('TEST_SANDBOX_SSH_KEY')

try {
    # 1. Manifest path resolution precedence
    [Environment]::SetEnvironmentVariable('WSL_AGENT_SANDBOX_SECRETS_PATH', $null)
    $defaultPath = Resolve-SecretsManifestPath -ExplicitPath '' -Config $null -RepoRoot $RepoRoot
    Assert-True "Defaults manifest path to %USERPROFILE%\.wsl-agent-sandbox\secrets.json" ($defaultPath -eq (Join-Path $env:USERPROFILE '.wsl-agent-sandbox\secrets.json'))

    $cfgWithPtr = [pscustomobject]@{ secrets = [pscustomobject]@{ manifestPath = 'C:\CentralSecrets\box.json' } }
    $fromCfg = Resolve-SecretsManifestPath -ExplicitPath '' -Config $cfgWithPtr -RepoRoot $RepoRoot
    Assert-True "Uses box.json secrets.manifestPath when CLI and env are unset" ($fromCfg -eq 'C:\CentralSecrets\box.json')

    [Environment]::SetEnvironmentVariable('WSL_AGENT_SANDBOX_SECRETS_PATH', 'C:\EnvSecrets\secrets.json')
    $fromEnv = Resolve-SecretsManifestPath -ExplicitPath '' -Config $cfgWithPtr -RepoRoot $RepoRoot
    Assert-True "Env WSL_AGENT_SANDBOX_SECRETS_PATH overrides box.json pointer" ($fromEnv -eq 'C:\EnvSecrets\secrets.json')

    $fromExplicit = Resolve-SecretsManifestPath -ExplicitPath 'C:\CliSecrets\secrets.json' -Config $cfgWithPtr -RepoRoot $RepoRoot
    Assert-True "Explicit -SecretsPath overrides env and box.json" ($fromExplicit -eq 'C:\CliSecrets\secrets.json')
    [Environment]::SetEnvironmentVariable('WSL_AGENT_SANDBOX_SECRETS_PATH', $null)

    # 2. Prepare fixture files for all supported services
    [System.IO.File]::WriteAllText((Join-Path $tmpDir 'tokens\ado.txt'), "ado_pat_from_file_123`r`n", (New-Object System.Text.UTF8Encoding($false)))
    [System.IO.File]::WriteAllText((Join-Path $tmpDir 'tokens\claude.txt'), "sk-ant-from-file-456`n", (New-Object System.Text.UTF8Encoding($false)))
    [System.IO.File]::WriteAllText((Join-Path $tmpDir 'keys\gcp-sa.json'), (@{
        type         = 'service_account'
        project_id   = 'sandbox-gcp-proj'
        private_key  = "-----BEGIN PRIVATE KEY-----`nMOCKKEY`n-----END PRIVATE KEY-----`n"
        client_email = 'bot@sandbox-gcp-proj.iam.gserviceaccount.com'
    } | ConvertTo-Json), (New-Object System.Text.UTF8Encoding($false)))
    [System.IO.File]::WriteAllText((Join-Path $tmpDir 'keys\azure-sp.pem'), "-----BEGIN CERTIFICATE-----`nMOCKCERT`n-----END CERTIFICATE-----`n", (New-Object System.Text.UTF8Encoding($false)))
    [System.IO.File]::WriteAllText((Join-Path $tmpDir 'keys\kubeconfig.yaml'), "apiVersion: v1`nkind: Config`nclusters: []`n", (New-Object System.Text.UTF8Encoding($false)))
    [System.IO.File]::WriteAllText((Join-Path $tmpDir 'keys\npmrc'), "//registry.npmjs.org/:_authToken=npm_mock_789`n", (New-Object System.Text.UTF8Encoding($false)))
    [System.IO.File]::WriteAllText((Join-Path $tmpDir 'keys\ssh_deploy'), "-----BEGIN OPENSSH PRIVATE KEY-----`r`nMOCKSSHDEPLOYKEYBODY12345`r`n-----END OPENSSH PRIVATE KEY-----", (New-Object System.Text.UTF8Encoding($false)))
    [System.IO.File]::WriteAllText((Join-Path $tmpDir 'keys\ssh_deploy.pub'), "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIMOCKPUBKEY agent@sandbox`r`n", (New-Object System.Text.UTF8Encoding($false)))
    [System.IO.File]::WriteAllText((Join-Path $tmpDir 'keys\ssh_deploy-cert.pub'), "ssh-ed25519-cert-v01@openssh.com AAAAHHNzaC1lZDI1NTE5LWNlcnQtbW9jaw== agent@sandbox`r`n", (New-Object System.Text.UTF8Encoding($false)))
    [System.IO.File]::WriteAllText((Join-Path $tmpDir 'keys\ssh_host_inline'), "-----BEGIN OPENSSH PRIVATE KEY-----`nMOCKINLINEHOSTKEYBODY67890`n-----END OPENSSH PRIVATE KEY-----`n", (New-Object System.Text.UTF8Encoding($false)))
    [System.IO.File]::WriteAllText((Join-Path $tmpDir 'keys\known_hosts'), "# pinned hosts`r`nbastion.example.com ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIBASTIONHOSTKEY`r`n", (New-Object System.Text.UTF8Encoding($false)))

    [Environment]::SetEnvironmentVariable('TEST_SANDBOX_GH_TOKEN', 'ghp_from_env_999')
    [Environment]::SetEnvironmentVariable('TEST_SANDBOX_GEMINI_KEY', 'AIza_from_env_888')
    [Environment]::SetEnvironmentVariable('TEST_SANDBOX_SSH_KEY', "-----BEGIN OPENSSH PRIVATE KEY-----`nMOCKENVSSHKEYBODY54321`n-----END OPENSSH PRIVATE KEY-----")

    $fullManifestPath = Join-Path $tmpDir 'secrets.json'
    $fullManifest = [ordered]@{
        github = [ordered]@{
            enabled     = $true
            hostname    = 'github.com'
            tokenEnv    = 'TEST_SANDBOX_GH_TOKEN'
            user        = 'sandbox-bot'
            gitProtocol = 'https'
            setupGit    = $true
            exportEnv   = $true
        }
        aws = [ordered]@{
            enabled        = $true
            defaultProfile = 'dev'
            profiles       = @(
                [ordered]@{
                    name            = 'default'
                    accessKeyId     = 'AKIA_DEFAULT'
                    secretAccessKey = 'SECRET_DEFAULT'
                    region          = 'eu-north-1'
                    output          = 'json'
                },
                [ordered]@{
                    name            = 'dev'
                    accessKeyId     = 'AKIA_DEV'
                    secretAccessKey = 'SECRET_DEV'
                    sessionToken    = 'STS_TOKEN_DEV'
                    region          = 'us-east-1'
                }
            )
        }
        gcloud = [ordered]@{
            enabled                          = $true
            serviceAccountKeyFile            = 'keys\gcp-sa.json'
            region                           = 'europe-north1'
            setApplicationDefaultCredentials = $true
            skipActivate                     = $true
        }
        azure = [ordered]@{
            enabled         = $true
            clientId        = '11111111-1111-1111-1111-111111111111'
            tenantId        = '22222222-2222-2222-2222-222222222222'
            certificateFile = 'keys\azure-sp.pem'
            subscription    = '33333333-3333-3333-3333-333333333333'
            skipLogin       = $true
        }
        azureDevops = [ordered]@{
            enabled      = $true
            organization = 'https://dev.azure.com/demo-org'
            project      = 'demo-proj'
            patFile      = 'tokens\ado.txt'
        }
        jira = [ordered]@{
            enabled      = $true
            server       = 'https://demo.atlassian.net'
            login        = 'bot@demo.example'
            apiToken     = 'ATATT_MOCK_123'
            installation = 'cloud'
            authType     = 'basic'
            projectKey   = 'DEMO'
        }
        upcloud = [ordered]@{
            enabled   = $true
            token     = 'ucat_mock_456'
            exportEnv = $true
        }
        kubectl = [ordered]@{
            enabled        = $true
            kubeconfigFile = 'keys\kubeconfig.yaml'
        }
        gemini = [ordered]@{
            enabled   = $true
            apiKeyEnv = 'TEST_SANDBOX_GEMINI_KEY'
        }
        claude = [ordered]@{
            enabled    = $true
            apiKeyFile = 'tokens\claude.txt'
        }
        ssh = [ordered]@{
            enabled             = $true
            defaultKey          = 'deploy'
            serverAliveInterval = 60
            connectTimeout      = 15
            batchMode           = $true
            knownHostsFile      = 'keys\known_hosts'
            keys                = @(
                [ordered]@{
                    name            = 'deploy'
                    privateKeyFile  = 'keys\ssh_deploy'
                    publicKeyFile   = 'keys\ssh_deploy.pub'
                    certificateFile = 'keys\ssh_deploy-cert.pub'
                },
                [ordered]@{
                    name          = 'env-key'
                    privateKeyEnv = 'TEST_SANDBOX_SSH_KEY'
                }
            )
            hosts               = @(
                [ordered]@{
                    name      = 'bastion'
                    hostName  = 'bastion.example.com'
                    user      = 'jump'
                    port      = 2222
                    key       = 'deploy'
                },
                [ordered]@{
                    name           = 'staging-web'
                    hostName       = '203.0.113.10'
                    user           = 'deploy'
                    proxyJump      = 'bastion'
                    privateKeyFile = 'keys\ssh_host_inline'
                    knownHost      = '203.0.113.10 ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAISTAGINGHOSTKEY'
                }
            )
        }
        env = [ordered]@{
            CUSTOM_MACHINE_TOKEN = 'tok_custom_111'
            FILE_BASED_TOKEN     = [ordered]@{ valueFile = 'tokens\ado.txt' }
        }
        files = @(
            [ordered]@{
                name       = 'npmrc'
                sourcePath = 'keys\npmrc'
                targetPath = '~/.npmrc'
                mode       = '0600'
            }
        )
    }
    [System.IO.File]::WriteAllText($fullManifestPath, ($fullManifest | ConvertTo-Json -Depth 10), (New-Object System.Text.UTF8Encoding($false)))

    $res = Build-SeedSecretsPayload -ManifestPath $fullManifestPath -AgentName 'agent' -Prune
    $svcs = $res.Payload.services
    Assert-True "Builds full payload with all 13 service types" ($svcs.Count -eq 13)
    Assert-True "Resolves github token from Windows env var" ($svcs['github'].token -eq 'ghp_from_env_999')
    Assert-True "Resolves multi-profile AWS credentials" ($svcs['aws'].profiles.Count -eq 2 -and $svcs['aws'].defaultProfile -eq 'dev')
    Assert-True "Infers gcloud project from service account JSON key" ($svcs['gcloud'].project -eq 'sandbox-gcp-proj' -and $svcs['gcloud'].clientEmail -eq 'bot@sandbox-gcp-proj.iam.gserviceaccount.com')
    Assert-True "Resolves azure PEM certificate with LF normalization" ($svcs['azure'].certificatePem.Contains('MOCKCERT') -and -not $svcs['azure'].certificatePem.Contains("`r"))
    Assert-True "Resolves azureDevops PAT from relative tokenFile (trimmed)" ($svcs['azureDevops'].pat -eq 'ado_pat_from_file_123')
    Assert-True "Resolves claude API key from relative file" ($svcs['claude'].apiKey -eq 'sk-ant-from-file-456')
    Assert-True "Resolves ssh keys (named + env + inline host key), certs, hosts, and knownHosts" (
        $svcs['ssh'].keys.Count -eq 3 -and
        $svcs['ssh'].hosts.Count -eq 2 -and
        $svcs['ssh'].knownHosts.Count -eq 2 -and
        $svcs['ssh'].defaultKey -eq 'deploy' -and
        $svcs['ssh'].keys[0].privateKey.EndsWith("`n") -and
        (-not $svcs['ssh'].keys[0].privateKey.Contains("`r")) -and
        $svcs['ssh'].keys[0].certificate.StartsWith('ssh-ed25519-cert-v01@openssh.com') -and
        $svcs['ssh'].hosts[1].key -eq 'host-staging-web'
    )
    Assert-True "Expands ~/ in files targetPath to /home/agent/..." ($svcs['files'][0].targetPath -eq '/home/agent/.npmrc')
    Assert-True "Summary contains zero secret values" (-not (($res.Summary -join ' ') -match 'ghp_from_env_999|SECRET_DEFAULT|ado_pat_from_file_123|ATATT_MOCK_123|ucat_mock_456|AIza_from_env_888|sk-ant-from-file-456|MOCKSSHDEPLOYKEYBODY12345|MOCKINLINEHOSTKEYBODY67890|MOCKENVSSHKEYBODY54321'))

    # 3. Selective service filtering (including comma-separated & case-insensitive)
    $filtered = Build-SeedSecretsPayload -ManifestPath $fullManifestPath -AgentName 'agent' -Services @('GitHub,jira,SSH')
    Assert-True "Selective -Services filters to only github, jira, and ssh" ($filtered.Payload.services.Count -eq 3 -and $filtered.Payload.services.Contains('github') -and $filtered.Payload.services.Contains('jira') -and $filtered.Payload.services.Contains('ssh'))

    # 4. kubectl service-account token mode
    $kcTokenManifest = Join-Path $tmpDir 'kc-token.json'
    [System.IO.File]::WriteAllText($kcTokenManifest, (@{
        kubectl = @{
            server    = 'https://k8s.sandbox.local:6443'
            token     = 'eyJhbGciOiJSUzI1NiJ9.mock'
            namespace = 'sandbox-ns'
        }
    } | ConvertTo-Json -Depth 6), (New-Object System.Text.UTF8Encoding($false)))
    $kcRes = Build-SeedSecretsPayload -ManifestPath $kcTokenManifest -AgentName 'agent'
    Assert-True "Builds kubectl token-mode payload cleanly" ($kcRes.Payload.services['kubectl'].mode -eq 'token' -and $kcRes.Payload.services['kubectl'].namespace -eq 'sandbox-ns')

    # 5. Disabled service is skipped cleanly
    $disabledManifest = Join-Path $tmpDir 'disabled.json'
    [System.IO.File]::WriteAllText($disabledManifest, (@{
        github = @{ enabled = $false; token = 'ignored' }
        upcloud = @{ enabled = $true; token = 'ucat_active' }
    } | ConvertTo-Json -Depth 6), (New-Object System.Text.UTF8Encoding($false)))
    $disRes = Build-SeedSecretsPayload -ManifestPath $disabledManifest -AgentName 'agent'
    Assert-True "Skips disabled services without failing" ($disRes.Payload.services.Count -eq 1 -and $disRes.Payload.services.Contains('upcloud') -and ($disRes.SkippedDisabled -contains 'github'))

    # 6. Negative / security validation tests
    Assert-Throws "Rejects unknown service name in -Services filter" {
        Build-SeedSecretsPayload -ManifestPath $fullManifestPath -AgentName 'agent' -Services @('nonexistent')
    } 'Unknown service'

    $ambigManifest = Join-Path $tmpDir 'ambig.json'
    [System.IO.File]::WriteAllText($ambigManifest, (@{
        github = @{ token = 'ghp_secret_value_should_not_leak'; tokenFile = 'tokens\ado.txt' }
    } | ConvertTo-Json -Depth 6), (New-Object System.Text.UTF8Encoding($false)))
    Assert-Throws "Rejects specifying both token and tokenFile without leaking token" {
        Build-SeedSecretsPayload -ManifestPath $ambigManifest -AgentName 'agent'
    } 'specify only one' 'ghp_secret_value_should_not_leak'

    $badSaManifest = Join-Path $tmpDir 'bad-sa.json'
    [System.IO.File]::WriteAllText($badSaManifest, (@{
        gcloud = @{ serviceAccountKeyJson = '{"type":"authorized_user"}' }
    } | ConvertTo-Json -Depth 6), (New-Object System.Text.UTF8Encoding($false)))
    Assert-Throws "Rejects non-service-account GCP key JSON" {
        Build-SeedSecretsPayload -ManifestPath $badSaManifest -AgentName 'agent'
    } 'service_account'

    $bothAzManifest = Join-Path $tmpDir 'both-az.json'
    [System.IO.File]::WriteAllText($bothAzManifest, (@{
        azure = @{ clientId = 'a'; tenantId = 'b'; clientSecret = 's'; certificateFile = 'keys\azure-sp.pem' }
    } | ConvertTo-Json -Depth 6), (New-Object System.Text.UTF8Encoding($false)))
    Assert-Throws "Rejects specifying both azure clientSecret and certificateFile" {
        Build-SeedSecretsPayload -ManifestPath $bothAzManifest -AgentName 'agent'
    } 'not both'

    $badEnvManifest = Join-Path $tmpDir 'bad-env.json'
    [System.IO.File]::WriteAllText($badEnvManifest, (@{
        env = @{ LD_PRELOAD = '/tmp/evil.so' }
    } | ConvertTo-Json -Depth 6), (New-Object System.Text.UTF8Encoding($false)))
    Assert-Throws "Rejects overriding protected system env var (LD_PRELOAD)" {
        Build-SeedSecretsPayload -ManifestPath $badEnvManifest -AgentName 'agent'
    } 'protected system environment variable'

    $badPathManifest = Join-Path $tmpDir 'bad-path.json'
    [System.IO.File]::WriteAllText($badPathManifest, (@{
        files = @(@{ name = 'escape'; sourcePath = 'keys\npmrc'; targetPath = '/etc/shadow'; mode = '0600' })
    } | ConvertTo-Json -Depth 6), (New-Object System.Text.UTF8Encoding($false)))
    Assert-Throws "Rejects files targetPath outside /home/agent/" {
        Build-SeedSecretsPayload -ManifestPath $badPathManifest -AgentName 'agent'
    } 'must be inside'

    $travPathManifest = Join-Path $tmpDir 'trav-path.json'
    [System.IO.File]::WriteAllText($travPathManifest, (@{
        files = @(@{ name = 'trav'; sourcePath = 'keys\npmrc'; targetPath = '~/../../etc/passwd'; mode = '0600' })
    } | ConvertTo-Json -Depth 6), (New-Object System.Text.UTF8Encoding($false)))
    Assert-Throws "Rejects path traversal in files targetPath" {
        Build-SeedSecretsPayload -ManifestPath $travPathManifest -AgentName 'agent'
    } 'relative segments'

    $unknownTopManifest = Join-Path $tmpDir 'unknown-top.json'
    [System.IO.File]::WriteAllText($unknownTopManifest, (@{
        githbu = @{ token = 'abc' }
    } | ConvertTo-Json -Depth 6), (New-Object System.Text.UTF8Encoding($false)))
    Assert-Throws "Rejects unknown top-level service typo" {
        Build-SeedSecretsPayload -ManifestPath $unknownTopManifest -AgentName 'agent'
    } 'Unknown top-level service'

    # 7. SSH-specific security & validation tests
    $badSshKeyManifest = Join-Path $tmpDir 'bad-ssh-key.json'
    [System.IO.File]::WriteAllText($badSshKeyManifest, (@{
        ssh = @{
            keys = @(@{ name = 'bad'; privateKey = 'ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAISECRETPUBNOTPRIV' })
        }
    } | ConvertTo-Json -Depth 6), (New-Object System.Text.UTF8Encoding($false)))
    Assert-Throws "Rejects public key passed as SSH privateKey without leaking material" {
        Build-SeedSecretsPayload -ManifestPath $badSshKeyManifest -AgentName 'agent'
    } 'invalid SSH private key format' 'AAAAISECRETPUBNOTPRIV'

    $badSshKeyNameManifest = Join-Path $tmpDir 'bad-ssh-keyname.json'
    [System.IO.File]::WriteAllText($badSshKeyNameManifest, (@{
        ssh = @{
            keys = @(@{ name = '../escape'; privateKeyFile = 'keys\ssh_deploy' })
        }
    } | ConvertTo-Json -Depth 6), (New-Object System.Text.UTF8Encoding($false)))
    Assert-Throws "Rejects path traversal in ssh.keys name" {
        Build-SeedSecretsPayload -ManifestPath $badSshKeyNameManifest -AgentName 'agent'
    } 'invalid name'

    $badSshDefaultKeyManifest = Join-Path $tmpDir 'bad-ssh-defkey.json'
    [System.IO.File]::WriteAllText($badSshDefaultKeyManifest, (@{
        ssh = @{
            defaultKey = 'missing-key'
            keys       = @(@{ name = 'deploy'; privateKeyFile = 'keys\ssh_deploy' })
        }
    } | ConvertTo-Json -Depth 6), (New-Object System.Text.UTF8Encoding($false)))
    Assert-Throws "Rejects ssh.defaultKey referencing unknown key" {
        Build-SeedSecretsPayload -ManifestPath $badSshDefaultKeyManifest -AgentName 'agent'
    } 'does not match any key'

    $badSshHostBothKeysManifest = Join-Path $tmpDir 'bad-ssh-bothkeys.json'
    [System.IO.File]::WriteAllText($badSshHostBothKeysManifest, (@{
        ssh = @{
            keys  = @(@{ name = 'deploy'; privateKeyFile = 'keys\ssh_deploy' })
            hosts = @(@{ name = 'web'; hostName = 'web.example.com'; key = 'deploy'; privateKeyFile = 'keys\ssh_host_inline' })
        }
    } | ConvertTo-Json -Depth 6), (New-Object System.Text.UTF8Encoding($false)))
    Assert-Throws "Rejects ssh host specifying both key and privateKeyFile" {
        Build-SeedSecretsPayload -ManifestPath $badSshHostBothKeysManifest -AgentName 'agent'
    } 'not both'

    $badSshInjectionManifest = Join-Path $tmpDir 'bad-ssh-inject.json'
    [System.IO.File]::WriteAllText($badSshInjectionManifest, (@{
        ssh = @{
            hosts = @(@{ name = 'web'; hostName = "web.example.com`nProxyCommand id"; key = '' })
        }
    } | ConvertTo-Json -Depth 6), (New-Object System.Text.UTF8Encoding($false)))
    Assert-Throws "Rejects newline/directive injection in ssh hostName" {
        Build-SeedSecretsPayload -ManifestPath $badSshInjectionManifest -AgentName 'agent'
    } 'invalid newline or control characters'

    $badSshWildcardHostManifest = Join-Path $tmpDir 'bad-ssh-wild.json'
    [System.IO.File]::WriteAllText($badSshWildcardHostManifest, (@{
        ssh = @{
            hosts = @(@{ name = '*'; hostName = 'example.com' })
        }
    } | ConvertTo-Json -Depth 6), (New-Object System.Text.UTF8Encoding($false)))
    Assert-Throws "Rejects wildcard '*' as ssh.hosts entry name" {
        Build-SeedSecretsPayload -ManifestPath $badSshWildcardHostManifest -AgentName 'agent'
    } "cannot be '\*'"

    $badSshPortManifest = Join-Path $tmpDir 'bad-ssh-port.json'
    [System.IO.File]::WriteAllText($badSshPortManifest, (@{
        ssh = @{
            hosts = @(@{ name = 'web'; hostName = 'web.example.com'; port = 70000 })
        }
    } | ConvertTo-Json -Depth 6), (New-Object System.Text.UTF8Encoding($false)))
    Assert-Throws "Rejects out-of-range ssh host port" {
        Build-SeedSecretsPayload -ManifestPath $badSshPortManifest -AgentName 'agent'
    } 'between 1 and 65535'

    $emptySshManifest = Join-Path $tmpDir 'empty-ssh.json'
    [System.IO.File]::WriteAllText($emptySshManifest, (@{
        ssh = @{ enabled = $true }
    } | ConvertTo-Json -Depth 6), (New-Object System.Text.UTF8Encoding($false)))
    Assert-Throws "Rejects empty enabled ssh section" {
        Build-SeedSecretsPayload -ManifestPath $emptySshManifest -AgentName 'agent'
    } 'specify at least one'
} finally {
    [Environment]::SetEnvironmentVariable('WSL_AGENT_SANDBOX_SECRETS_PATH', $prevEnvManifest)
    [Environment]::SetEnvironmentVariable('TEST_SANDBOX_GH_TOKEN', $prevTestToken)
    [Environment]::SetEnvironmentVariable('TEST_SANDBOX_GEMINI_KEY', $prevTestGemini)
    [Environment]::SetEnvironmentVariable('TEST_SANDBOX_SSH_KEY', $prevTestSshKey)
    if (Test-Path -LiteralPath $tmpDir) {
        Remove-Item -LiteralPath $tmpDir -Recurse -Force
    }
}

Write-Host ""
Write-Host "=== Secrets.Tests.ps1 Summary: PASS=$script:Passed FAIL=$script:Failed ==="
if ($script:Failed -gt 0) {
    exit 1
}
exit 0
