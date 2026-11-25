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
Assert-True "secrets.schema.json parses as valid JSON" ($null -ne $schemaObj.properties.github -and $null -ne $schemaObj.properties.git -and $null -ne $schemaObj.properties.gcloud -and $null -ne $schemaObj.properties.ssh)

$exampleRaw = Get-Content -LiteralPath (Join-Path $RepoRoot 'examples\secrets.example.json') -Raw -Encoding UTF8
$exampleObj = $exampleRaw | ConvertFrom-Json
Assert-True "examples/secrets.example.json parses as valid JSON" ($null -ne $exampleObj.github -and $null -ne $exampleObj.git -and $null -ne $exampleObj.jira -and $null -ne $exampleObj.ssh)

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
    [System.IO.File]::WriteAllText((Join-Path $tmpDir 'keys\git_github'), "-----BEGIN OPENSSH PRIVATE KEY-----`r`nMOCKGITGITHUBKEYBODY11111`r`n-----END OPENSSH PRIVATE KEY-----", (New-Object System.Text.UTF8Encoding($false)))
    [System.IO.File]::WriteAllText((Join-Path $tmpDir 'keys\git_github.pub'), "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIMOCKGITPUBKEY bot@sandbox`r`n", (New-Object System.Text.UTF8Encoding($false)))
    [System.IO.File]::WriteAllText((Join-Path $tmpDir 'keys\git_signing'), "-----BEGIN OPENSSH PRIVATE KEY-----`nMOCKGITSIGNINGKEYBODY22222`n-----END OPENSSH PRIVATE KEY-----`n", (New-Object System.Text.UTF8Encoding($false)))
    [System.IO.File]::WriteAllText((Join-Path $tmpDir 'keys\git_deploy_repo'), "-----BEGIN OPENSSH PRIVATE KEY-----`nMOCKGITDEPLOYKEYBODY33333`n-----END OPENSSH PRIVATE KEY-----`n", (New-Object System.Text.UTF8Encoding($false)))
    [System.IO.File]::WriteAllText((Join-Path $tmpDir 'keys\allowed_signers'), "bot@example.com namespaces=`"git`" ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIMOCKSIGNERKEY`r`n", (New-Object System.Text.UTF8Encoding($false)))

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
        git = [ordered]@{
            enabled   = $true
            userName  = 'Sandbox Bot'
            userEmail = 'sandbox-bot@example.com'
            keys      = @(
                [ordered]@{
                    name           = 'github-git'
                    privateKeyFile = 'keys\git_github'
                    publicKeyFile  = 'keys\git_github.pub'
                }
            )
            hosts     = @(
                [ordered]@{
                    name              = 'github.com'
                    key               = 'github-git'
                    knownHost         = 'github.com ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIOMqqnkVzrm0SdG6UOoqKLsabgH5C9okWi0dh2l9GKJl'
                    rewriteHttpsToSsh = $true
                },
                [ordered]@{
                    name           = 'github-repo-a'
                    hostName       = 'github.com'
                    privateKeyFile = 'keys\git_deploy_repo'
                }
            )
            signing   = [ordered]@{
                enabled            = $true
                privateKeyFile     = 'keys\git_signing'
                signCommits        = $true
                signTags           = $true
                allowedSignersFile = 'keys\allowed_signers'
            }
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
    Assert-True "Builds full payload with all 14 service types" ($svcs.Count -eq 14)
    Assert-True "Resolves github token from Windows env var" ($svcs['github'].token -eq 'ghp_from_env_999')
    Assert-True "Resolves git SSH keys, hosts (default hostName/user + deploy alias), signing, and allowedSigners" (
        $svcs['git'].userName -eq 'Sandbox Bot' -and
        $svcs['git'].userEmail -eq 'sandbox-bot@example.com' -and
        $svcs['git'].keys.Count -eq 3 -and
        $svcs['git'].hosts.Count -eq 2 -and
        $svcs['git'].hosts[0].hostName -eq 'github.com' -and
        $svcs['git'].hosts[0].user -eq 'git' -and
        $svcs['git'].hosts[0].rewriteHttpsToSsh -eq $true -and
        $svcs['git'].hosts[0].hasPinnedKnownHost -eq $true -and
        $svcs['git'].hosts[1].key -eq 'host-github-repo-a' -and
        $svcs['git'].hosts[1].hasPinnedKnownHost -eq $false -and
        $svcs['git'].signing.key -eq 'signing' -and
        $svcs['git'].signing.signCommits -eq $true -and
        $svcs['git'].signing.signTags -eq $true -and
        $svcs['git'].signing.allowedSigners.Count -eq 1 -and
        $svcs['git'].knownHosts.Count -eq 1 -and
        $svcs['git'].batchMode -eq $true
    )
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
    Assert-True "Summary contains zero secret values" (-not (($res.Summary -join ' ') -match 'ghp_from_env_999|SECRET_DEFAULT|ado_pat_from_file_123|ATATT_MOCK_123|ucat_mock_456|AIza_from_env_888|sk-ant-from-file-456|MOCKSSHDEPLOYKEYBODY12345|MOCKINLINEHOSTKEYBODY67890|MOCKENVSSHKEYBODY54321|MOCKGITGITHUBKEYBODY11111|MOCKGITSIGNINGKEYBODY22222|MOCKGITDEPLOYKEYBODY33333'))

    # 3. Selective service filtering (including comma-separated & case-insensitive)
    $filtered = Build-SeedSecretsPayload -ManifestPath $fullManifestPath -AgentName 'agent' -Services @('GitHub,GIT,jira,SSH')
    Assert-True "Selective -Services filters to only github, git, jira, and ssh" ($filtered.Payload.services.Count -eq 4 -and $filtered.Payload.services.Contains('github') -and $filtered.Payload.services.Contains('git') -and $filtered.Payload.services.Contains('jira') -and $filtered.Payload.services.Contains('ssh'))

    # 3b. Shorthand single-host git mode
    $gitShortManifest = Join-Path $tmpDir 'git-shorthand.json'
    [System.IO.File]::WriteAllText($gitShortManifest, (@{
        git = @{
            host           = 'gitlab.com'
            port           = 2222
            privateKeyFile = 'keys\git_github'
            publicKeyFile  = 'keys\git_github.pub'
            userName       = 'Shorthand Bot'
            userEmail      = 'short@example.com'
            signing        = @{ enabled = $true }
        }
    } | ConvertTo-Json -Depth 6), (New-Object System.Text.UTF8Encoding($false)))
    $gitShortRes = Build-SeedSecretsPayload -ManifestPath $gitShortManifest -AgentName 'agent'
    $gs = $gitShortRes.Payload.services['git']
    Assert-True "Builds shorthand single-host git payload cleanly (inherits default key for host & signing)" (
        $gs.keys.Count -eq 1 -and
        $gs.keys[0].name -eq 'default' -and
        $gs.hosts.Count -eq 1 -and
        $gs.hosts[0].name -eq 'gitlab.com' -and
        $gs.hosts[0].hostName -eq 'gitlab.com' -and
        $gs.hosts[0].user -eq 'git' -and
        $gs.hosts[0].port -eq 2222 -and
        $gs.hosts[0].key -eq 'default' -and
        $gs.signing.key -eq 'default'
    )

    # 3c. Multi-project gcloud mode with separate Service Accounts
    [System.IO.File]::WriteAllText((Join-Path $tmpDir 'keys\gcp-sa-2.json'), (@{
        type         = 'service_account'
        project_id   = 'sandbox-gcp-staging'
        private_key  = "-----BEGIN PRIVATE KEY-----`nMOCKKEY2`n-----END PRIVATE KEY-----`n"
        client_email = 'staging-bot@sandbox-gcp-staging.iam.gserviceaccount.com'
    } | ConvertTo-Json), (New-Object System.Text.UTF8Encoding($false)))
    $gcloudMultiManifest = Join-Path $tmpDir 'gcloud-multi.json'
    [System.IO.File]::WriteAllText($gcloudMultiManifest, (@{
        gcloud = @{
            defaultProject = 'staging'
            region         = 'europe-north1'
            skipActivate   = $true
            projects       = @(
                @{
                    name                  = 'dev'
                    serviceAccountKeyFile = 'keys\gcp-sa.json'
                },
                @{
                    name                  = 'staging'
                    serviceAccountKeyFile = 'keys\gcp-sa-2.json'
                    region                = 'europe-west1'
                }
            )
        }
    } | ConvertTo-Json -Depth 6), (New-Object System.Text.UTF8Encoding($false)))
    $gcMultiRes = Build-SeedSecretsPayload -ManifestPath $gcloudMultiManifest -AgentName 'agent'
    $gcm = $gcMultiRes.Payload.services['gcloud']
    Assert-True "Builds multi-project gcloud payload with separate service accounts and active defaultProject" (
        $gcm.projects.Count -eq 2 -and
        $gcm.defaultProject -eq 'staging' -and
        $gcm.project -eq 'sandbox-gcp-staging' -and
        $gcm.clientEmail -eq 'staging-bot@sandbox-gcp-staging.iam.gserviceaccount.com' -and
        $gcm.region -eq 'europe-west1' -and
        $gcm.projects[0].name -eq 'dev' -and
        $gcm.projects[0].project -eq 'sandbox-gcp-proj' -and
        $gcm.projects[0].region -eq 'europe-north1' -and
        $gcm.projects[1].name -eq 'staging' -and
        $gcm.projects[1].project -eq 'sandbox-gcp-staging' -and
        (($gcMultiRes.Summary -join ' ') -match 'projects=dev:sandbox-gcp-proj, staging:sandbox-gcp-staging; default=staging')
    )

    $badGcloudDupManifest = Join-Path $tmpDir 'gcloud-dup.json'
    [System.IO.File]::WriteAllText($badGcloudDupManifest, (@{
        gcloud = @{
            projects = @(
                @{ name = 'dev'; serviceAccountKeyFile = 'keys\gcp-sa.json' },
                @{ name = 'dev'; serviceAccountKeyFile = 'keys\gcp-sa-2.json' }
            )
        }
    } | ConvertTo-Json -Depth 6), (New-Object System.Text.UTF8Encoding($false)))
    Assert-Throws "Rejects duplicate configuration name in gcloud.projects" {
        Build-SeedSecretsPayload -ManifestPath $badGcloudDupManifest -AgentName 'agent'
    } 'duplicate configuration'

    $badGcloudDefManifest = Join-Path $tmpDir 'gcloud-bad-def.json'
    [System.IO.File]::WriteAllText($badGcloudDefManifest, (@{
        gcloud = @{
            defaultProject = 'nonexistent'
            projects       = @(
                @{ name = 'dev'; serviceAccountKeyFile = 'keys\gcp-sa.json' }
            )
        }
    } | ConvertTo-Json -Depth 6), (New-Object System.Text.UTF8Encoding($false)))
    Assert-Throws "Rejects gcloud.defaultProject referencing unknown project" {
        Build-SeedSecretsPayload -ManifestPath $badGcloudDefManifest -AgentName 'agent'
    } 'does not match any configured project'

    # 3d. Multi-profile GitHub fine-grained PAT mode (with proxyInject)
    $ghMultiManifest = Join-Path $tmpDir 'github-multi.json'
    [System.IO.File]::WriteAllText($ghMultiManifest, (@{
        github = @{
            defaultProfile = 'work-org'
            user           = 'Thorup'
            gitProtocol    = 'ssh'
            setupGit       = $false
            proxyInject    = $true
            profiles       = @(
                @{
                    name  = 'personal'
                    owner = 'Thorup'
                    token = 'github_pat_personal_secret_111'
                },
                @{
                    name  = 'work-org'
                    owner = 'acme-org'
                    token = 'github_pat_org_secret_222'
                }
            )
        }
    } | ConvertTo-Json -Depth 6), (New-Object System.Text.UTF8Encoding($false)))
    $ghMultiRes = Build-SeedSecretsPayload -ManifestPath $ghMultiManifest -AgentName 'agent'
    $ghm = $ghMultiRes.Payload.services['github']
    $ghRoute = $ghMultiRes.Payload.proxyRoutes['github']
    $ghSvcJson = ($ghm | ConvertTo-Json -Depth 6)
    Assert-True "Builds multi-profile github payload with per-profile proxyInject placeholders and tokenProfiles map" (
        $ghm.profiles.Count -eq 2 -and
        $ghm.defaultProfile -eq 'work-org' -and
        $ghm.owner -eq 'acme-org' -and
        $ghm.profiles[0].name -eq 'personal' -and
        $ghm.profiles[0].owner -eq 'Thorup' -and
        $ghm.profiles[0].token -match '^sandbox-proxy-github-[0-9a-f]{48}$' -and
        $ghm.profiles[1].name -eq 'work-org' -and
        $ghm.profiles[1].owner -eq 'acme-org' -and
        $ghm.profiles[1].token -match '^sandbox-proxy-github-[0-9a-f]{48}$' -and
        $ghm.profiles[0].token -ne $ghm.profiles[1].token -and
        $ghm.token -eq $ghm.profiles[1].token -and
        $ghRoute.expectedTokens.Count -eq 2 -and
        $ghRoute.tokenProfiles[$ghm.profiles[0].token].injectHeaders['Authorization'] -eq 'Bearer github_pat_personal_secret_111' -and
        $ghRoute.tokenProfiles[$ghm.profiles[1].token].injectHeaders['Authorization'] -eq 'Bearer github_pat_org_secret_222' -and
        $ghSvcJson -notmatch 'github_pat_personal_secret_111|github_pat_org_secret_222' -and
        (($ghMultiRes.Summary -join ' ') -match 'profiles=personal:Thorup, work-org:acme-org; default=work-org')
    )

    $badGhDupManifest = Join-Path $tmpDir 'github-dup.json'
    [System.IO.File]::WriteAllText($badGhDupManifest, (@{
        github = @{
            profiles = @(
                @{ name = 'personal'; token = 'github_pat_1' },
                @{ name = 'personal'; token = 'github_pat_2' }
            )
        }
    } | ConvertTo-Json -Depth 6), (New-Object System.Text.UTF8Encoding($false)))
    Assert-Throws "Rejects duplicate profile name in github.profiles" {
        Build-SeedSecretsPayload -ManifestPath $badGhDupManifest -AgentName 'agent'
    } 'duplicate profile name'

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

    # 8. Git SSH-specific security & validation tests
    $badGitKeyManifest = Join-Path $tmpDir 'bad-git-key.json'
    [System.IO.File]::WriteAllText($badGitKeyManifest, (@{
        git = @{
            privateKey = 'ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIGITSECRETPUBNOTPRIV'
        }
    } | ConvertTo-Json -Depth 6), (New-Object System.Text.UTF8Encoding($false)))
    Assert-Throws "Rejects public key passed as git privateKey without leaking material" {
        Build-SeedSecretsPayload -ManifestPath $badGitKeyManifest -AgentName 'agent'
    } 'invalid SSH private key format' 'AAAAIGITSECRETPUBNOTPRIV'

    $bothGitKeysManifest = Join-Path $tmpDir 'both-git-keys.json'
    [System.IO.File]::WriteAllText($bothGitKeysManifest, (@{
        git = @{
            privateKeyFile = 'keys\git_github'
            keys           = @(@{ name = 'gh'; privateKeyFile = 'keys\git_github' })
        }
    } | ConvertTo-Json -Depth 6), (New-Object System.Text.UTF8Encoding($false)))
    Assert-Throws "Rejects specifying both top-level git privateKeyFile and keys" {
        Build-SeedSecretsPayload -ManifestPath $bothGitKeysManifest -AgentName 'agent'
    } 'not both'

    $bothGitHostsManifest = Join-Path $tmpDir 'both-git-hosts.json'
    [System.IO.File]::WriteAllText($bothGitHostsManifest, (@{
        git = @{
            host  = 'github.com'
            hosts = @(@{ name = 'gitlab.com'; privateKeyFile = 'keys\git_github' })
        }
    } | ConvertTo-Json -Depth 6), (New-Object System.Text.UTF8Encoding($false)))
    Assert-Throws "Rejects specifying both top-level git host and hosts" {
        Build-SeedSecretsPayload -ManifestPath $bothGitHostsManifest -AgentName 'agent'
    } 'not both'

    $reservedGitKeyManifest = Join-Path $tmpDir 'reserved-git-key.json'
    [System.IO.File]::WriteAllText($reservedGitKeyManifest, (@{
        git = @{
            keys = @(@{ name = 'allowed_signers'; privateKeyFile = 'keys\git_github' })
        }
    } | ConvertTo-Json -Depth 6), (New-Object System.Text.UTF8Encoding($false)))
    Assert-Throws "Rejects reserved key name 'allowed_signers' in git.keys" {
        Build-SeedSecretsPayload -ManifestPath $reservedGitKeyManifest -AgentName 'agent'
    } 'reserved'

    $wildcardGitHostManifest = Join-Path $tmpDir 'wildcard-git-host.json'
    [System.IO.File]::WriteAllText($wildcardGitHostManifest, (@{
        git = @{
            hosts = @(@{ name = '*'; hostName = 'github.com' })
        }
    } | ConvertTo-Json -Depth 6), (New-Object System.Text.UTF8Encoding($false)))
    Assert-Throws "Rejects wildcard '*' as git.hosts entry name" {
        Build-SeedSecretsPayload -ManifestPath $wildcardGitHostManifest -AgentName 'agent'
    } "cannot be '\*'"

    $wildcardRewriteManifest = Join-Path $tmpDir 'wildcard-rewrite.json'
    [System.IO.File]::WriteAllText($wildcardRewriteManifest, (@{
        git = @{
            hosts = @(@{ name = '*.github.com'; hostName = 'github.com'; rewriteHttpsToSsh = $true })
        }
    } | ConvertTo-Json -Depth 6), (New-Object System.Text.UTF8Encoding($false)))
    Assert-Throws "Rejects rewriteHttpsToSsh on wildcard git host alias" {
        Build-SeedSecretsPayload -ManifestPath $wildcardRewriteManifest -AgentName 'agent'
    } 'wildcard host patterns'

    $badGitIdentityManifest = Join-Path $tmpDir 'bad-git-identity.json'
    [System.IO.File]::WriteAllText($badGitIdentityManifest, (@{
        git = @{
            userName = "Bot`n[core]`nsshCommand = id"
        }
    } | ConvertTo-Json -Depth 6), (New-Object System.Text.UTF8Encoding($false)))
    Assert-Throws "Rejects newline/config injection in git.userName" {
        Build-SeedSecretsPayload -ManifestPath $badGitIdentityManifest -AgentName 'agent'
    } 'invalid newline or control characters'

    $badAllowedSignerManifest = Join-Path $tmpDir 'bad-allowed-signer.json'
    [System.IO.File]::WriteAllText($badAllowedSignerManifest, (@{
        git = @{
            privateKeyFile = 'keys\git_github'
            signing        = @{
                enabled        = $true
                allowedSigners = @('-----BEGIN OPENSSH PRIVATE KEY-----')
            }
        }
    } | ConvertTo-Json -Depth 6), (New-Object System.Text.UTF8Encoding($false)))
    Assert-Throws "Rejects private key passed in git.signing.allowedSigners" {
        Build-SeedSecretsPayload -ManifestPath $badAllowedSignerManifest -AgentName 'agent'
    } 'private key'

    $badSigningBothManifest = Join-Path $tmpDir 'bad-signing-both.json'
    [System.IO.File]::WriteAllText($badSigningBothManifest, (@{
        git = @{
            keys    = @(@{ name = 'gh'; privateKeyFile = 'keys\git_github' })
            signing = @{ key = 'gh'; privateKeyFile = 'keys\git_signing' }
        }
    } | ConvertTo-Json -Depth 6), (New-Object System.Text.UTF8Encoding($false)))
    Assert-Throws "Rejects git.signing specifying both key and privateKeyFile" {
        Build-SeedSecretsPayload -ManifestPath $badSigningBothManifest -AgentName 'agent'
    } 'not both'

    $badSigningUnknownManifest = Join-Path $tmpDir 'bad-signing-unknown.json'
    [System.IO.File]::WriteAllText($badSigningUnknownManifest, (@{
        git = @{
            keys    = @(@{ name = 'gh'; privateKeyFile = 'keys\git_github' })
            signing = @{ key = 'nonexistent' }
        }
    } | ConvertTo-Json -Depth 6), (New-Object System.Text.UTF8Encoding($false)))
    Assert-Throws "Rejects git.signing.key referencing unknown key" {
        Build-SeedSecretsPayload -ManifestPath $badSigningUnknownManifest -AgentName 'agent'
    } 'does not match any key'

    $emptyGitManifest = Join-Path $tmpDir 'empty-git.json'
    [System.IO.File]::WriteAllText($emptyGitManifest, (@{
        git = @{ enabled = $true }
    } | ConvertTo-Json -Depth 6), (New-Object System.Text.UTF8Encoding($false)))
    Assert-Throws "Rejects empty enabled git section" {
        Build-SeedSecretsPayload -ManifestPath $emptyGitManifest -AgentName 'agent'
    } 'specify at least one'

    $proxyManifest = Join-Path $tmpDir 'proxy-inject.json'
    [System.IO.File]::WriteAllText($proxyManifest, (@{
        claude = @{ apiKey = 'sk-ant-real-secret-value'; oauthToken = 'oauth-real-secret-value'; proxyInject = $true }
        gemini = @{ apiKey = 'AIza-real-secret-value'; proxyInject = $true }
        github = @{ hostname = 'ghes.example.internal'; token = 'ghp_realsecret123456'; proxyInject = $true }
        jira   = @{ server = 'https://jira.example.com'; login = 'alice@example.com'; apiToken = 'jira-real-tok'; authType = 'basic'; proxyInject = $true }
    } | ConvertTo-Json -Depth 5), (New-Object System.Text.UTF8Encoding($false)))
    $proxyBuilt = Build-SeedSecretsPayload -ManifestPath $proxyManifest -AgentName 'agent'
    $proxyBuilt2 = Build-SeedSecretsPayload -ManifestPath $proxyManifest -AgentName 'agent'
    $svcJson = ($proxyBuilt.Payload.services | ConvertTo-Json -Depth 8)
    Assert-True "proxyInject replaces all real secrets (including claude oauthToken & jira apiToken) with random per-seed placeholders" (
        $proxyBuilt.Payload.services.claude.apiKey -match '^sandbox-proxy-claude-[0-9a-f]{48}$' -and
        $proxyBuilt.Payload.services.claude.oauthToken -match '^sandbox-proxy-claude-oauth-[0-9a-f]{48}$' -and
        $proxyBuilt.Payload.services.claude.apiKey -ne $proxyBuilt2.Payload.services.claude.apiKey -and
        $proxyBuilt.Payload.services.gemini.apiKey -match '^sandbox-proxy-gemini-[0-9a-f]{48}$' -and
        $proxyBuilt.Payload.services.jira.server -eq 'http://127.0.0.1:3129/jira' -and
        $svcJson -notmatch 'real-secret-value|ghp_realsecret123456|jira-real-tok'
    )
    Assert-True "proxyInject configures proxyBaseUrl, GHES /api/v3, expectedTokens, and real headers in root proxyRoutes" (
        $proxyBuilt.Payload.services.claude.proxyBaseUrl -eq 'http://127.0.0.1:3129/claude' -and
        $proxyBuilt.Payload.services.gemini.proxyBaseUrl -eq 'http://127.0.0.1:3129/gemini' -and
        $proxyBuilt.Payload.services.github.proxyBaseUrl -eq 'http://127.0.0.1:3129/github' -and
        $proxyBuilt.Payload.proxyRoutes.github.upstreamBaseUrl -eq 'https://ghes.example.internal/api/v3' -and
        $proxyBuilt.Payload.proxyRoutes.claude.injectHeaders['x-api-key'] -eq 'sk-ant-real-secret-value' -and
        $proxyBuilt.Payload.proxyRoutes.claude.injectHeaders['Authorization'] -eq 'Bearer oauth-real-secret-value' -and
        $proxyBuilt.Payload.proxyRoutes.gemini.injectHeaders['x-goog-api-key'] -eq 'AIza-real-secret-value' -and
        $proxyBuilt.Payload.proxyRoutes.jira.injectHeaders['Authorization'] -match '^Basic '
    )

    $badJiraMtlsManifest = Join-Path $tmpDir 'bad-jira-mtls.json'
    [System.IO.File]::WriteAllText($badJiraMtlsManifest, (@{
        jira = @{ server = 'https://jira.example.com'; login = 'alice@example.com'; apiToken = 'tok'; authType = 'mtls'; proxyInject = $true }
    } | ConvertTo-Json -Depth 5), (New-Object System.Text.UTF8Encoding($false)))
    Assert-Throws "Rejects jira.proxyInject with authType=mtls" {
        Build-SeedSecretsPayload -ManifestPath $badJiraMtlsManifest -AgentName 'agent'
    } 'mtls'

    $ttlBuilt = Build-SeedSecretsPayload -ManifestPath $proxyManifest -AgentName 'agent' -Ttl '2h'
    Assert-True "TTL 2h resolves to 7200 seconds in payload" ($ttlBuilt.Payload.ttlSeconds -eq 7200 -and $ttlBuilt.Payload.serviceTtls.claude -eq 7200)
    Assert-Throws "Rejects invalid -Ttl format" {
        ConvertTo-TtlSeconds -Ttl '2hours' | Out-Null
    } 'Invalid -Ttl'
    Assert-Throws "Rejects zero -Ttl duration" {
        ConvertTo-TtlSeconds -Ttl '0s' | Out-Null
    } 'positive integer'
    Assert-Throws "Rejects overflowing -Ttl duration" {
        ConvertTo-TtlSeconds -Ttl '99999999999999999999d' | Out-Null
    } 'between 1s and 365d'
    Assert-Throws "Rejects -Ttl exceeding 365d max bound" {
        ConvertTo-TtlSeconds -Ttl '366d' | Out-Null
    } 'exceeds maximum'

    $perSvcTtlManifest = Join-Path $tmpDir 'per-svc-ttl.json'
    [System.IO.File]::WriteAllText($perSvcTtlManifest, (@{
        github = @{ token = 'ghp_persvc123456'; ttl = '15m'; loginOnline = $false }
        gemini = @{ apiKey = 'AIza_persvc123456' }
    } | ConvertTo-Json -Depth 4), (New-Object System.Text.UTF8Encoding($false)))
    $svcTtlBuilt = Build-SeedSecretsPayload -ManifestPath $perSvcTtlManifest -AgentName 'agent'
    Assert-True "Per-service ttl resolves into serviceTtls without affecting sibling services" (
        $svcTtlBuilt.Payload.ttlSeconds -eq 0 -and
        $svcTtlBuilt.Payload.serviceTtls.github -eq 900 -and
        -not $svcTtlBuilt.Payload.serviceTtls.Contains('gemini') -and
        (($svcTtlBuilt.Summary | Where-Object { $_ -match '^github ' }) -match '\[ttl=900s\]')
    )
    $svcTtlOverride = Build-SeedSecretsPayload -ManifestPath $perSvcTtlManifest -AgentName 'agent' -Ttl '30s'
    Assert-True "CLI -Ttl overrides per-service ttl" (
        $svcTtlOverride.Payload.ttlSeconds -eq 30 -and
        $svcTtlOverride.Payload.serviceTtls.github -eq 30 -and
        $svcTtlOverride.Payload.serviceTtls.gemini -eq 30
    )

    # Vault backend resolver tests (mocked hook + negative scheme test)
    $vaultManifest = Join-Path $tmpDir 'vault.json'
    [System.IO.File]::WriteAllText($vaultManifest, (@{
        github = @{ tokenVault = 'op://SandboxVault/GitHub/token' }
        claude = @{ apiKeyVault = 'azkv://sandbox-kv/anthropic-key' }
    } | ConvertTo-Json -Depth 5), (New-Object System.Text.UTF8Encoding($false)))
    $script:VaultResolverHook = {
        param($uri, $baseDir, $ctx)
        $null = $baseDir
        $null = $ctx
        if ($uri -eq 'op://SandboxVault/GitHub/token') { return 'ghp_from_op_vault' }
        if ($uri -eq 'azkv://sandbox-kv/anthropic-key') { return 'sk-ant-from-azkv' }
        throw "unexpected uri: $uri"
    }
    try {
        $vaultBuilt = Build-SeedSecretsPayload -ManifestPath $vaultManifest -AgentName 'agent'
        Assert-True "Resolves github tokenVault via op:// backend" ($vaultBuilt.Payload.services.github.token -eq 'ghp_from_op_vault')
        Assert-True "Resolves claude apiKeyVault via azkv:// backend" ($vaultBuilt.Payload.services.claude.apiKey -eq 'sk-ant-from-azkv')
        Assert-True "DryRun summary reports vault backend schemes without leaking secrets" (
            (($vaultBuilt.Summary | Where-Object { $_ -match '^github ' }) -match '\[vault=op://\]') -and
            (($vaultBuilt.Summary | Where-Object { $_ -match '^claude ' }) -match '\[vault=azkv://\]') -and
            (($vaultBuilt.Summary -join "`n") -notmatch 'ghp_from_op_vault|sk-ant-from-azkv')
        )

        # URI validation must run even when VaultResolverHook is active
        Assert-Throws "Hook does not bypass malformed azkv:// empty secret segment" {
            Resolve-VaultSecretUri -Uri 'azkv://myvault/' -BaseDir $tmpDir -Context 'test' | Out-Null
        } 'azkv://<vault>/<secret>'
        Assert-Throws "Hook does not bypass malformed gcpsm:// empty project segment" {
            Resolve-VaultSecretUri -Uri 'gcpsm:///mysecret' -BaseDir $tmpDir -Context 'test' | Out-Null
        } 'gcpsm://<project>/<secret>'
        Assert-Throws "Hook does not bypass option-injection leading '-' target" {
            Resolve-VaultSecretUri -Uri 'bw://--raw' -BaseDir $tmpDir -Context 'test' | Out-Null
        } 'cannot start with'
    } finally {
        $script:VaultResolverHook = $null
    }
    Assert-Throws "Rejects unsupported vault URI scheme" {
        Resolve-VaultSecretUri -Uri 'unknown://vault/item' -BaseDir $tmpDir -Context 'test' | Out-Null
    } 'unsupported vault URI scheme'

    $conflictVaultManifest = Join-Path $tmpDir 'conflict-vault.json'
    [System.IO.File]::WriteAllText($conflictVaultManifest, (@{
        github = @{ token = 'ghp_direct'; tokenVault = 'op://Vault/Item/token' }
    } | ConvertTo-Json -Depth 5), (New-Object System.Text.UTF8Encoding($false)))
    Assert-Throws "Rejects specifying both token and tokenVault without leaking token" {
        Build-SeedSecretsPayload -ManifestPath $conflictVaultManifest -AgentName 'agent' | Out-Null
    } 'specify only one of' 'ghp_direct'

    # DPAPI round-trip and empty decrypted secret rejection (works on PS 5.1 & PS 7)
    if (-not ('System.Security.Cryptography.ProtectedData' -as [type])) {
        try { Add-Type -AssemblyName 'System.Security' -ErrorAction Stop } catch { Write-Verbose $_.Exception.Message }
    }
    if (-not ('System.Security.Cryptography.ProtectedData' -as [type])) {
        try { Add-Type -AssemblyName 'System.Security.Cryptography.ProtectedData' -ErrorAction Stop } catch { Write-Verbose $_.Exception.Message }
    }
    $dpapiFile = Join-Path $tmpDir 'dpapi-secret.bin'
    $rawDpapiBytes = [System.Text.Encoding]::UTF8.GetBytes("dpapi-protected-token-xyz`r`n")
    $encDpapiBytes = [System.Security.Cryptography.ProtectedData]::Protect($rawDpapiBytes, $null, [System.Security.Cryptography.DataProtectionScope]::CurrentUser)
    [System.IO.File]::WriteAllBytes($dpapiFile, $encDpapiBytes)
    $resolvedDpapi = Resolve-VaultSecretUri -Uri 'dpapi://dpapi-secret.bin' -BaseDir $tmpDir -Context 'test.dpapi'
    Assert-True "Resolves dpapi:// encrypted file cleanly on current user scope" ($resolvedDpapi -eq 'dpapi-protected-token-xyz')

    $dpapiEmptyFile = Join-Path $tmpDir 'dpapi-empty.bin'
    $encEmptyBytes = [System.Security.Cryptography.ProtectedData]::Protect([System.Text.Encoding]::UTF8.GetBytes("   `r`n"), $null, [System.Security.Cryptography.DataProtectionScope]::CurrentUser)
    [System.IO.File]::WriteAllBytes($dpapiEmptyFile, $encEmptyBytes)
    Assert-Throws "Rejects dpapi:// file that decrypts to whitespace" {
        Resolve-VaultSecretUri -Uri 'dpapi://dpapi-empty.bin' -BaseDir $tmpDir -Context 'test.dpapi' | Out-Null
    } 'decrypted to an empty value'

    # Invoke-VaultCliProcess separates stdout from stderr warnings without NativeCommandError
    $cliStdout = Invoke-VaultCliProcess -FileName 'powershell.exe' -Arguments @('-NoProfile', '-Command', '[Console]::Error.WriteLine("WARNING: CLI update available"); [Console]::Out.WriteLine("clean-secret-from-stdout")') -Context 'test.cli' -Uri 'op://v/i/f'
    Assert-True "Invoke-VaultCliProcess ignores stderr warnings and returns clean stdout" ($cliStdout -eq 'clean-secret-from-stdout')

    $agentProxyManifest = Join-Path $tmpDir 'ssh-agent-proxy.json'
    [System.IO.File]::WriteAllText($agentProxyManifest, (@{
        ssh = @{ mode = 'agent-proxy'; keys = @(@{ name = 'deploy'; privateKeyFile = 'keys\ssh_deploy'; publicKeyFile = 'keys\ssh_deploy.pub' }) }
        git = @{ mode = 'agent-proxy'; host = 'github.com'; privateKeyFile = 'keys\git_github'; publicKeyFile = 'keys\git_github.pub' }
    } | ConvertTo-Json -Depth 6), (New-Object System.Text.UTF8Encoding($false)))
    $apBuilt = Build-SeedSecretsPayload -ManifestPath $agentProxyManifest -AgentName 'agent'
    Assert-True "Supports mode=agent-proxy on ssh and git services" ($apBuilt.Payload.services.ssh.mode -eq 'agent-proxy' -and $apBuilt.Payload.services.git.mode -eq 'agent-proxy')

    $badModeManifest = Join-Path $tmpDir 'bad-ssh-mode.json'
    [System.IO.File]::WriteAllText($badModeManifest, (@{
        ssh = @{ mode = 'invalid-mode'; keys = @(@{ name = 'deploy'; privateKeyFile = 'keys\ssh_deploy' }) }
    } | ConvertTo-Json -Depth 6), (New-Object System.Text.UTF8Encoding($false)))
    Assert-Throws "Rejects invalid ssh.mode value" {
        Build-SeedSecretsPayload -ManifestPath $badModeManifest -AgentName 'agent' | Out-Null
    } "must be 'files' or 'agent-proxy'"

    # 9. Schema-driven unknown nested property rejection without secret leakage
    $unknownNestedCases = @(
        @{
            Name     = 'github unknown top-level property'
            File     = 'unknown-gh-key.json'
            Data     = @{ github = @{ token = 'ghp_secret_leak_check'; tkoen = 'ghp_secret_leak_check' } }
            NoLeak   = 'ghp_secret_leak_check'
        },
        @{
            Name     = 'github.profiles[*] unknown property'
            File     = 'unknown-gh-prof-key.json'
            Data     = @{ github = @{ profiles = @(@{ name = 'work'; pat = 'ghp_profile_leak_check' }) } }
            NoLeak   = 'ghp_profile_leak_check'
        },
        @{
            Name     = 'ssh unknown top-level property'
            File     = 'unknown-ssh-key.json'
            Data     = @{ ssh = @{ strictHostKeyCheck = 'yes'; keys = @(@{ name = 'deploy'; privateKeyFile = 'keys\ssh_deploy' }) } }
            NoLeak   = ''
        },
        @{
            Name     = 'ssh.hosts[*] unknown property'
            File     = 'unknown-ssh-host-key.json'
            Data     = @{ ssh = @{ hosts = @(@{ name = 'web'; hostName = 'web.example.com'; hostnameAlias = 'x' }) } }
            NoLeak   = ''
        },
        @{
            Name     = 'git.signing unknown property'
            File     = 'unknown-git-sign-key.json'
            Data     = @{ git = @{ privateKeyFile = 'keys\git_github'; signing = @{ enabled = $true; signCommit = $true } } }
            NoLeak   = ''
        },
        @{
            Name     = 'env.<VAR> object unknown property'
            File     = 'unknown-env-obj-key.json'
            Data     = @{ env = @{ NPM_TOKEN = @{ val = 'npm_secret_leak_check' } } }
            NoLeak   = 'npm_secret_leak_check'
        },
        @{
            Name     = 'files[*] unknown property'
            File     = 'unknown-files-key.json'
            Data     = @{ files = @(@{ name = 'npmrc'; sourcePath = 'keys\npmrc'; targetPath = '~/.npmrc'; chmod = '0600' }) }
            NoLeak   = ''
        }
    )
    foreach ($uc in $unknownNestedCases) {
        $uPath = Join-Path $tmpDir $uc.File
        [System.IO.File]::WriteAllText($uPath, ($uc.Data | ConvertTo-Json -Depth 8), (New-Object System.Text.UTF8Encoding($false)))
        Assert-Throws "Rejects $($uc.Name) without leaking secrets" {
            Build-SeedSecretsPayload -ManifestPath $uPath -AgentName 'agent' | Out-Null
        } 'Unknown property' $uc.NoLeak
    }

    $gcloudObjSaManifest = Join-Path $tmpDir 'gcloud-obj-sa.json'
    [System.IO.File]::WriteAllText($gcloudObjSaManifest, (@{
        gcloud = @{
            skipActivate          = $true
            serviceAccountKeyJson = @{
                type           = 'service_account'
                project_id     = 'compat-proj'
                private_key_id = 'key-id-123'
                private_key    = "-----BEGIN PRIVATE KEY-----`nMOCKKEY`n-----END PRIVATE KEY-----`n"
                client_email   = 'bot@compat-proj.iam.gserviceaccount.com'
                auth_uri       = 'https://accounts.google.com/o/oauth2/auth'
            }
        }
    } | ConvertTo-Json -Depth 6), (New-Object System.Text.UTF8Encoding($false)))
    $gcloudObjBuilt = Build-SeedSecretsPayload -ManifestPath $gcloudObjSaManifest -AgentName 'agent'
    Assert-True "Accepts inline gcloud.serviceAccountKeyJson object with extra GCP metadata fields" ($gcloudObjBuilt.Payload.services.gcloud.projects[0].project -eq 'compat-proj')

    # Case-sensitive key matching (parity with secrets.schema.json)
    $wrongCaseNestedManifest = Join-Path $tmpDir 'wrong-case-nested.json'
    [System.IO.File]::WriteAllText($wrongCaseNestedManifest, (@{
        github = @{ TOKEN = 'ghp_wrong_case_canary_123' }
    } | ConvertTo-Json -Depth 5), (New-Object System.Text.UTF8Encoding($false)))
    Assert-Throws "Rejects wrong-case nested key github.TOKEN without leaking secret" {
        Build-SeedSecretsPayload -ManifestPath $wrongCaseNestedManifest -AgentName 'agent' | Out-Null
    } 'Unknown property' 'ghp_wrong_case_canary_123'

    $wrongCaseTopManifest = Join-Path $tmpDir 'wrong-case-top.json'
    [System.IO.File]::WriteAllText($wrongCaseTopManifest, (@{
        GitHub = @{ token = 'ghp_top_case_canary_456' }
    } | ConvertTo-Json -Depth 5), (New-Object System.Text.UTF8Encoding($false)))
    Assert-Throws "Rejects wrong-case top-level service GitHub without leaking secret" {
        Build-SeedSecretsPayload -ManifestPath $wrongCaseTopManifest -AgentName 'agent' | Out-Null
    } 'Unknown top-level service' 'ghp_top_case_canary_456'

    # Per-UID credential-proxy port allocation in Build-SeedSecretsPayload
    $profPorts = Get-DeterministicProxyPorts -Uid 26150
    $profProxyBuilt = Build-SeedSecretsPayload -ManifestPath $proxyManifest -AgentName 'agent' -AgentUid 26150
    Assert-True "Build-SeedSecretsPayload uses per-UID credential-proxy port for non-default UID" (
        $profProxyBuilt.Payload.services.jira.server -eq "http://127.0.0.1:$($profPorts.CredentialPort)/jira" -and
        $profProxyBuilt.Payload.services.claude.proxyBaseUrl -eq "http://127.0.0.1:$($profPorts.CredentialPort)/claude" -and
        $profProxyBuilt.Payload.services.gemini.proxyBaseUrl -eq "http://127.0.0.1:$($profPorts.CredentialPort)/gemini" -and
        $profProxyBuilt.Payload.services.github.proxyBaseUrl -eq "http://127.0.0.1:$($profPorts.CredentialPort)/github"
    )
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
