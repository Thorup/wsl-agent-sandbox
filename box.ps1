<#
.SYNOPSIS
    Manage the hardened Ubuntu 26.04 LTS WSL2 Agent Sandbox (wsl-agent-sandbox).

.DESCRIPTION
    Declaratively provisions, updates, verifies, snapshots, resets, and destroys
    an isolated Ubuntu 26.04 LTS WSL2 distribution controlled strictly from box.json.

.EXAMPLE
    .\box.ps1 init
    .\box.ps1 apply
    .\box.ps1 seed-secrets
    .\box.ps1 seed-secrets -Service github,jira
    .\box.ps1 clear-secrets
    .\box.ps1 verify
    .\box.ps1 shell
#>
#Requires -Version 5.1
param(
    [Parameter(Position = 0)]
    [ValidateSet('init', 'up', 'apply', 'upgrade', 'doctor', 'compact', 'logs', 'audit', 'list', 'push-repo', 'pull-diff', 'pull-branch', 'seed-secrets', 'clear-secrets', 'register-terminal', 'shell', 'root-shell', 'status', 'verify', 'snapshot', 'restore', 'reset', 'destroy', 'help')]
    [string]$Command = 'help',

    [Parameter(Position = 1)]
    [string]$Argument = '',

    [string]$ConfigPath = '',

    [string]$SecretsPath = '',

    [string[]]$Service = @(),

    [switch]$Prune,

    [switch]$DryRun,

    [switch]$Force,

    [switch]$RebuildProxy,

    [switch]$Golden,

    [switch]$SaveGolden,

    [switch]$Full,

    [switch]$Unregister,

    [string[]]$Scope = @('all'),

    [ValidateSet('all', 'docker', 'network', 'egress', 'credentials', 'ssh-agent', 'hardening')]
    [string]$Source = 'all',

    [string]$Since = '1 hour ago',

    [ValidateRange(1, 100000)]
    [int]$Lines = 100,

    [string]$Dest = '',

    [string]$Branch = 'HEAD',

    [string]$RepoPath = '',

    [Alias('Profile')]
    [string]$ProfileName = '',

    [string]$Ttl = ''
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

$AppRoot = $PSScriptRoot
$userSpecifiedConfigPath = -not [string]::IsNullOrWhiteSpace($ConfigPath)
if (-not $userSpecifiedConfigPath) {
    $cwdConfig = Join-Path (Get-Location).Path 'box.json'
    $userConfig = Join-Path $env:USERPROFILE '.wsl-agent-sandbox\box.json'
    if (Test-Path -LiteralPath $cwdConfig -PathType Leaf) {
        $ConfigPath = $cwdConfig
        $StateRoot = (Get-Location).Path
    } elseif (Test-Path -LiteralPath $userConfig -PathType Leaf) {
        $ConfigPath = $userConfig
        $StateRoot = Split-Path -Parent $userConfig
    } else {
        $ConfigPath = Join-Path $AppRoot 'box.json'
        $StateRoot = if (Test-Path -LiteralPath (Join-Path $AppRoot '.git')) {
            $AppRoot
        } else {
            Join-Path $env:USERPROFILE '.wsl-agent-sandbox'
        }
    }
} else {
    $fullConfigPath = if ([System.IO.Path]::IsPathRooted($ConfigPath)) {
        [System.IO.Path]::GetFullPath($ConfigPath)
    } else {
        [System.IO.Path]::GetFullPath((Join-Path (Get-Location).Path $ConfigPath))
    }
    $ConfigPath = $fullConfigPath
    $StateRoot = Split-Path -Parent $fullConfigPath
}
. (Join-Path $AppRoot 'scripts\lib\Config.ps1')
. (Join-Path $AppRoot 'scripts\lib\Image.ps1')
. (Join-Path $AppRoot 'scripts\lib\Wsl.ps1')
. (Join-Path $AppRoot 'scripts\lib\Secrets.ps1')
. (Join-Path $AppRoot 'scripts\lib\Terminal.ps1')

function Show-Usage {
    @"
wsl-agent-sandbox - Hardened Ubuntu 26.04 LTS WSL2 Sandbox CLI (box.ps1)

Usage:
  .\box.ps1 <command> [options]

Commands:
  init               Download/verify Ubuntu 26.04 LTS, import WSL distro, provision toolchain,
                     build & test Docker policy proxy, harden distro, and run verification.
  up                 Ensure the distro is running and systemd hardening services are active.
  apply              Push updated box.json (shared folders, allowed host ports, Docker policy,
                     apt packages, CLI/language toolchains) and reload hardening + proxy live
                     without rebuilding (use -RebuildProxy to rebuild docker-policy-proxy).
  upgrade            Update installed apt packages, AI agents, and toolchains in place
                     (optional -Scope apt,agents,toolchains).
  doctor             Run Windows + WSL preflight diagnostics (WSL2, .wslconfig, Docker Desktop,
                     systemd health, VHDX disk size, image cache).
  compact            Trim free blocks inside WSL (fstrim) and compact the distro's ext4.vhdx.
  logs / audit       View root-owned security events (nftables drops, docker-policy-proxy denials,
                     box-hardening reloads) with optional -Source, -Since, -Lines.
  list               List configured sandbox profiles, their distro names, UIDs, and WSL state.
  push-repo <path>   Bundle a Windows git repo and clone/update it into ~/work/<name> on native ext4.
  pull-diff <name>   Show git status, recent commits, and diffstat from ~/work/<name> inside WSL.
  pull-branch <name> Fetch agent commits from ~/work/<name> into a safe local branch (sandbox/<name>)
                     on Windows without touching working tree or .git/hooks.
  seed-secrets [path] Seed or rotate CLI tokens, service accounts, and Git/SSH credentials from a
                     central Windows manifest (default: %USERPROFILE%\.wsl-agent-sandbox\secrets.json)
                     independently of init/apply. Supports -SecretsPath, -Service <names>, -Ttl <dur>, -Prune, -DryRun.
  clear-secrets      Remove managed seeded CLI credentials inside WSL (optionally scoped via -Service).
  register-terminal  Add or update a dedicated Windows Terminal profile for this sandbox
                     (pass -Unregister to remove it).
  shell              Open an interactive shell inside the box as the non-root agent user.
  root-shell         Open an administrative root shell (Windows host control plane only).
  status             Show distro state, systemd service health, active /shared mounts, seeded secrets, and warnings.
  verify             Run full red-team isolation audit + Windows<->WSL localhost web test +
                     blocked Windows host port test + Docker escape tests.
  snapshot [path]    Export the distro to a .tar backup (defaults to .cache\<distro>-<timestamp>.tar;
                     pass -Golden to save .cache\<distro>-golden.tar for fast resets).
  restore <path>     Unregister the current distro, import a .tar backup, re-apply box.json, and verify.
  reset              Fast-restore from golden snapshot if present (pass -Full for clean Ubuntu rebuild).
  destroy            Unregister the WSL distro and remove its VHDX directory (use -Force to skip prompt).
"@
}

function Sync-AssetsToWsl {
    param(
        [Parameter(Mandatory)]$Config,
        [switch]$IncludeProxySource
    )
    $distro = $Config.distroName

    # Push merged policy.json and Windows host IPs
    $policyJson = $Config | ConvertTo-Json -Depth 20
    Copy-TextToWsl -DistroName $distro -Content $policyJson -RemotePath '/etc/wsl-agent-sandbox/policy.json' -Mode '0600'

    $hostIps = (Get-WindowsHostIPs) -join "`n"
    Copy-TextToWsl -DistroName $distro -Content ($hostIps + "`n") -RemotePath '/etc/wsl-agent-sandbox/host_ips.txt' -Mode '0600'

    # Push Linux scripts & systemd units
    Copy-FileToWsl -DistroName $distro -LocalPath (Join-Path $AppRoot 'scripts\linux\box-hardening.sh') -RemotePath '/usr/local/sbin/box-hardening.sh' -Mode '0755' -NormalizeLF
    Copy-FileToWsl -DistroName $distro -LocalPath (Join-Path $AppRoot 'scripts\linux\install-tools.sh') -RemotePath '/usr/local/sbin/box-install-tools.sh' -Mode '0755' -NormalizeLF
    Copy-FileToWsl -DistroName $distro -LocalPath (Join-Path $AppRoot 'scripts\linux\provision.sh') -RemotePath '/usr/local/sbin/box-provision.sh' -Mode '0755' -NormalizeLF
    Copy-FileToWsl -DistroName $distro -LocalPath (Join-Path $AppRoot 'scripts\linux\apply-policy.sh') -RemotePath '/usr/local/sbin/box-apply-policy.sh' -Mode '0755' -NormalizeLF
    Copy-FileToWsl -DistroName $distro -LocalPath (Join-Path $AppRoot 'scripts\linux\box-seed-secrets.sh') -RemotePath '/usr/local/sbin/box-seed-secrets.sh' -Mode '0755' -NormalizeLF
    Copy-FileToWsl -DistroName $distro -LocalPath (Join-Path $AppRoot 'scripts\linux\box-sync-context.py') -RemotePath '/usr/local/sbin/box-sync-context.py' -Mode '0755' -NormalizeLF
    Copy-FileToWsl -DistroName $distro -LocalPath (Join-Path $AppRoot 'scripts\linux\verify-isolation.sh') -RemotePath '/usr/local/bin/box-verify-isolation.sh' -Mode '0755' -NormalizeLF
    Copy-FileToWsl -DistroName $distro -LocalPath (Join-Path $AppRoot 'systemd\box-hardening.service') -RemotePath '/etc/systemd/system/box-hardening.service' -Mode '0644' -NormalizeLF
    Copy-FileToWsl -DistroName $distro -LocalPath (Join-Path $AppRoot 'systemd\docker-policy-proxy.service') -RemotePath '/etc/systemd/system/docker-policy-proxy.service' -Mode '0644' -NormalizeLF
    Copy-FileToWsl -DistroName $distro -LocalPath (Join-Path $AppRoot 'scripts\linux\egress-proxy.py') -RemotePath '/usr/local/sbin/box-egress-proxy.py' -Mode '0755' -NormalizeLF
    Copy-FileToWsl -DistroName $distro -LocalPath (Join-Path $AppRoot 'systemd\egress-proxy.service') -RemotePath '/etc/systemd/system/egress-proxy.service' -Mode '0644' -NormalizeLF
    Copy-FileToWsl -DistroName $distro -LocalPath (Join-Path $AppRoot 'scripts\linux\credential-proxy.py') -RemotePath '/usr/local/sbin/box-credential-proxy.py' -Mode '0755' -NormalizeLF
    Copy-FileToWsl -DistroName $distro -LocalPath (Join-Path $AppRoot 'systemd\credential-proxy.service') -RemotePath '/etc/systemd/system/credential-proxy.service' -Mode '0644' -NormalizeLF
    Copy-FileToWsl -DistroName $distro -LocalPath (Join-Path $AppRoot 'scripts\linux\ssh-agent-proxy.py') -RemotePath '/usr/local/sbin/box-ssh-agent-proxy.py' -Mode '0755' -NormalizeLF
    Copy-FileToWsl -DistroName $distro -LocalPath (Join-Path $AppRoot 'scripts\linux\box-ssh-agent-ctl.sh') -RemotePath '/usr/local/sbin/box-ssh-agent-ctl.sh' -Mode '0755' -NormalizeLF
    Copy-FileToWsl -DistroName $distro -LocalPath (Join-Path $AppRoot 'systemd\ssh-agent-proxy.service') -RemotePath '/etc/systemd/system/ssh-agent-proxy.service' -Mode '0644' -NormalizeLF

    if ($IncludeProxySource) {
        $proxyFiles = @('go.mod', 'main.go', 'policy.go', 'proxy.go', 'bind_pin.go', 'policy_test.go')
        foreach ($pf in $proxyFiles) {
            Copy-FileToWsl -DistroName $distro -LocalPath (Join-Path $AppRoot "docker-policy-proxy\$pf") -RemotePath "/usr/local/src/docker-policy-proxy/$pf" -Mode '0644' -NormalizeLF
        }
    }
}

function Get-GoldenSnapshotPath {
    param([Parameter(Mandatory)]$Config)
    $cacheDir = Expand-BoxPath -RawPath $Config.image.cacheDir -BaseDir $StateRoot
    return (Join-Path $cacheDir "$($Config.distroName)-golden.tar")
}

function Invoke-Snapshot {
    param(
        [Parameter(Mandatory)]$Config,
        [string]$OutFile = '',
        [switch]$Golden
    )
    if (-not (Test-WslDistroExists -DistroName $Config.distroName)) {
        throw "Distro '$($Config.distroName)' does not exist."
    }
    $cacheDir = Expand-BoxPath -RawPath $Config.image.cacheDir -BaseDir $StateRoot
    if ($Golden) {
        $OutFile = Get-GoldenSnapshotPath -Config $Config
    } elseif ([string]::IsNullOrWhiteSpace($OutFile)) {
        $stamp = Get-Date -Format 'yyyyMMdd-HHmmss'
        $OutFile = Join-Path $cacheDir "$($Config.distroName)-$stamp.tar"
    } else {
        $OutFile = Expand-BoxPath -RawPath $OutFile -BaseDir $StateRoot
    }

    $outParent = Split-Path -Parent $OutFile
    if (-not [string]::IsNullOrWhiteSpace($outParent) -and -not (Test-Path -LiteralPath $outParent)) {
        New-Item -ItemType Directory -Path $outParent -Force | Out-Null
    }

    $tmpOut = "$OutFile.tmp.$([Guid]::NewGuid().ToString('N').Substring(0, 8))"
    Write-Host "[snapshot] Exporting '$($Config.distroName)' -> '$OutFile'..."
    try {
        & wsl.exe --export $Config.distroName $tmpOut
        if ($LASTEXITCODE -ne 0 -or -not (Test-Path -LiteralPath $tmpOut -PathType Leaf)) {
            throw "wsl --export failed (exit code $LASTEXITCODE)."
        }
        Move-Item -LiteralPath $tmpOut -Destination $OutFile -Force
    } finally {
        if (Test-Path -LiteralPath $tmpOut -PathType Leaf) {
            Remove-Item -LiteralPath $tmpOut -Force -ErrorAction SilentlyContinue
        }
    }
    Write-Host "[snapshot] Saved: $OutFile"
}

function Invoke-Restore {
    param(
        [Parameter(Mandatory)]$Config,
        [string]$SnapshotPath = '',
        [switch]$Force
    )
    if ([string]::IsNullOrWhiteSpace($SnapshotPath)) {
        throw "Snapshot path is required. Usage: .\box.ps1 restore <path-to-snapshot.tar>"
    }
    $SnapshotPath = Expand-BoxPath -RawPath $SnapshotPath -BaseDir $StateRoot
    if (-not (Test-Path -LiteralPath $SnapshotPath -PathType Leaf)) {
        throw "Snapshot file not found: '$SnapshotPath'"
    }
    $distro = $Config.distroName
    $installDir = Expand-BoxPath -RawPath $Config.installDir -BaseDir $StateRoot

    if (Test-WslDistroExists -DistroName $distro) {
        Invoke-Destroy -Config $Config -Force:$Force
        if (Test-WslDistroExists -DistroName $distro) {
            return
        }
    }

    if (-not (Test-Path -LiteralPath $installDir)) {
        New-Item -ItemType Directory -Path $installDir -Force | Out-Null
    }
    Write-Host "[restore] Importing '$distro' into '$installDir' from '$SnapshotPath' (WSL 2)..."
    & wsl.exe --import $distro $installDir $SnapshotPath --version 2
    if ($LASTEXITCODE -ne 0) {
        throw "wsl --import failed with exit code $LASTEXITCODE."
    }

    Write-Host "[restore] Syncing current policy and scripts, and waiting for systemd..."
    Sync-AssetsToWsl -Config $Config
    if (-not (Wait-WslSystemdReady -DistroName $distro -TimeoutSeconds 60 -SkipHardeningCheck)) {
        throw "Restored distro '$distro' systemd did not finish booting."
    }

    Invoke-Apply -Config $Config
    if (-not (Wait-WslSystemdReady -DistroName $distro -TimeoutSeconds 30)) {
        throw "Restored distro '$distro' systemd hardening did not reach active state."
    }
    Invoke-Verify -Config $Config
}

function Invoke-Init {
    param(
        $Config,
        [switch]$SaveGolden
    )
    $distro = $Config.distroName
    $installDir = Expand-BoxPath -RawPath $Config.installDir -BaseDir $StateRoot

    if (Test-WslDistroExists -DistroName $distro) {
        Write-Host "[init] Distro '$distro' already exists. Use '.\box.ps1 apply' to update policy or '.\box.ps1 reset' to rebuild."
        return
    }

    $imagePath = Resolve-UbuntuWslImage -Config $Config -RepoRoot $StateRoot

    if (-not (Test-Path -LiteralPath $installDir)) {
        New-Item -ItemType Directory -Path $installDir -Force | Out-Null
    }

    Write-Host "[init] Importing '$distro' into '$installDir' from '$imagePath' (WSL 2)..."
    & wsl.exe --import $distro $installDir $imagePath --version 2
    if ($LASTEXITCODE -ne 0) {
        throw "wsl --import failed with exit code $LASTEXITCODE."
    }

    Write-Host "[init] Syncing policy, hardening scripts, and Docker policy proxy source..."
    Sync-AssetsToWsl -Config $Config -IncludeProxySource

    Write-Host "[init] Running Ubuntu 26.04 provisioning & Go policy proxy build/tests (this may take a few minutes)..."
    & wsl.exe -d $distro -u root -- /usr/local/sbin/box-provision.sh
    if ($LASTEXITCODE -ne 0) {
        throw "Provisioning failed with exit code $LASTEXITCODE."
    }

    Write-Host "[init] Restarting '$distro' so /etc/wsl.conf (automount=false, interop=false, systemd=true) takes effect..."
    & wsl.exe --terminate $distro | Out-Null
    Start-Sleep -Seconds 2

    Write-Host "[init] Waiting for systemd and box-hardening.service..."
    if (-not (Wait-WslSystemdReady -DistroName $distro -TimeoutSeconds 60)) {
        Write-Warning "Timed out waiting for systemd; checking service status..."
        & wsl.exe -d $distro -u root -- sh -c "systemctl status box-hardening.service docker-policy-proxy.service --no-pager || true"
        throw "Distro systemd hardening did not reach active state."
    }

    Write-Host "[init] Applying policy and starting Docker policy proxy..."
    if (Test-ShouldConfigureIdeRemoteWsl -Config $Config) {
        [void](Sync-IdeWslScriptlessStartup)
    }
    if ($Config.docker.enabled) {
        [void](Sync-DockerDesktopSocketBridge)
    }
    & wsl.exe -d $distro -u root -- /usr/local/sbin/box-apply-policy.sh
    if ($LASTEXITCODE -ne 0) {
        throw "apply-policy.sh failed with exit code $LASTEXITCODE."
    }

    foreach ($w in (Get-GlobalWslConfigWarnings)) {
        Write-Warning $w
    }

    Write-Host "[init] '$distro' is provisioned and hardened! Running verification..."
    Invoke-Verify -Config $Config

    if ($SaveGolden) {
        $goldenPath = Get-GoldenSnapshotPath -Config $Config
        Write-Host "[init] Saving golden base snapshot for fast resets -> '$goldenPath'..."
        Invoke-Snapshot -Config $Config -Golden
    }
}

function Invoke-Apply {
    param(
        $Config,
        [switch]$RebuildProxy
    )
    $distro = $Config.distroName
    if (-not (Test-WslDistroExists -DistroName $distro)) {
        throw "Distro '$distro' does not exist. Run '.\box.ps1 init' first."
    }
    Write-Host "[apply] Pushing updated policy & scripts to '$distro'..."
    if (Test-ShouldConfigureIdeRemoteWsl -Config $Config) {
        [void](Sync-IdeWslScriptlessStartup)
    }
    if ($Config.docker.enabled) {
        [void](Sync-DockerDesktopSocketBridge)
    }
    Sync-AssetsToWsl -Config $Config -IncludeProxySource:$RebuildProxy
    if ($RebuildProxy) {
        Write-Host "[apply] Re-testing and rebuilding docker-policy-proxy..."
        $buildScript = @'
set -euo pipefail
cd /usr/local/src/docker-policy-proxy
go test -v -race ./...
CGO_ENABLED=0 go build -trimpath -ldflags='-s -w' -o /usr/local/libexec/docker-policy-proxy.new .
chown root:root /usr/local/libexec/docker-policy-proxy.new
chmod 0755 /usr/local/libexec/docker-policy-proxy.new
mv -f /usr/local/libexec/docker-policy-proxy.new /usr/local/libexec/docker-policy-proxy
'@
        Invoke-WslRootBash -DistroName $distro -Script $buildScript
    }
    & wsl.exe -d $distro -u root -- /usr/local/sbin/box-apply-policy.sh
    if ($LASTEXITCODE -ne 0) {
        throw "apply-policy.sh failed with exit code $LASTEXITCODE."
    }
}

function Invoke-SeedSecrets {
    param(
        $Config,
        [string]$SecretsPath = '',
        [string[]]$Service = @(),
        [switch]$Prune,
        [switch]$DryRun,
        [string]$Ttl = '',
        [string]$ProfileName = ''
    )
    $distro = $Config.distroName
    if (-not (Test-WslDistroExists -DistroName $distro)) {
        throw "Distro '$distro' does not exist. Run '.\box.ps1 init' first."
    }

    $explicitPath = if (-not [string]::IsNullOrWhiteSpace($SecretsPath)) { $SecretsPath } else { $Argument }
    $manifestPath = Resolve-SecretsManifestPath -ExplicitPath $explicitPath -Config $Config -RepoRoot $StateRoot -ProfileName $ProfileName

    $built = Build-SeedSecretsPayload -ManifestPath $manifestPath -AgentName $Config.agentUser.name -AgentUid ([int]$Config.agentUser.uid) -Services $Service -Prune:$Prune -Ttl $Ttl -ProfileName $ProfileName

    $summaryLines = @($built.Summary)
    $disabledLines = @($built.SkippedDisabled)

    Write-Host "[seed-secrets] Manifest: $($built.ManifestPath)"
    if ($summaryLines.Count -gt 0) {
        Write-Host "[seed-secrets] Services to seed:"
        foreach ($line in $summaryLines) {
            Write-Host "  - $line"
        }
    } else {
        Write-Host "[seed-secrets] No enabled services matched."
    }
    if ($disabledLines.Count -gt 0) {
        Write-Host "[seed-secrets] Skipped disabled: $($disabledLines -join ', ')"
    }

    if ($DryRun) {
        Write-Host "[seed-secrets] Dry run complete - no credentials were pushed to '$distro'."
        return
    }

    if ($summaryLines.Count -eq 0 -and -not $Prune) {
        Write-Host "[seed-secrets] Nothing to apply (pass -Prune to remove disabled/removed services)."
        return
    }

    # Always sync the seeder script & root proxy assets so seed-secrets works independently of init/apply
    Copy-FileToWsl -DistroName $distro -LocalPath (Join-Path $AppRoot 'scripts\linux\box-seed-secrets.sh') -RemotePath '/usr/local/sbin/box-seed-secrets.sh' -Mode '0755' -NormalizeLF
    Copy-FileToWsl -DistroName $distro -LocalPath (Join-Path $AppRoot 'scripts\linux\box-sync-context.py') -RemotePath '/usr/local/sbin/box-sync-context.py' -Mode '0755' -NormalizeLF
    Copy-FileToWsl -DistroName $distro -LocalPath (Join-Path $AppRoot 'scripts\linux\box-ssh-agent-ctl.sh') -RemotePath '/usr/local/sbin/box-ssh-agent-ctl.sh' -Mode '0755' -NormalizeLF
    Copy-FileToWsl -DistroName $distro -LocalPath (Join-Path $AppRoot 'scripts\linux\credential-proxy.py') -RemotePath '/usr/local/sbin/box-credential-proxy.py' -Mode '0755' -NormalizeLF
    Copy-FileToWsl -DistroName $distro -LocalPath (Join-Path $AppRoot 'systemd\credential-proxy.service') -RemotePath '/etc/systemd/system/credential-proxy.service' -Mode '0644' -NormalizeLF
    Copy-FileToWsl -DistroName $distro -LocalPath (Join-Path $AppRoot 'scripts\linux\ssh-agent-proxy.py') -RemotePath '/usr/local/sbin/box-ssh-agent-proxy.py' -Mode '0755' -NormalizeLF
    Copy-FileToWsl -DistroName $distro -LocalPath (Join-Path $AppRoot 'systemd\ssh-agent-proxy.service') -RemotePath '/etc/systemd/system/ssh-agent-proxy.service' -Mode '0644' -NormalizeLF

    $payloadJson = $built.Payload | ConvertTo-Json -Depth 10 -Compress
    Write-Host "[seed-secrets] Pushing resolved credentials to '$distro' via root control plane (stdin only)..."
    Invoke-WslRootStdinCommand -DistroName $distro -RemoteCommand '/usr/local/sbin/box-seed-secrets.sh --apply' -StdinText $payloadJson
}

function Invoke-ClearSecrets {
    param(
        $Config,
        [string[]]$Service = @()
    )
    $distro = $Config.distroName
    if (-not (Test-WslDistroExists -DistroName $distro)) {
        throw "Distro '$distro' does not exist. Run '.\box.ps1 init' first."
    }

    $filterServices = @(Resolve-RequestedServiceFilter -Services $Service)
    Copy-FileToWsl -DistroName $distro -LocalPath (Join-Path $AppRoot 'scripts\linux\box-seed-secrets.sh') -RemotePath '/usr/local/sbin/box-seed-secrets.sh' -Mode '0755' -NormalizeLF
    Copy-FileToWsl -DistroName $distro -LocalPath (Join-Path $AppRoot 'scripts\linux\box-sync-context.py') -RemotePath '/usr/local/sbin/box-sync-context.py' -Mode '0755' -NormalizeLF
    Copy-FileToWsl -DistroName $distro -LocalPath (Join-Path $AppRoot 'scripts\linux\box-ssh-agent-ctl.sh') -RemotePath '/usr/local/sbin/box-ssh-agent-ctl.sh' -Mode '0755' -NormalizeLF

    if ($filterServices.Count -gt 0) {
        $svcArg = $filterServices -join ','
        Write-Host "[clear-secrets] Clearing managed credentials in '$distro' for: $svcArg..."
        Invoke-WslRootStdinCommand -DistroName $distro -RemoteCommand "/usr/local/sbin/box-seed-secrets.sh --clear --services $svcArg"
    } else {
        Write-Host "[clear-secrets] Clearing all managed seeded credentials in '$distro'..."
        Invoke-WslRootStdinCommand -DistroName $distro -RemoteCommand '/usr/local/sbin/box-seed-secrets.sh --clear'
    }
}

function Invoke-Status {
    param($Config)
    $distro = $Config.distroName
    $localOverride = Get-BoxLocalOverridePath -ConfigPath $ConfigPath -SearchDir $StateRoot
    $profileOverride = if (-not [string]::IsNullOrWhiteSpace($ProfileName)) {
        Get-ProfileOverridePath -RepoRoot $StateRoot -ProfileName $ProfileName
    } else {
        $null
    }
    if (-not (Test-WslDistroExists -DistroName $distro)) {
        Write-Host "Distro '$distro': NOT INSTALLED"
        if ($localOverride) {
            Write-Host "Local override: $localOverride (active)"
        }
        if ($profileOverride) {
            Write-Host "Profile override ($ProfileName): $profileOverride (active)"
        }
        return
    }
    Write-Host "=== Status: $distro ==="
    if ($localOverride) {
        Write-Host "Local override: $localOverride (active)"
    }
    if ($profileOverride) {
        Write-Host "Profile override ($ProfileName): $profileOverride (active)"
    }
    $agentUid = [int]$Config.agentUser.uid
    $egressMode = if ($Config.PSObject.Properties['network'] -and $Config.network.PSObject.Properties['egressMode']) { "$($Config.network.egressMode)" } else { 'open' }
    $statusScript = "AGENT_UID=$agentUid`nEGRESS_MODE='$egressMode'`n" + @'
echo "OS:          $(. /etc/os-release && echo "$PRETTY_NAME")"
echo "Systemd:     $(systemctl is-system-running 2>/dev/null || echo inactive)"
echo "Hardening:   $(systemctl is-active box-hardening.service 2>/dev/null || echo inactive)"
echo "DockerProxy: $(systemctl is-active docker-policy-proxy.service 2>/dev/null || echo inactive)"
if [ "$EGRESS_MODE" = "allowlist" ]; then
  echo "EgressProxy: $(systemctl is-active egress-proxy.service 2>/dev/null || echo inactive)"
fi
if [ -f /etc/wsl-agent-sandbox/credential-proxy.json ]; then
  echo "CredProxy:   $(systemctl is-active credential-proxy.service 2>/dev/null || echo inactive)"
fi
if [ -f /etc/wsl-agent-sandbox/ssh-agent-allowlist.json ]; then
  echo "SshProxy:    $(systemctl is-active ssh-agent-proxy.service 2>/dev/null || echo inactive)"
fi
echo ""
echo "Active /shared mounts:"
SHARES="$(findmnt -rn -o TARGET,SOURCE,OPTIONS -R /shared 2>/dev/null || true)"
if [ -n "$SHARES" ]; then
  echo "$SHARES"
else
  echo "  (none - deny-all)"
fi
echo ""
echo "Seeded CLI secrets:"
if [ -x /usr/local/sbin/box-seed-secrets.sh ]; then
  /usr/local/sbin/box-seed-secrets.sh --status 2>/dev/null || echo "  (unavailable)"
else
  echo "  (not initialized)"
fi
echo ""
echo "Active nftables table inet wsl_agent_sandbox_${AGENT_UID}:"
nft list table inet "wsl_agent_sandbox_${AGENT_UID}" 2>/dev/null || echo "  (not loaded)"
if nft list table inet wsl_agent_sandbox_shared >/dev/null 2>&1; then
  echo ""
  echo "Shared mirrored-loopback table inet wsl_agent_sandbox_shared:"
  nft list table inet wsl_agent_sandbox_shared 2>/dev/null || true
fi
'@
    Invoke-WslRootBash -DistroName $distro -Script $statusScript
    $installDir = Expand-BoxPath -RawPath $Config.installDir -BaseDir $StateRoot
    $vhdx = Join-Path $installDir 'ext4.vhdx'
    if (Test-Path -LiteralPath $vhdx -PathType Leaf) {
        $sizeGB = [Math]::Round(((Get-Item -LiteralPath $vhdx).Length / 1GB), 2)
        Write-Host ""
        Write-Host "VHDX disk footprint: ${sizeGB} GB ($vhdx)"
    }
    if ($Config.PSObject.Properties['resources'] -and $null -ne $Config.resources) {
        Write-Host "Configured agent UID slice quotas: $($Config.resources | ConvertTo-Json -Compress)"
    }
    foreach ($w in (Get-GlobalWslConfigWarnings)) {
        Write-Warning $w
    }
    foreach ($adv in @(Get-DockerSecurityAdvisories -Config $Config)) {
        Write-Warning $adv
    }
}

function Invoke-Verify {
    param($Config)
    $distro = $Config.distroName
    $agent = $Config.agentUser.name
    if (-not (Test-WslDistroExists -DistroName $distro)) {
        throw "Distro '$distro' does not exist. Run '.\box.ps1 init' first."
    }

    if ($Config.docker.enabled) {
        [void](Sync-DockerDesktopSocketBridge)
    }

    # Ensure host_ips.txt is fresh
    $hostIps = (Get-WindowsHostIPs) -join "`n"
    Copy-TextToWsl -DistroName $distro -Content ($hostIps + "`n") -RemotePath '/etc/wsl-agent-sandbox/host_ips.txt' -Mode '0600'

    $overallFailed = $false
    $blockHostAndLan = $true
    if ($Config.network -and $Config.network.PSObject.Properties['blockHostAndLan'] -and $null -ne $Config.network.blockHostAndLan) {
        $blockHostAndLan = [bool]$Config.network.blockHostAndLan
    }

    # Start an ephemeral TCP listener on Windows host so we can PROVE nftables blocks
    # an actually-open Windows host port (not just a closed port!) when blockHostAndLan=true.
    $winListener = $null
    $winTestPort = ''
    $winTestIp = ''
    if ($blockHostAndLan) {
        try {
            $winListener = New-Object System.Net.Sockets.TcpListener([System.Net.IPAddress]::Any, 0)
            $winListener.Start()
            $winTestPort = $winListener.LocalEndpoint.Port
            # Prefer an actual Windows host IPv4 (works in both NAT and mirrored modes) so we probe
            # the genuinely-open Windows TcpListener rather than an external LAN router.
            $hostV4s = @(Get-WindowsHostIPs | Where-Object { $_ -match '^\d+\.\d+\.\d+\.\d+$' -and $_ -notmatch '^169\.254\.' })
            $winTestIp = $hostV4s | Select-Object -First 1
            if ([string]::IsNullOrWhiteSpace($winTestIp)) {
                $winTestIp = (& wsl.exe -d $distro -u root -- sh -c 'ip -4 route show default | awk "{for(i=1;i<=NF;i++) if(\$i==\"via\") {print \$(i+1); exit}}"' | Out-String).Trim()
            }
            Write-Host "[verify] Started ephemeral Windows host TCP listener on port $winTestPort (target $winTestIp) to test WSL->Windows blocking..."
        } catch {
            Write-Warning "[verify] Could not bind ephemeral Windows listener: $($_.Exception.Message)"
        }
    }

    try {
        # Run red-team isolation & capability suite inside WSL as non-root agent
        & wsl.exe -d $distro -u $agent -- bash -lc "/usr/local/bin/box-verify-isolation.sh '$winTestPort' '$winTestIp'"
        if ($LASTEXITCODE -ne 0) {
            $overallFailed = $true
        }
    } finally {
        if ($winListener) {
            try { $winListener.Stop() } catch { Write-Verbose "Ignoring listener stop error: $($_.Exception.Message)" }
        }
    }

    # Verify WSL -> Windows 127.0.0.1 (mirrored loopback) is blocked when blockHostAndLan=true!
    Write-Host ""
    Write-Host "[Windows <-> WSL Localhost Isolation & Web Server Tests]"
    if (-not $blockHostAndLan) {
        Write-Host "  [WARN] Host & LAN isolation disabled by policy (network.blockHostAndLan=false)"
    } else {
        $winLoopListener = $null
        try {
            $winLoopListener = New-Object System.Net.Sockets.TcpListener([System.Net.IPAddress]::Loopback, 0)
            $winLoopListener.Start()
            $winLoopPort = $winLoopListener.LocalEndpoint.Port
            $loopOut = (& wsl.exe -d $distro -u $agent -- bash -c "if nc -z -w 2 127.0.0.1 $winLoopPort >/dev/null 2>&1; then echo REACHABLE; else echo BLOCKED; fi" | Out-String).Trim()
            if ($loopOut -eq 'BLOCKED') {
                Write-Host "  [PASS] Outbound connection from WSL agent to Windows 127.0.0.1:$winLoopPort blocked (even in mirrored mode)"
            } else {
                Write-Host "  [FAIL] WSL agent reached Windows 127.0.0.1:$winLoopPort!"
                $overallFailed = $true
            }
        } finally {
            if ($winLoopListener) {
                try { $winLoopListener.Stop() } catch { Write-Verbose "Ignoring loopback listener stop error: $($_.Exception.Message)" }
            }
        }
    }

    # Verify Windows -> WSL localhost web browsing AND WSL-internal localhost using an ephemeral free port!
    $webPort = 0
    $token = "wsl-localhost-ok-$([Guid]::NewGuid().ToString('N').Substring(0, 8))"
    $serverProc = $null
    try {
        $prepWeb = @'
set -euo pipefail
mkdir -p /tmp/box-web-verify
rm -f /tmp/box-web-verify/port.txt /tmp/box-web-verify/port.txt.tmp
cat <<'PYEOF' > /tmp/box-web-verify/srv.py
import functools
import http.server
import os
handler = functools.partial(http.server.SimpleHTTPRequestHandler, directory="/tmp/box-web-verify")
httpd = http.server.HTTPServer(("0.0.0.0", 0), handler)
with open("/tmp/box-web-verify/port.txt.tmp", "w", encoding="utf-8") as f:
    f.write(str(httpd.server_port))
os.replace("/tmp/box-web-verify/port.txt.tmp", "/tmp/box-web-verify/port.txt")
httpd.serve_forever()
PYEOF
printf '%s' "$1" > /tmp/box-web-verify/token.txt
'@.Replace("`r`n", "`n")
        $null = Invoke-WslAgentBashStdin -DistroName $distro -AgentName $agent -BashArgs @($token) -ScriptText $prepWeb
        $serverProc = Start-Process -FilePath 'wsl.exe' -ArgumentList "-d $distro -u $agent -- python3 /tmp/box-web-verify/srv.py" -PassThru -WindowStyle Hidden

        for ($i = 0; $i -lt 25; $i++) {
            Start-Sleep -Milliseconds 200
            $portStr = (& wsl.exe -d $distro -u $agent -- cat /tmp/box-web-verify/port.txt 2>$null | Out-String).Trim()
            if ($portStr -match '^\d+$') {
                $webPort = [int]$portStr
                break
            }
        }

        $winOk = $false
        if ($webPort -gt 0) {
            for ($i = 0; $i -lt 15; $i++) {
                try {
                    $resp = Invoke-WebRequest -Uri "http://127.0.0.1:$webPort/token.txt" -UseBasicParsing -TimeoutSec 2
                    if ($resp.StatusCode -eq 200 -and $resp.Content.Trim() -eq $token) {
                        $winOk = $true
                        break
                    }
                } catch {
                    Write-Verbose "Waiting for WSL test HTTP server on port ${webPort}: $($_.Exception.Message)"
                }
                Start-Sleep -Milliseconds 250
            }
        }

        if ($winOk) {
            Write-Host "  [PASS] Windows successfully browsed http://localhost:$webPort hosted by non-root agent inside WSL!"
        } else {
            Write-Host "  [FAIL] Windows could NOT reach http://localhost:$webPort hosted inside WSL!"
            $overallFailed = $true
        }

        $wslSelf = if ($webPort -gt 0) {
            (& wsl.exe -d $distro -u $agent -- curl -fsS --max-time 3 "http://127.0.0.1:$webPort/token.txt" 2>$null | Out-String).Trim()
        } else { '' }
        if ($wslSelf -eq $token) {
            Write-Host "  [PASS] WSL-internal localhost (http://127.0.0.1:$webPort) still works for agent's own local services!"
        } else {
            Write-Host "  [FAIL] WSL-internal localhost failed!"
            $overallFailed = $true
        }
    } finally {
        if ($serverProc -and -not $serverProc.HasExited) {
            try { $serverProc.Kill() } catch { Write-Verbose "Ignoring test HTTP server kill error: $($_.Exception.Message)" }
        }
        & wsl.exe -d $distro -u $agent -- rm -rf /tmp/box-web-verify 2>$null | Out-Null
    }

    foreach ($w in (Get-GlobalWslConfigWarnings)) {
        Write-Warning $w
    }

    if ($overallFailed) {
        throw "Verification failed! Review the [FAIL] lines above."
    }
    Write-Host ""
    Write-Host "[verify] ALL security containment and capability checks PASSED!"
}

function Invoke-Upgrade {
    param(
        $Config,
        [string[]]$Scope = @('all')
    )
    $distro = $Config.distroName
    if (-not (Test-WslDistroExists -DistroName $distro)) {
        throw "Distro '$distro' does not exist. Run '.\box.ps1 init' first."
    }
    $validScopes = @('all', 'apt', 'agents', 'toolchains')
    $normalized = New-Object System.Collections.Generic.List[string]
    foreach ($s in @($Scope)) {
        foreach ($part in ($s -split ',')) {
            $clean = $part.Trim().ToLowerInvariant()
            if (-not $clean) { continue }
            if ($clean -notin $validScopes) {
                throw "Invalid -Scope '$clean'. Valid values: $($validScopes -join ', ')"
            }
            $normalized.Add($clean)
        }
    }
    $scopeArg = if ($normalized.Count -gt 0) { $normalized -join ',' } else { 'all' }
    Copy-FileToWsl -DistroName $distro -LocalPath (Join-Path $AppRoot 'scripts\linux\upgrade-tools.sh') -RemotePath '/usr/local/sbin/box-upgrade-tools.sh' -Mode '0755' -NormalizeLF
    Write-Host "[upgrade] Running in-place upgrade in '$distro' (scope=$scopeArg)..."
    & wsl.exe -d $distro -u root -- /usr/local/sbin/box-upgrade-tools.sh $scopeArg
    if ($LASTEXITCODE -ne 0) {
        throw "upgrade-tools.sh failed with exit code $LASTEXITCODE."
    }
}

function Invoke-Doctor {
    param($Config)
    Write-Host "=== wsl-agent-sandbox Doctor ==="
    $hasFail = $false

    # 1. WSL2 availability
    $wslCmd = Get-Command wsl.exe -ErrorAction SilentlyContinue
    if (-not $wslCmd) {
        Write-Host "  [FAIL] wsl.exe not found on PATH. Ensure WSL2 is installed and enabled."
        $hasFail = $true
    } else {
        try {
            $null = & $wslCmd.Source --status 2>&1
            if ($LASTEXITCODE -eq 0) {
                Write-Host "  [PASS] WSL2 CLI reachable (wsl.exe --status)"
            } else {
                Write-Host "  [FAIL] wsl.exe --status failed (exit code $LASTEXITCODE). Ensure WSL2 is installed and enabled."
                $hasFail = $true
            }
        } catch {
            Write-Host "  [FAIL] wsl.exe --status error: $($_.Exception.Message)"
            $hasFail = $true
        }
    }

    # 2. Global .wslconfig checks
    $warnings = @(Get-GlobalWslConfigWarnings)
    if ($warnings.Count -eq 0) {
        Write-Host "  [PASS] Global .wslconfig has no blocking warnings"
    } else {
        foreach ($w in $warnings) {
            Write-Host "  [WARN] $w"
        }
    }

    # 3. Distro & systemd checks
    $distro = $Config.distroName
    $distroInstalled = $wslCmd -and (Test-WslDistroExists -DistroName $distro)
    if ($distroInstalled) {
        Write-Host "  [PASS] Distro '$distro' is registered"
        $runningRaw = & $wslCmd.Source --list --quiet --running 2>$null
        $runningList = @($runningRaw | ForEach-Object { ("$_" -replace "`0", '').Trim() } | Where-Object { $_ })
        if ($runningList -notcontains $distro) {
            Write-Host "  [INFO] Distro '$distro' was stopped; waiting for systemd startup..."
            [void](Wait-WslSystemdReady -DistroName $distro -TimeoutSeconds 45)
        }
        $sysState = (& $wslCmd.Source -d $distro -u root -- sh -c "systemctl is-system-running 2>/dev/null || echo inactive" | Out-String).Trim()
        if ($sysState -eq 'running' -or $sysState -eq 'degraded') {
            Write-Host "  [PASS] systemd state: $sysState"
        } else {
            Write-Host "  [WARN] systemd state: $sysState (try '.\box.ps1 up')"
        }
        $hardenState = (& $wslCmd.Source -d $distro -u root -- sh -c "systemctl is-active box-hardening.service 2>/dev/null || echo inactive" | Out-String).Trim()
        if ($hardenState -eq 'active') {
            Write-Host "  [PASS] box-hardening.service is active"
        } else {
            Write-Host "  [FAIL] box-hardening.service is $hardenState (run '.\box.ps1 apply')"
            $hasFail = $true
        }
        $egressMode = if ($Config.PSObject.Properties['network'] -and $Config.network.PSObject.Properties['egressMode']) { "$($Config.network.egressMode)" } else { 'open' }
        if ($egressMode -eq 'allowlist') {
            $egressState = (& $wslCmd.Source -d $distro -u root -- sh -c "systemctl is-active egress-proxy.service 2>/dev/null || echo inactive" | Out-String).Trim()
            if ($egressState -eq 'active') {
                Write-Host "  [PASS] egress-proxy.service is active"
            } else {
                Write-Host "  [FAIL] egress-proxy.service is $egressState (run '.\box.ps1 apply')"
                $hasFail = $true
            }
        }
        $credState = (& $wslCmd.Source -d $distro -u root -- sh -c 'if [ -f /etc/wsl-agent-sandbox/credential-proxy.json ]; then systemctl is-active credential-proxy.service 2>/dev/null || echo inactive; else echo NOT_CONFIGURED; fi' | Out-String).Trim()
        if ($credState -eq 'active') {
            Write-Host "  [PASS] credential-proxy.service is active"
        } elseif ($credState -ne 'NOT_CONFIGURED') {
            Write-Host "  [FAIL] credential-proxy.service is $credState (run '.\box.ps1 seed-secrets')"
            $hasFail = $true
        }
        $sshState = (& $wslCmd.Source -d $distro -u root -- sh -c 'if [ -f /etc/wsl-agent-sandbox/ssh-agent-allowlist.json ]; then systemctl is-active ssh-agent-proxy.service 2>/dev/null || echo inactive; else echo NOT_CONFIGURED; fi' | Out-String).Trim()
        if ($sshState -eq 'active') {
            Write-Host "  [PASS] ssh-agent-proxy.service is active"
        } elseif ($sshState -ne 'NOT_CONFIGURED') {
            Write-Host "  [FAIL] ssh-agent-proxy.service is $sshState (run '.\box.ps1 apply')"
            $hasFail = $true
        }
    } else {
        Write-Host "  [WARN] Distro '$distro' is not installed yet (run '.\box.ps1 init')"
    }

    # 4. Docker Desktop bridge & WSL proxy check
    if ($Config.docker.enabled) {
        $pipes = @(Get-ChildItem '\\.\pipe\' -ErrorAction SilentlyContinue | Where-Object { $_.Name -eq 'docker_engine' })
        if ($pipes.Count -gt 0) {
            Write-Host "  [PASS] Docker Desktop named pipe (docker_engine) is active"
        } else {
            Write-Host "  [WARN] Docker Desktop is not running (docker.enabled=true). Start Docker Desktop on Windows."
        }
        if ($distroInstalled) {
            $ddSock = (& $wslCmd.Source -d $distro -u root -- sh -c '[ -S /run/box-root/mnt-wsl/box-binds/dd-upstream.sock ] && echo OK || echo MISSING' 2>$null | Out-String).Trim()
            if ($ddSock -eq 'OK') {
                Write-Host "  [PASS] Docker upstream socket bridge (dd-upstream.sock) present"
            } else {
                Write-Host "  [WARN] Docker upstream socket bridge (dd-upstream.sock) missing (run '.\box.ps1 up' or '.\box.ps1 apply')"
            }
            $proxyState = (& $wslCmd.Source -d $distro -u root -- sh -c "systemctl is-active docker-policy-proxy.service 2>/dev/null || echo inactive" | Out-String).Trim()
            if ($proxyState -eq 'active') {
                Write-Host "  [PASS] docker-policy-proxy.service is active"
            } else {
                Write-Host "  [FAIL] docker-policy-proxy.service is $proxyState (run '.\box.ps1 apply')"
                $hasFail = $true
            }
        }
        foreach ($adv in @(Get-DockerSecurityAdvisories -Config $Config)) {
            Write-Host "  [WARN] $adv"
        }
    } else {
        Write-Host "  [PASS] Docker integration disabled per policy (docker.enabled=false)"
    }

    # 5. VHDX disk size & image cache
    $installDir = Expand-BoxPath -RawPath $Config.installDir -BaseDir $StateRoot
    $vhdx = Join-Path $installDir 'ext4.vhdx'
    if (Test-Path -LiteralPath $vhdx -PathType Leaf) {
        $sizeGB = [Math]::Round(((Get-Item -LiteralPath $vhdx).Length / 1GB), 2)
        Write-Host "  [PASS] VHDX footprint: ${sizeGB} GB ($vhdx)"
    }
    $cacheDir = Expand-BoxPath -RawPath $Config.image.cacheDir -BaseDir $StateRoot
    $cachedImages = @(Get-ChildItem -Path $cacheDir -Filter 'ubuntu-*.wsl' -ErrorAction SilentlyContinue)
    if ($cachedImages.Count -gt 0) {
        Write-Host "  [PASS] Cached Ubuntu WSL image(s): $($cachedImages.Name -join ', ')"
    } else {
        Write-Host "  [WARN] No cached Ubuntu .wsl image in '$cacheDir' (will download on init)"
    }

    # 6. VS Code / Antigravity Remote-WSL scriptLessStartup check (only when opted in via ide.configureRemoteWsl)
    if (Test-ShouldConfigureIdeRemoteWsl -Config $Config) {
        $idePaths = @(Get-IdeUserSettingsPaths)
        foreach ($idePath in $idePaths) {
            try {
                $rawIde = Get-Content -LiteralPath $idePath -Raw -Encoding UTF8
                $ideJson = if ([string]::IsNullOrWhiteSpace($rawIde)) { $null } else { ConvertFrom-Jsonc -Text $rawIde }
                if ($null -ne $ideJson -and $ideJson.PSObject.Properties['remote.WSL.experimental.scriptLessStartup'] -and ($ideJson.'remote.WSL.experimental.scriptLessStartup' -eq $true)) {
                    Write-Host "  [PASS] IDE Remote-WSL scriptLessStartup enabled ($idePath)"
                } else {
                    Write-Host "  [WARN] IDE Remote-WSL scriptLessStartup not enabled in '$idePath' (run '.\box.ps1 apply' to configure automatically)"
                }
            } catch {
                Write-Host "  [WARN] Could not parse IDE settings '$idePath': $($_.Exception.Message)"
            }
        }
    }

    if ($hasFail) {
        throw "Doctor found one or more failing checks."
    }
}

function Invoke-Compact {
    param($Config)
    $distro = $Config.distroName
    if (-not (Test-WslDistroExists -DistroName $distro)) {
        throw "Distro '$distro' does not exist."
    }
    $installDir = Expand-BoxPath -RawPath $Config.installDir -BaseDir $StateRoot
    $vhdx = Join-Path $installDir 'ext4.vhdx'
    if (-not (Test-Path -LiteralPath $vhdx -PathType Leaf)) {
        throw "VHDX file not found at '$vhdx'."
    }
    $principal = New-Object System.Security.Principal.WindowsPrincipal([System.Security.Principal.WindowsIdentity]::GetCurrent())
    if (-not $principal.IsInRole([System.Security.Principal.WindowsBuiltInRole]::Administrator)) {
        throw "VHDX compaction requires an elevated Administrator PowerShell session (Optimize-VHD and diskpart require Administrator privileges)."
    }

    $beforeBytes = (Get-Item -LiteralPath $vhdx).Length
    Write-Host "[compact] Running fstrim inside '$distro'..."
    & wsl.exe -d $distro -u root -- fstrim -av
    if ($LASTEXITCODE -ne 0) {
        throw "fstrim inside '$distro' failed with exit code $LASTEXITCODE."
    }
    Write-Host "[compact] Terminating '$distro' before VHDX compaction..."
    & wsl.exe --terminate $distro | Out-Null
    if ($LASTEXITCODE -ne 0) {
        throw "wsl --terminate '$distro' failed with exit code $LASTEXITCODE."
    }
    Start-Sleep -Seconds 2

    if (Get-Command Optimize-VHD -ErrorAction SilentlyContinue) {
        Write-Host "[compact] Compacting '$vhdx' via Optimize-VHD..."
        Optimize-VHD -Path $vhdx -Mode Full
    } else {
        Write-Host "[compact] Optimize-VHD unavailable; compacting '$vhdx' via diskpart..."
        $dpScript = "select vdisk file=""$vhdx""`r`nattach vdisk readonly`r`ncompact vdisk`r`ndetach vdisk"
        $tmpDp = Join-Path ([System.IO.Path]::GetTempPath()) ("wsl-compact-" + [Guid]::NewGuid().ToString('N').Substring(0, 8) + ".txt")
        try {
            [System.IO.File]::WriteAllText($tmpDp, $dpScript, [System.Text.Encoding]::Unicode)
            $dpOut = (& diskpart.exe /s $tmpDp 2>&1 | Out-String).Trim()
            if ($LASTEXITCODE -ne 0) {
                throw "diskpart compaction failed (exit code $LASTEXITCODE): $dpOut"
            }
        } finally {
            Remove-Item -LiteralPath $tmpDp -Force -ErrorAction SilentlyContinue
        }
    }
    $afterBytes = (Get-Item -LiteralPath $vhdx).Length
    $savedMB = [Math]::Round(($beforeBytes - $afterBytes) / 1MB, 1)
    Write-Host ("[compact] Done: {0:N2} GB -> {1:N2} GB (reclaimed {2:N1} MB)." -f ($beforeBytes / 1GB), ($afterBytes / 1GB), $savedMB)
}

function Invoke-AuditLogs {
    param(
        $Config,
        [string]$Source = 'all',
        [string]$Since = '1 hour ago',
        [ValidateRange(1, 100000)]
        [int]$Lines = 100
    )
    if ($Lines -lt 1 -or $Lines -gt 100000) {
        throw "-Lines must be between 1 and 100000."
    }
    $distro = $Config.distroName
    if (-not (Test-WslDistroExists -DistroName $distro)) {
        throw "Distro '$distro' does not exist."
    }
    $safeSince = $Since -replace "'", ""
    # Validate --since timestamp up front so invalid expressions fail loudly instead of being masked.
    $sinceCheck = "journalctl --since '$safeSince' -n 0 >/dev/null"
    $cmd = switch ($Source) {
        'docker'      { "$sinceCheck && journalctl -u docker-policy-proxy.service --since '$safeSince' -n $Lines --no-pager" }
        'hardening'   { "$sinceCheck && journalctl -u box-hardening.service --since '$safeSince' -n $Lines --no-pager" }
        'egress'      { "$sinceCheck && journalctl -u egress-proxy.service --since '$safeSince' -n $Lines --no-pager" }
        'credentials' { "$sinceCheck && journalctl -u credential-proxy.service --since '$safeSince' -n $Lines --no-pager" }
        'ssh-agent'   { "$sinceCheck && journalctl -u ssh-agent-proxy.service --since '$safeSince' -n $Lines --no-pager" }
        'network'     { "$sinceCheck && (journalctl -u egress-proxy.service --since '$safeSince' -n $Lines --no-pager || true) && echo '--- Kernel nftables drops ---' && (journalctl -k --grep='wsl-agent-sandbox-drop' --since '$safeSince' -n $Lines --no-pager || true)" }
        default       { "$sinceCheck && (journalctl -u docker-policy-proxy.service -u box-hardening.service -u egress-proxy.service -u credential-proxy.service -u ssh-agent-proxy.service -u 'wsl-box-ttl-*.service' --since '$safeSince' -n $Lines --no-pager || true) && echo '--- Kernel nftables drops ---' && (journalctl -k --grep='wsl-agent-sandbox-drop' --since '$safeSince' -n $Lines --no-pager || true)" }
    }
    Write-Host "=== Security Audit Logs: $distro (source=$Source, since='$safeSince') ==="
    Invoke-WslRootBash -DistroName $distro -Script $cmd
}

function Assert-SafeBoxBranchName {
    param([Parameter(Mandatory)][string]$Name)
    $trimmed = $Name.Trim()
    if ([string]::IsNullOrWhiteSpace($trimmed) -or
        $trimmed.StartsWith('-') -or
        $trimmed.StartsWith('/') -or
        $trimmed.EndsWith('/') -or
        $trimmed.EndsWith('.lock') -or
        $trimmed.Contains('..') -or
        $trimmed.Contains('@{') -or
        $trimmed -notmatch '^[A-Za-z0-9._/@^-]+$') {
        throw "Invalid git branch/ref name '$Name'."
    }
    return $trimmed
}

function Resolve-WslWorkRelPath {
    param(
        [Parameter(Mandatory)][string]$RawPath,
        [string]$DefaultPrefix = ''
    )
    $norm = ($RawPath.Trim() -replace '\\', '/') -replace '^~/', ''
    if ([string]::IsNullOrWhiteSpace($norm)) {
        throw "Specify a non-empty relative repository path."
    }
    if ($DefaultPrefix -and -not $norm.Contains('/')) {
        $norm = "$DefaultPrefix/$norm"
    }
    if ($norm.StartsWith('/') -or
        $norm.Contains('..') -or
        $norm.StartsWith('-') -or
        $norm -notmatch '^[A-Za-z0-9._/-]+$') {
        throw "Repository path '$RawPath' must be a safe relative path inside ~/."
    }
    return $norm.TrimEnd('/')
}

function Resolve-SandboxCheckoutBranch {
    param(
        [Parameter(Mandatory)][string]$SafeBranch,
        [string]$SymbolicHead = ''
    )
    $candidate = ''
    if ($SafeBranch -eq 'HEAD') {
        $candidate = $SymbolicHead.Trim()
    } elseif ($SafeBranch -notmatch '^[0-9a-fA-F]{7,40}$') {
        $candidate = $SafeBranch -replace '^refs/heads/', ''
    }

    if ([string]::IsNullOrWhiteSpace($candidate) -or
        $candidate -eq 'HEAD' -or
        $candidate -match '[\^~:@]' -or
        $candidate -match '^[0-9a-fA-F]{7,40}$') {
        return 'sandbox-base'
    }

    & git check-ref-format --branch $candidate 2>$null | Out-Null
    if ($LASTEXITCODE -ne 0) {
        return 'sandbox-base'
    }
    return $candidate
}

function Resolve-PullTargetBranchName {
    param(
        [Parameter(Mandatory)][string]$RepoLeafName,
        [string]$SafeBranch = 'HEAD'
    )
    $safeName = $RepoLeafName -replace '[^A-Za-z0-9._-]', '-'
    if ([string]::IsNullOrWhiteSpace($SafeBranch) -or $SafeBranch -eq 'HEAD') {
        return "sandbox/$safeName"
    }
    $sanitizedBranch = ($SafeBranch -replace '^refs/heads/', '') -replace '[^A-Za-z0-9._/-]', '-'
    $sanitizedBranch = $sanitizedBranch.Trim('/')
    if ([string]::IsNullOrWhiteSpace($sanitizedBranch)) {
        return "sandbox/$safeName"
    }
    return "sandbox/$safeName-$sanitizedBranch"
}

function Invoke-PushRepo {
    param(
        $Config,
        [string]$WindowsRepoPath,
        [string]$Dest = '',
        [string]$Branch = 'HEAD',
        [switch]$Force
    )
    $distro = $Config.distroName
    $agent = $Config.agentUser.name
    if (-not (Test-WslDistroExists -DistroName $distro)) { throw "Distro '$distro' does not exist." }
    if ([string]::IsNullOrWhiteSpace($WindowsRepoPath) -or -not (Test-Path -LiteralPath $WindowsRepoPath -PathType Container)) {
        throw "Windows repository directory not found: '$WindowsRepoPath'"
    }
    $resolved = (Resolve-Path -LiteralPath $WindowsRepoPath).Path
    $isGit = (& git -C $resolved rev-parse --is-inside-work-tree 2>$null | Out-String).Trim()
    if ($isGit -ne 'true') {
        throw "'$resolved' is not a git repository."
    }
    $safeBranch = Assert-SafeBoxBranchName -Name $Branch
    $targetOid = (& git -C $resolved rev-parse --verify --quiet "$safeBranch^{commit}" 2>$null | Out-String).Trim()
    if ($LASTEXITCODE -ne 0 -or [string]::IsNullOrWhiteSpace($targetOid)) {
        throw "Git ref '$safeBranch' not found in '$resolved'."
    }

    $repoName = Split-Path -Leaf $resolved
    $rawDest = if ([string]::IsNullOrWhiteSpace($Dest)) { "work/$repoName" } else { $Dest }
    $targetRel = Resolve-WslWorkRelPath -RawPath $rawDest

    $headSym = ''
    if ($safeBranch -eq 'HEAD') {
        $headSym = (& git -C $resolved symbolic-ref --short -q HEAD 2>$null | Out-String).Trim()
    }
    $checkoutBranch = Resolve-SandboxCheckoutBranch -SafeBranch $safeBranch -SymbolicHead $headSym

    $bundleRefs = New-Object System.Collections.Generic.List[string]
    $bundleRefs.Add($safeBranch)
    $mainRef = ''
    foreach ($candidateMain in @('refs/heads/main', 'refs/remotes/origin/main', 'refs/heads/master')) {
        & git -C $resolved rev-parse --verify --quiet $candidateMain 2>$null | Out-Null
        if ($LASTEXITCODE -eq 0) {
            $mainRef = $candidateMain
            break
        }
    }
    $mainOid = ''
    if ($mainRef) {
        $mainOid = (& git -C $resolved rev-parse --verify --quiet "$mainRef^{commit}" 2>$null | Out-String).Trim()
        if ($mainRef -ne $safeBranch) {
            $bundleRefs.Add($mainRef)
        }
    }

    $tmpBundle = Join-Path ([System.IO.Path]::GetTempPath()) ("wsl-push-" + [Guid]::NewGuid().ToString('N').Substring(0, 8) + ".bundle")
    try {
        Write-Host "[push-repo] Creating git bundle from '$resolved' ($($bundleRefs -join ', '))..."
        & git -C $resolved bundle create $tmpBundle @bundleRefs
        if ($LASTEXITCODE -ne 0) { throw "git bundle create failed." }

        $remoteScript = @'
set -euo pipefail
target_rel="$1"
checkout_branch="$2"
force_flag="$3"
target_oid="$4"
main_oid="${5:-}"
tmp="$(mktemp /tmp/box-push-XXXXXX.bundle)"
trap 'rm -f "$tmp"' EXIT
cat > "$tmp"
target="$HOME/$target_rel"
if [ ! -s "$tmp" ]; then
  echo "[push-repo] ERROR: received empty bundle." >&2
  exit 1
fi
if [ -d "$target/.git" ]; then
  if [ "$force_flag" != "1" ] && [ -n "$(git -C "$target" status --porcelain)" ]; then
    echo "[push-repo] ERROR: $target has uncommitted changes (commit/stash or pass -Force to overwrite)." >&2
    exit 1
  fi
  if origin_url="$(git -C "$target" remote get-url origin 2>/dev/null || true)"; then
    case "$origin_url" in
      /tmp/box-push-*.bundle) git -C "$target" remote remove origin 2>/dev/null || true ;;
    esac
  fi
else
  mkdir -p "$target"
  git -C "$target" init -q
fi
while read -r _oid bref; do
  [ -n "$bref" ] && git -C "$target" fetch -q "$tmp" "$bref"
done < <(git bundle list-heads "$tmp")
git -C "$target" checkout -B "$checkout_branch" "$target_oid"
git -C "$target" update-ref refs/sandbox/base "$target_oid"
if [ -n "$main_oid" ]; then
  git -C "$target" update-ref refs/remotes/origin/main "$main_oid"
fi
echo "[push-repo] Synced branch $checkout_branch to $target"
'@
        $lfScript = ($remoteScript -replace "`r`n", "`n").TrimEnd("`n") + "`n"
        $escapedScript = '"' + ($lfScript -replace '"', '\"') + '"'
        $forceArg = if ($Force) { '1' } else { '0' }

        $psi = New-Object System.Diagnostics.ProcessStartInfo
        $psi.FileName = 'wsl.exe'
        $psi.Arguments = "-d $distro -u $agent -- bash -c $escapedScript _ `"$targetRel`" `"$checkoutBranch`" `"$forceArg`" `"$targetOid`" `"$mainOid`""
        $psi.UseShellExecute = $false
        $psi.RedirectStandardInput = $true
        $psi.RedirectStandardOutput = $true
        $psi.RedirectStandardError = $true

        $proc = [System.Diagnostics.Process]::Start($psi)
        try {
            $stdoutTask = $proc.StandardOutput.ReadToEndAsync()
            $stderrTask = $proc.StandardError.ReadToEndAsync()
            $fs = [System.IO.File]::OpenRead($tmpBundle)
            try {
                $fs.CopyTo($proc.StandardInput.BaseStream)
                $proc.StandardInput.BaseStream.Flush()
            } finally {
                $fs.Dispose()
            }
            $proc.StandardInput.Close()
            $proc.WaitForExit()
            $stdout = $stdoutTask.GetAwaiter().GetResult()
            $stderr = $stderrTask.GetAwaiter().GetResult()
            if ($stdout) { Write-Host $stdout.TrimEnd() }
            if ($proc.ExitCode -ne 0) {
                throw "Failed pushing bundle into WSL: $stderr"
            }
        } finally {
            $proc.Dispose()
        }
    } finally {
        Remove-Item -LiteralPath $tmpBundle -Force -ErrorAction SilentlyContinue
    }
}

function Invoke-WslAgentBashStdin {
    param(
        [Parameter(Mandatory)][string]$DistroName,
        [Parameter(Mandatory)][string]$AgentName,
        [Parameter(Mandatory)][string[]]$BashArgs,
        [Parameter(Mandatory)][string]$ScriptText
    )
    $lfScript = ($ScriptText -replace "`r`n", "`n").TrimEnd("`n") + "`n"
    $psi = New-Object System.Diagnostics.ProcessStartInfo
    $psi.FileName = 'wsl.exe'
    $escapedArgs = ($BashArgs | ForEach-Object {
        if ($_ -match '[\s"]') { '"' + ($_ -replace '"', '\"') + '"' } else { $_ }
    }) -join ' '
    $psi.Arguments = "-d $DistroName -u $AgentName -- bash -s -- $escapedArgs"
    $psi.UseShellExecute = $false
    $psi.RedirectStandardInput = $true
    $psi.RedirectStandardOutput = $true
    $psi.RedirectStandardError = $true
    $proc = [System.Diagnostics.Process]::Start($psi)
    try {
        $stdoutTask = $proc.StandardOutput.ReadToEndAsync()
        $stderrTask = $proc.StandardError.ReadToEndAsync()
        $utf8NoBom = New-Object System.Text.UTF8Encoding($false)
        $bytes = $utf8NoBom.GetBytes($lfScript)
        $proc.StandardInput.BaseStream.Write($bytes, 0, $bytes.Length)
        $proc.StandardInput.BaseStream.Flush()
        $proc.StandardInput.Close()
        $proc.WaitForExit()
        $stdout = $stdoutTask.GetAwaiter().GetResult()
        $stderr = $stderrTask.GetAwaiter().GetResult()
        return [pscustomobject]@{
            ExitCode = $proc.ExitCode
            Stdout   = $stdout
            Stderr   = $stderr
        }
    } finally {
        $proc.Dispose()
    }
}

function Invoke-PullDiff {
    param(
        $Config,
        [string]$RepoName
    )
    $distro = $Config.distroName
    $agent = $Config.agentUser.name
    if (-not (Test-WslDistroExists -DistroName $distro)) {
        throw "Distro '$distro' does not exist."
    }
    $rel = Resolve-WslWorkRelPath -RawPath $RepoName -DefaultPrefix 'work'
    $remoteScript = @'
set -euo pipefail
target="$HOME/$1"
if ! git -C "$target" rev-parse --is-inside-work-tree >/dev/null 2>&1; then
  echo "[pull-diff] ERROR: $target is not a git repository." >&2
  exit 1
fi
echo "=== Status ==="
git -C "$target" status --short
if git -C "$target" rev-parse --verify --quiet refs/sandbox/base >/dev/null; then
  echo "=== Commits Since Push (refs/sandbox/base..HEAD) ==="
  git -C "$target" log --oneline refs/sandbox/base..HEAD
  echo "=== Committed Diff Stat (refs/sandbox/base..HEAD) ==="
  git -C "$target" diff --stat refs/sandbox/base..HEAD
  if [ -n "$(git -C "$target" status --porcelain)" ]; then
    echo "=== Uncommitted Working Tree Diff Stat ==="
    git -C "$target" diff HEAD --stat
  fi
else
  echo "=== Recent Commits ==="
  git -C "$target" log --oneline -n 15
  echo "=== Diff Stat ==="
  git -C "$target" diff HEAD --stat 2>/dev/null || git -C "$target" diff --stat
fi
wt_count="$(git -C "$target" worktree list --porcelain | grep -c '^worktree ' || true)"
if [ "$wt_count" -gt 1 ]; then
  echo "=== Active Git Worktrees ==="
  git -C "$target" worktree list
fi
'@
    $res = Invoke-WslAgentBashStdin -DistroName $distro -AgentName $agent -BashArgs @($rel) -ScriptText $remoteScript
    if ($res.Stdout) { Write-Host $res.Stdout.TrimEnd() }
    if ($res.ExitCode -ne 0) {
        throw "pull-diff failed for '~/$rel' in '$distro': $($res.Stderr)"
    }
}

function Invoke-PullBranch {
    param(
        $Config,
        [string]$RepoName,
        [string]$WindowsRepoPath = '',
        [string]$Branch = 'HEAD'
    )
    $distro = $Config.distroName
    $agent = $Config.agentUser.name
    if (-not (Test-WslDistroExists -DistroName $distro)) {
        throw "Distro '$distro' does not exist."
    }
    $rel = Resolve-WslWorkRelPath -RawPath $RepoName -DefaultPrefix 'work'
    $safeBranch = Assert-SafeBoxBranchName -Name $Branch

    $winTargetRaw = if ([string]::IsNullOrWhiteSpace($WindowsRepoPath)) { (Get-Location).Path } else { $WindowsRepoPath }
    if (-not (Test-Path -LiteralPath $winTargetRaw -PathType Container)) {
        throw "Windows target repository directory not found: '$winTargetRaw'"
    }
    $winRepo = (Resolve-Path -LiteralPath $winTargetRaw).Path
    $isGit = (& git -C $winRepo rev-parse --is-inside-work-tree 2>$null | Out-String).Trim()
    if ($isGit -ne 'true') {
        throw "Windows target '$winRepo' is not a git repository."
    }

    $targetBranch = Resolve-PullTargetBranchName -RepoLeafName (Split-Path -Leaf $rel) -SafeBranch $safeBranch
    $tmpBundle = Join-Path ([System.IO.Path]::GetTempPath()) ("wsl-pull-" + [Guid]::NewGuid().ToString('N').Substring(0, 8) + ".bundle")
    try {
        $remoteScript = @'
set -euo pipefail
target="$HOME/$1"
ref="$2"
if ! git -C "$target" rev-parse --is-inside-work-tree >/dev/null 2>&1; then
  echo "[pull-branch] ERROR: $target is not a git repository." >&2
  exit 1
fi
tmp="$(mktemp /tmp/box-pull-XXXXXX.bundle)"
trap 'rm -f "$tmp"' EXIT
git -C "$target" bundle create "$tmp" "$ref" >/dev/null
cat "$tmp"
'@
        $lfScript = ($remoteScript -replace "`r`n", "`n").TrimEnd("`n") + "`n"
        $escapedScript = '"' + ($lfScript -replace '"', '\"') + '"'

        $psi = New-Object System.Diagnostics.ProcessStartInfo
        $psi.FileName = 'wsl.exe'
        $psi.Arguments = "-d $distro -u $agent -- bash -c $escapedScript _ `"$rel`" `"$safeBranch`""
        $psi.UseShellExecute = $false
        $psi.RedirectStandardOutput = $true
        $psi.RedirectStandardError = $true

        $proc = [System.Diagnostics.Process]::Start($psi)
        try {
            $stderrTask = $proc.StandardError.ReadToEndAsync()
            $outFs = [System.IO.File]::Create($tmpBundle)
            try {
                $proc.StandardOutput.BaseStream.CopyTo($outFs)
            } finally {
                $outFs.Dispose()
            }
            $proc.WaitForExit()
            $stderr = $stderrTask.GetAwaiter().GetResult()
            if ($proc.ExitCode -ne 0 -or -not (Test-Path -LiteralPath $tmpBundle) -or (Get-Item -LiteralPath $tmpBundle).Length -eq 0) {
                throw "Failed creating bundle from ~/$rel in '$distro': $stderr"
            }
        } finally {
            $proc.Dispose()
        }

        $bundleRef = ((& git bundle list-heads $tmpBundle 2>$null | Out-String).Trim() -split '\s+' | Select-Object -Skip 1 -First 1)
        if ([string]::IsNullOrWhiteSpace($bundleRef)) {
            $bundleRef = $safeBranch
        }
        & git -C $winRepo fetch --force $tmpBundle "+${bundleRef}:refs/heads/${targetBranch}"
        if ($LASTEXITCODE -ne 0) { throw "git fetch from bundle failed." }
        Write-Host "[pull-branch] Imported agent commits into local branch '$targetBranch' in '$winRepo' (review with 'git diff main..$targetBranch')."
    } finally {
        Remove-Item -LiteralPath $tmpBundle -Force -ErrorAction SilentlyContinue
    }
}

function Invoke-Destroy {
    param(
        $Config,
        [switch]$Force
    )
    $distro = $Config.distroName
    $installDir = Expand-BoxPath -RawPath $Config.installDir -BaseDir $StateRoot

    if (-not $Force) {
        $answer = Read-Host "Unregister WSL distro '$distro' and delete '$installDir'? Type YES to confirm"
        if ($answer -ne 'YES') {
            Write-Host "Aborted."
            return
        }
    }
    if (Test-WslDistroExists -DistroName $distro) {
        $agentUid = [int]$Config.agentUser.uid
        $cleanupScript = @"
nft delete table inet "wsl_agent_sandbox_${agentUid}" 2>/dev/null || true
for _ in 1 2 3 4; do
  ip -4 rule del pref 0 to 127.0.0.0/8 uidrange "${agentUid}-${agentUid}" lookup local 2>/dev/null || break
done
for _ in 1 2 3 4; do
  ip -6 rule del pref 0 to ::1/128 uidrange "${agentUid}-${agentUid}" lookup local 2>/dev/null || break
done
for BIND_DIR in "/run/box-root/mnt-wsl/box-binds/${distro}" "/mnt/wsl/box-binds/${distro}"; do
  if [ -d "`$BIND_DIR" ]; then
    findmnt -rn -o TARGET -R "`$BIND_DIR" 2>/dev/null | sort -r | while IFS= read -r mp; do
      umount -l "`$mp" 2>/dev/null || true
    done
    rm -rf "`$BIND_DIR" 2>/dev/null || true
  fi
done
"@
        try {
            Invoke-WslRootBash -DistroName $distro -Script $cleanupScript
        } catch {
            Write-Verbose "Best-effort shared kernel cleanup for '$distro' skipped: $($_.Exception.Message)"
        }
        Write-Host "[destroy] Unregistering '$distro'..."
        & wsl.exe --unregister $distro
    }
    if (Test-Path -LiteralPath $installDir) {
        Write-Host "[destroy] Removing '$installDir'..."
        Remove-Item -LiteralPath $installDir -Recurse -Force
    }
    Write-Host "[destroy] Done."
}

if ($Command -eq 'help') {
    Show-Usage
    exit 0
}

if ($Command -eq 'list') {
    $registered = @(Get-WslDistroList)
    $profileNames = @('') + @(Get-ManagedBoxProfileNames -RepoRoot $StateRoot -WarnOnInvalid)
    $listExplicitCfg = if ($ConfigPath -ne (Join-Path $StateRoot 'box.json')) { $ConfigPath } else { '' }
    Write-Host "=== Managed Sandbox Profiles ==="
    foreach ($pName in $profileNames) {
        $c = Resolve-BoxProfileConfig -RepoRoot $StateRoot -ProfileName $pName -ExplicitConfigPath $listExplicitCfg -LocalOverrideSearchDir $StateRoot
        $state = if ($registered -contains $c.distroName) { 'Installed' } else { 'Not Installed' }
        $label = if ($pName) { $pName } else { 'default' }
        Write-Host ("  - {0,-15} distro={1,-28} uid={2} state={3}" -f $label, $c.distroName, $c.agentUser.uid, $state)
    }
    exit 0
}

$cfg = Resolve-BoxProfileConfig -RepoRoot $StateRoot -ProfileName $ProfileName -ExplicitConfigPath $(if ($ConfigPath -ne (Join-Path $StateRoot 'box.json')) { $ConfigPath } else { '' }) -LocalOverrideSearchDir $StateRoot

switch ($Command) {
    'init' {
        Invoke-Init -Config $cfg -SaveGolden:$SaveGolden
    }
    'up' {
        if (-not (Test-WslDistroExists -DistroName $cfg.distroName)) {
            Invoke-Init -Config $cfg
        } else {
            if ($cfg.docker.enabled) {
                [void](Sync-DockerDesktopSocketBridge)
            }
            if (-not (Wait-WslSystemdReady -DistroName $cfg.distroName -TimeoutSeconds 45)) {
                throw "Distro '$($cfg.distroName)' failed to start systemd hardening."
            }
            Sync-HostIpsIfChanged -Config $cfg
            Write-Host "[up] '$($cfg.distroName)' is running and hardened."
        }
    }
    'apply' {
        Invoke-Apply -Config $cfg -RebuildProxy:$RebuildProxy
    }
    'upgrade' {
        Invoke-Upgrade -Config $cfg -Scope $Scope
    }
    'doctor' {
        Invoke-Doctor -Config $cfg
    }
    'compact' {
        Invoke-Compact -Config $cfg
    }
    'logs' {
        Invoke-AuditLogs -Config $cfg -Source $Source -Since $Since -Lines $Lines
    }
    'audit' {
        Invoke-AuditLogs -Config $cfg -Source $Source -Since $Since -Lines $Lines
    }
    'push-repo' {
        Invoke-PushRepo -Config $cfg -WindowsRepoPath $Argument -Dest $Dest -Branch $Branch -Force:$Force
    }
    'pull-diff' {
        Invoke-PullDiff -Config $cfg -RepoName $Argument
    }
    'pull-branch' {
        Invoke-PullBranch -Config $cfg -RepoName $Argument -WindowsRepoPath $RepoPath -Branch $Branch
    }
    'seed-secrets' {
        Invoke-SeedSecrets -Config $cfg -SecretsPath $SecretsPath -Service $Service -Prune:$Prune -DryRun:$DryRun -Ttl $Ttl -ProfileName $ProfileName
    }
    'clear-secrets' {
        Invoke-ClearSecrets -Config $cfg -Service $Service
    }
    'register-terminal' {
        [void](Register-WindowsTerminalProfile -Config $cfg -Unregister:$Unregister)
    }
    'shell' {
        if ($cfg.docker.enabled) {
            [void](Sync-DockerDesktopSocketBridge)
        }
        Sync-HostIpsIfChanged -Config $cfg
        & wsl.exe -d $cfg.distroName -u $cfg.agentUser.name --cd ~
    }
    'root-shell' {
        & wsl.exe -d $cfg.distroName -u root
    }
    'status' {
        Invoke-Status -Config $cfg
    }
    'verify' {
        Invoke-Verify -Config $cfg
    }
    'snapshot' {
        Invoke-Snapshot -Config $cfg -OutFile $Argument -Golden:$Golden
    }
    'restore' {
        Invoke-Restore -Config $cfg -SnapshotPath $Argument -Force:$Force
    }
    'reset' {
        $goldenPath = Get-GoldenSnapshotPath -Config $cfg
        if ((-not $Full) -and (Test-Path -LiteralPath $goldenPath -PathType Leaf)) {
            Write-Host "[reset] Fast-restoring from golden snapshot '$goldenPath' (use -Full for clean Ubuntu rebuild)..."
            Invoke-Restore -Config $cfg -SnapshotPath $goldenPath -Force:$Force
        } else {
            if (Test-WslDistroExists -DistroName $cfg.distroName) {
                Invoke-Destroy -Config $cfg -Force:$Force
                if (Test-WslDistroExists -DistroName $cfg.distroName) {
                    return
                }
            }
            Invoke-Init -Config $cfg -SaveGolden:($Full -or $SaveGolden)
        }
    }
    'destroy' {
        Invoke-Destroy -Config $cfg -Force:$Force
    }
}
