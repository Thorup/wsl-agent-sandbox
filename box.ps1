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
    [ValidateSet('init', 'up', 'apply', 'seed-secrets', 'clear-secrets', 'register-terminal', 'shell', 'root-shell', 'status', 'verify', 'snapshot', 'restore', 'reset', 'destroy', 'help')]
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

    [switch]$Unregister
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

$RepoRoot = $PSScriptRoot
if ([string]::IsNullOrWhiteSpace($ConfigPath)) {
    $ConfigPath = Join-Path $RepoRoot 'box.json'
}
. (Join-Path $RepoRoot 'scripts\lib\Config.ps1')
. (Join-Path $RepoRoot 'scripts\lib\Image.ps1')
. (Join-Path $RepoRoot 'scripts\lib\Wsl.ps1')
. (Join-Path $RepoRoot 'scripts\lib\Secrets.ps1')
. (Join-Path $RepoRoot 'scripts\lib\Terminal.ps1')

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
  seed-secrets [path] Seed or rotate CLI tokens, service accounts, and Git/SSH credentials from a
                     central Windows manifest (default: %USERPROFILE%\.wsl-agent-sandbox\secrets.json)
                     independently of init/apply. Supports -SecretsPath, -Service <names>, -Prune, -DryRun.
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
    Copy-FileToWsl -DistroName $distro -LocalPath (Join-Path $RepoRoot 'scripts\linux\box-hardening.sh') -RemotePath '/usr/local/sbin/box-hardening.sh' -Mode '0755' -NormalizeLF
    Copy-FileToWsl -DistroName $distro -LocalPath (Join-Path $RepoRoot 'scripts\linux\install-tools.sh') -RemotePath '/usr/local/sbin/box-install-tools.sh' -Mode '0755' -NormalizeLF
    Copy-FileToWsl -DistroName $distro -LocalPath (Join-Path $RepoRoot 'scripts\linux\provision.sh') -RemotePath '/usr/local/sbin/box-provision.sh' -Mode '0755' -NormalizeLF
    Copy-FileToWsl -DistroName $distro -LocalPath (Join-Path $RepoRoot 'scripts\linux\apply-policy.sh') -RemotePath '/usr/local/sbin/box-apply-policy.sh' -Mode '0755' -NormalizeLF
    Copy-FileToWsl -DistroName $distro -LocalPath (Join-Path $RepoRoot 'scripts\linux\box-seed-secrets.sh') -RemotePath '/usr/local/sbin/box-seed-secrets.sh' -Mode '0755' -NormalizeLF
    Copy-FileToWsl -DistroName $distro -LocalPath (Join-Path $RepoRoot 'scripts\linux\verify-isolation.sh') -RemotePath '/usr/local/bin/box-verify-isolation.sh' -Mode '0755' -NormalizeLF
    Copy-FileToWsl -DistroName $distro -LocalPath (Join-Path $RepoRoot 'systemd\box-hardening.service') -RemotePath '/etc/systemd/system/box-hardening.service' -Mode '0644' -NormalizeLF
    Copy-FileToWsl -DistroName $distro -LocalPath (Join-Path $RepoRoot 'systemd\docker-policy-proxy.service') -RemotePath '/etc/systemd/system/docker-policy-proxy.service' -Mode '0644' -NormalizeLF

    if ($IncludeProxySource) {
        $proxyFiles = @('go.mod', 'main.go', 'policy.go', 'proxy.go', 'policy_test.go')
        foreach ($pf in $proxyFiles) {
            Copy-FileToWsl -DistroName $distro -LocalPath (Join-Path $RepoRoot "docker-policy-proxy\$pf") -RemotePath "/usr/local/src/docker-policy-proxy/$pf" -Mode '0644' -NormalizeLF
        }
    }
}

function Get-GoldenSnapshotPath {
    param([Parameter(Mandatory)]$Config)
    $cacheDir = Expand-BoxPath -RawPath $Config.image.cacheDir -BaseDir $RepoRoot
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
    $cacheDir = Expand-BoxPath -RawPath $Config.image.cacheDir -BaseDir $RepoRoot
    if ($Golden) {
        $OutFile = Get-GoldenSnapshotPath -Config $Config
    } elseif ([string]::IsNullOrWhiteSpace($OutFile)) {
        $stamp = Get-Date -Format 'yyyyMMdd-HHmmss'
        $OutFile = Join-Path $cacheDir "$($Config.distroName)-$stamp.tar"
    } else {
        $OutFile = Expand-BoxPath -RawPath $OutFile -BaseDir $RepoRoot
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
    $SnapshotPath = Expand-BoxPath -RawPath $SnapshotPath -BaseDir $RepoRoot
    if (-not (Test-Path -LiteralPath $SnapshotPath -PathType Leaf)) {
        throw "Snapshot file not found: '$SnapshotPath'"
    }
    $distro = $Config.distroName
    $installDir = Expand-BoxPath -RawPath $Config.installDir -BaseDir $RepoRoot

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
    $installDir = Expand-BoxPath -RawPath $Config.installDir -BaseDir $RepoRoot

    if (Test-WslDistroExists -DistroName $distro) {
        Write-Host "[init] Distro '$distro' already exists. Use '.\box.ps1 apply' to update policy or '.\box.ps1 reset' to rebuild."
        return
    }

    $imagePath = Resolve-UbuntuWslImage -Config $Config -RepoRoot $RepoRoot

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

    $goldenPath = Get-GoldenSnapshotPath -Config $Config
    if ($SaveGolden -or -not (Test-Path -LiteralPath $goldenPath -PathType Leaf)) {
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
        [switch]$DryRun
    )
    $distro = $Config.distroName
    if (-not (Test-WslDistroExists -DistroName $distro)) {
        throw "Distro '$distro' does not exist. Run '.\box.ps1 init' first."
    }

    $explicitPath = if (-not [string]::IsNullOrWhiteSpace($SecretsPath)) { $SecretsPath } else { $Argument }
    $manifestPath = Resolve-SecretsManifestPath -ExplicitPath $explicitPath -Config $Config -RepoRoot $RepoRoot

    $built = Build-SeedSecretsPayload -ManifestPath $manifestPath -AgentName $Config.agentUser.name -Services $Service -Prune:$Prune

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

    # Always sync the seeder script directly so seed-secrets works independently of init/apply
    Copy-FileToWsl -DistroName $distro -LocalPath (Join-Path $RepoRoot 'scripts\linux\box-seed-secrets.sh') -RemotePath '/usr/local/sbin/box-seed-secrets.sh' -Mode '0755' -NormalizeLF

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
    Copy-FileToWsl -DistroName $distro -LocalPath (Join-Path $RepoRoot 'scripts\linux\box-seed-secrets.sh') -RemotePath '/usr/local/sbin/box-seed-secrets.sh' -Mode '0755' -NormalizeLF

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
    $localOverride = Get-BoxLocalOverridePath -ConfigPath $ConfigPath
    if (-not (Test-WslDistroExists -DistroName $distro)) {
        Write-Host "Distro '$distro': NOT INSTALLED"
        if ($localOverride) {
            Write-Host "Local override: $localOverride (active)"
        }
        return
    }
    Write-Host "=== Status: $distro ==="
    if ($localOverride) {
        Write-Host "Local override: $localOverride (active)"
    }
    $statusScript = @'
echo "OS:          $(. /etc/os-release && echo "$PRETTY_NAME")"
echo "Systemd:     $(systemctl is-system-running 2>/dev/null || echo inactive)"
echo "Hardening:   $(systemctl is-active box-hardening.service 2>/dev/null || echo inactive)"
echo "DockerProxy: $(systemctl is-active docker-policy-proxy.service 2>/dev/null || echo inactive)"
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
echo "Active nftables table inet wsl_agent_sandbox:"
nft list table inet wsl_agent_sandbox 2>/dev/null || echo "  (not loaded)"
'@
    Invoke-WslRootBash -DistroName $distro -Script $statusScript
    foreach ($w in (Get-GlobalWslConfigWarnings)) {
        Write-Warning $w
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

    # Start an ephemeral TCP listener on Windows host so we can PROVE nftables blocks
    # an actually-open Windows host port (not just a closed port!).
    $winListener = $null
    $winTestPort = 0
    $winTestIp = ''
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

    # Verify WSL -> Windows 127.0.0.1 (mirrored loopback) is blocked!
    Write-Host ""
    Write-Host "[Windows <-> WSL Localhost Isolation & Web Server Tests]"
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

    # Verify Windows -> WSL localhost web browsing AND WSL-internal localhost!
    $webPort = 18765
    $token = "wsl-localhost-ok-$([Guid]::NewGuid().ToString('N').Substring(0, 8))"
    $serverProc = $null
    try {
        & wsl.exe -d $distro -u $agent -- bash -c "mkdir -p /tmp/box-web-verify && printf '%s' '$token' > /tmp/box-web-verify/token.txt"
        $serverProc = Start-Process -FilePath 'wsl.exe' -ArgumentList "-d $distro -u $agent -- python3 -m http.server $webPort --bind 0.0.0.0 --directory /tmp/box-web-verify" -PassThru -WindowStyle Hidden

        $winOk = $false
        for ($i = 0; $i -lt 15; $i++) {
            Start-Sleep -Milliseconds 300
            try {
                $resp = Invoke-WebRequest -Uri "http://127.0.0.1:$webPort/token.txt" -UseBasicParsing -TimeoutSec 2
                if ($resp.StatusCode -eq 200 -and $resp.Content.Trim() -eq $token) {
                    $winOk = $true
                    break
                }
            } catch {
                Write-Verbose "Waiting for WSL test HTTP server on port ${webPort}: $($_.Exception.Message)"
            }
        }

        if ($winOk) {
            Write-Host "  [PASS] Windows successfully browsed http://localhost:$webPort hosted by non-root agent inside WSL!"
        } else {
            Write-Host "  [FAIL] Windows could NOT reach http://localhost:$webPort hosted inside WSL!"
            $overallFailed = $true
        }

        $wslSelf = (& wsl.exe -d $distro -u $agent -- curl -fsS --max-time 3 "http://127.0.0.1:$webPort/token.txt" 2>$null | Out-String).Trim()
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

function Invoke-Destroy {
    param(
        $Config,
        [switch]$Force
    )
    $distro = $Config.distroName
    $installDir = Expand-BoxPath -RawPath $Config.installDir -BaseDir $RepoRoot

    if (-not $Force) {
        $answer = Read-Host "Unregister WSL distro '$distro' and delete '$installDir'? Type YES to confirm"
        if ($answer -ne 'YES') {
            Write-Host "Aborted."
            return
        }
    }
    if (Test-WslDistroExists -DistroName $distro) {
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

$cfg = Read-BoxConfig -ConfigPath $ConfigPath

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
            Write-Host "[up] '$($cfg.distroName)' is running and hardened."
        }
    }
    'apply' {
        Invoke-Apply -Config $cfg -RebuildProxy:$RebuildProxy
    }
    'seed-secrets' {
        Invoke-SeedSecrets -Config $cfg -SecretsPath $SecretsPath -Service $Service -Prune:$Prune -DryRun:$DryRun
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
            Invoke-Destroy -Config $cfg -Force:$Force
            Invoke-Init -Config $cfg -SaveGolden:($Full -or $SaveGolden)
        }
    }
    'destroy' {
        Invoke-Destroy -Config $cfg -Force:$Force
    }
}
