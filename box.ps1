<#
.SYNOPSIS
    Manage the hardened Ubuntu 26.04 LTS WSL2 Agent Sandbox (wsl-agent-sandbox).

.DESCRIPTION
    Declaratively provisions, updates, verifies, snapshots, resets, and destroys
    an isolated Ubuntu 26.04 LTS WSL2 distribution controlled strictly from box.json.

.EXAMPLE
    .\box.ps1 init
    .\box.ps1 apply
    .\box.ps1 verify
    .\box.ps1 shell
#>
#Requires -Version 5.1
param(
    [Parameter(Position = 0)]
    [ValidateSet('init', 'up', 'apply', 'shell', 'root-shell', 'status', 'verify', 'snapshot', 'reset', 'destroy', 'help')]
    [string]$Command = 'help',

    [Parameter(Position = 1)]
    [string]$Argument = '',

    [string]$ConfigPath = '',

    [switch]$Force,

    [switch]$RebuildProxy
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

function Show-Usage {
    @"
wsl-agent-sandbox — Hardened Ubuntu 26.04 LTS WSL2 Sandbox CLI (box.ps1)

Usage:
  .\box.ps1 <command> [options]

Commands:
  init               Download/verify Ubuntu 26.04 LTS, import WSL distro, provision toolchain,
                     build & test Docker policy proxy, harden distro, and run verification.
  up                 Ensure the distro is running and systemd hardening services are active.
  apply              Push updated box.json (shared folders, allowed host ports, Docker policy,
                     apt packages, CLI/language toolchains) and reload hardening + proxy live
                     without rebuilding (use -RebuildProxy to rebuild docker-policy-proxy).
  shell              Open an interactive shell inside the box as the non-root agent user.
  root-shell         Open an administrative root shell (Windows host control plane only).
  status             Show distro state, systemd service health, active /shared mounts, and warnings.
  verify             Run full red-team isolation audit + Windows<->WSL localhost web test +
                     blocked Windows host port test + Docker escape tests.
  snapshot [path]    Export the distro to a .tar backup (defaults to .cache\<distro>-<timestamp>.tar).
  reset              Destroy and re-provision a clean distro from cached Ubuntu 26.04 image.
  destroy            Unregister the WSL distro and remove its VHDX directory (use -Force to skip prompt).
"@
}

function Sync-AssetsToWsl {
    param(
        [Parameter(Mandatory)]$Config,
        [switch]$IncludeProxySource
    )
    $distro = $Config.distroName

    # Push policy.json and Windows host IPs
    $policyJson = Get-Content -LiteralPath $ConfigPath -Raw -Encoding UTF8
    Copy-TextToWsl -DistroName $distro -Content $policyJson -RemotePath '/etc/wsl-agent-sandbox/policy.json' -Mode '0600'

    $hostIps = (Get-WindowsHostIPs) -join "`n"
    Copy-TextToWsl -DistroName $distro -Content ($hostIps + "`n") -RemotePath '/etc/wsl-agent-sandbox/host_ips.txt' -Mode '0600'

    # Push Linux scripts & systemd units
    Copy-FileToWsl -DistroName $distro -LocalPath (Join-Path $RepoRoot 'scripts\linux\box-hardening.sh') -RemotePath '/usr/local/sbin/box-hardening.sh' -Mode '0755' -NormalizeLF
    Copy-FileToWsl -DistroName $distro -LocalPath (Join-Path $RepoRoot 'scripts\linux\install-tools.sh') -RemotePath '/usr/local/sbin/box-install-tools.sh' -Mode '0755' -NormalizeLF
    Copy-FileToWsl -DistroName $distro -LocalPath (Join-Path $RepoRoot 'scripts\linux\provision.sh') -RemotePath '/usr/local/sbin/box-provision.sh' -Mode '0755' -NormalizeLF
    Copy-FileToWsl -DistroName $distro -LocalPath (Join-Path $RepoRoot 'scripts\linux\apply-policy.sh') -RemotePath '/usr/local/sbin/box-apply-policy.sh' -Mode '0755' -NormalizeLF
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

function Invoke-Init {
    param($Config)
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
}

function Invoke-Apply {
    param($Config)
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

function Invoke-Status {
    param($Config)
    $distro = $Config.distroName
    if (-not (Test-WslDistroExists -DistroName $distro)) {
        Write-Host "Distro '$distro': NOT INSTALLED"
        return
    }
    Write-Host "=== Status: $distro ==="
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
            try { $winListener.Stop() } catch {}
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
            try { $winLoopListener.Stop() } catch {}
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
            } catch {}
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
            try { $serverProc.Kill() } catch {}
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
    param($Config)
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
        Invoke-Init -Config $cfg
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
        Invoke-Apply -Config $cfg
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
        if (-not (Test-WslDistroExists -DistroName $cfg.distroName)) {
            throw "Distro '$($cfg.distroName)' does not exist."
        }
        $outFile = $Argument
        if ([string]::IsNullOrWhiteSpace($outFile)) {
            $cacheDir = Expand-BoxPath -RawPath $cfg.image.cacheDir -BaseDir $RepoRoot
            if (-not (Test-Path -LiteralPath $cacheDir)) { New-Item -ItemType Directory -Path $cacheDir -Force | Out-Null }
            $stamp = Get-Date -Format 'yyyyMMdd-HHmmss'
            $outFile = Join-Path $cacheDir "$($cfg.distroName)-$stamp.tar"
        }
        Write-Host "[snapshot] Exporting '$($cfg.distroName)' -> '$outFile'..."
        & wsl.exe --export $cfg.distroName $outFile
        if ($LASTEXITCODE -ne 0) { throw "wsl --export failed." }
        Write-Host "[snapshot] Saved: $outFile"
    }
    'reset' {
        Invoke-Destroy -Config $cfg
        Invoke-Init -Config $cfg
    }
    'destroy' {
        Invoke-Destroy -Config $cfg
    }
}
