#Requires -Version 5.1
Set-StrictMode -Version Latest

function Get-WslDistroList {
    $prevEnc = [Console]::OutputEncoding
    try {
        # wsl.exe emits UTF-16LE when stdout is redirected
        [Console]::OutputEncoding = [System.Text.Encoding]::Unicode
        $raw = & wsl.exe --list --quiet 2>&1
    } finally {
        [Console]::OutputEncoding = $prevEnc
    }
    $names = @()
    foreach ($line in @($raw)) {
        $clean = ("$line" -replace "`0", '').Trim()
        if (-not [string]::IsNullOrWhiteSpace($clean)) {
            $names += $clean
        }
    }
    return $names
}

function Test-WslDistroExists {
    param([Parameter(Mandatory)][string]$DistroName)
    $list = Get-WslDistroList
    return ($list -contains $DistroName)
}

function Invoke-WslRootBash {
    param(
        [Parameter(Mandatory)][string]$DistroName,
        [Parameter(Mandatory)][string]$Script,
        [switch]$PassThru
    )
    $lfScript = ($Script -replace "`r`n", "`n") -replace "`r", "`n"
    $b64 = [Convert]::ToBase64String([System.Text.Encoding]::UTF8.GetBytes($lfScript))
    $cmd = "echo '$b64' | base64 -d | bash -s"
    if ($PassThru) {
        $out = & wsl.exe -d $DistroName -u root -- sh -c $cmd
        if ($LASTEXITCODE -ne 0) {
            throw "WSL root bash command failed with exit code $LASTEXITCODE."
        }
        return $out
    } else {
        & wsl.exe -d $DistroName -u root -- sh -c $cmd
        if ($LASTEXITCODE -ne 0) {
            throw "WSL root bash command failed with exit code $LASTEXITCODE."
        }
    }
}

function Copy-BytesToWsl {
    param(
        [Parameter(Mandatory)][string]$DistroName,
        [Parameter(Mandatory)][byte[]]$Bytes,
        [Parameter(Mandatory)][string]$RemotePath,
        [string]$Mode = '0644'
    )
    $remoteDir = ($RemotePath -replace '/[^/]+$', '')
    if ([string]::IsNullOrEmpty($remoteDir)) { $remoteDir = '/' }

    $shCmd = 'set -e; mkdir -p "$1"; tmp="$2.tmp.$$"; trap ''rm -f "$tmp"'' EXIT; cat > "$tmp" && chown root:root "$tmp" && chmod "$3" "$tmp" && mv -f "$tmp" "$2"'
    $escapedShCmd = '"' + ($shCmd -replace '"', '\"') + '"'
    $escapedDir = '"' + ($remoteDir -replace '"', '\"') + '"'
    $escapedRemote = '"' + ($RemotePath -replace '"', '\"') + '"'
    $escapedMode = '"' + ($Mode -replace '"', '\"') + '"'

    $psi = New-Object System.Diagnostics.ProcessStartInfo
    $psi.FileName = 'wsl.exe'
    $psi.Arguments = "-d $DistroName -u root -- sh -c $escapedShCmd _ $escapedDir $escapedRemote $escapedMode"
    $psi.UseShellExecute = $false
    $psi.RedirectStandardInput = $true
    $psi.RedirectStandardError = $true
    $psi.RedirectStandardOutput = $true

    $proc = [System.Diagnostics.Process]::Start($psi)
    try {
        $stdoutTask = $proc.StandardOutput.ReadToEndAsync()
        $stderrTask = $proc.StandardError.ReadToEndAsync()
        if ($Bytes.Length -gt 0) {
            $proc.StandardInput.BaseStream.Write($Bytes, 0, $Bytes.Length)
            $proc.StandardInput.BaseStream.Flush()
        }
        $proc.StandardInput.Close()
        $proc.WaitForExit()
        [void]$stdoutTask.GetAwaiter().GetResult()
        $stderr = $stderrTask.GetAwaiter().GetResult()
        if ($proc.ExitCode -ne 0) {
            throw "Failed writing -> '${DistroName}:${RemotePath}' (exit $($proc.ExitCode)): $stderr"
        }
    } finally {
        $proc.Dispose()
    }
}

function Copy-FileToWsl {
    param(
        [Parameter(Mandatory)][string]$DistroName,
        [Parameter(Mandatory)][string]$LocalPath,
        [Parameter(Mandatory)][string]$RemotePath,
        [string]$Mode = '0644',
        [switch]$NormalizeLF
    )
    if (-not (Test-Path -LiteralPath $LocalPath -PathType Leaf)) {
        throw "Local file not found: $LocalPath"
    }
    if ($NormalizeLF) {
        $text = Get-Content -LiteralPath $LocalPath -Raw -Encoding UTF8
        $text = ($text -replace "`r`n", "`n") -replace "`r", "`n"
        $utf8NoBom = New-Object System.Text.UTF8Encoding($false)
        $bytes = $utf8NoBom.GetBytes($text)
    } else {
        $bytes = [System.IO.File]::ReadAllBytes($LocalPath)
    }

    Copy-BytesToWsl -DistroName $DistroName -Bytes $bytes -RemotePath $RemotePath -Mode $Mode
}

function Copy-TextToWsl {
    param(
        [Parameter(Mandatory)][string]$DistroName,
        [Parameter(Mandatory)][string]$Content,
        [Parameter(Mandatory)][string]$RemotePath,
        [string]$Mode = '0600'
    )
    $lf = ($Content -replace "`r`n", "`n") -replace "`r", "`n"
    $utf8NoBom = New-Object System.Text.UTF8Encoding($false)
    $bytes = $utf8NoBom.GetBytes($lf)

    Copy-BytesToWsl -DistroName $DistroName -Bytes $bytes -RemotePath $RemotePath -Mode $Mode
}

function Wait-WslSystemdReady {
    param(
        [Parameter(Mandatory)][string]$DistroName,
        [int]$TimeoutSeconds = 45,
        [switch]$SkipHardeningCheck
    )
    $deadline = (Get-Date).AddSeconds($TimeoutSeconds)
    while ((Get-Date) -lt $deadline) {
        $state = (& wsl.exe -d $DistroName -u root -- sh -c "systemctl is-system-running 2>/dev/null || true" | Out-String).Trim()
        if ($state -eq 'running' -or $state -eq 'degraded') {
            if ($SkipHardeningCheck) {
                return $true
            }
            $harden = (& wsl.exe -d $DistroName -u root -- sh -c "systemctl is-active box-hardening.service 2>/dev/null || true" | Out-String).Trim()
            if ($harden -eq 'active') {
                return $true
            }
        }
        Start-Sleep -Seconds 1
    }
    return $false
}

function Sync-DockerDesktopSocketBridge {
    <#
    .SYNOPSIS
        Bridges Docker Desktop's Linux Engine socket (/tmp/docker-desktop-root/run/docker.sock)
        into the root-only 0700 shared path /mnt/host/wsl/box-binds/dd-upstream.sock so
        docker-policy-proxy inside wsl-agent-sandbox can connect without enabling Docker Desktop
        WSL Integration on the agent distro.
    #>
    if (-not (Test-WslDistroExists -DistroName 'docker-desktop')) {
        return $false
    }

    # Check if Docker Desktop engine is running on Windows (named pipe exists)
    $pipes = @(Get-ChildItem '\\.\pipe\' -ErrorAction SilentlyContinue | Where-Object { $_.Name -eq 'docker_engine' })
    if ($pipes.Count -eq 0) {
        return $false
    }

    # Verify socket exists inside docker-desktop; if Docker Desktop is paused in Resource Saver
    # mode, wake the Linux engine cleanly using a zero-image write call (network create/rm).
    $hasSock = (& wsl.exe -d docker-desktop -- sh -c '[ -S /tmp/docker-desktop-root/run/docker.sock ] && echo YES || echo NO' 2>$null | Out-String).Trim()
    if ($hasSock -ne 'YES') {
        $dockerExe = Get-Command docker.exe -ErrorAction SilentlyContinue
        if ($dockerExe) {
            Write-Host "[docker-bridge] Waking Docker Desktop Linux engine from Resource Saver mode..."
            & $dockerExe.Source network create __wsl_agent_sandbox_wake 2>$null | Out-Null
            & $dockerExe.Source network rm __wsl_agent_sandbox_wake 2>$null | Out-Null
            Start-Sleep -Seconds 1
        }
        $hasSock = (& wsl.exe -d docker-desktop -- sh -c '[ -S /tmp/docker-desktop-root/run/docker.sock ] && echo YES || echo NO' 2>$null | Out-String).Trim()
        if ($hasSock -ne 'YES') {
            return $false
        }
    }

    # Always refresh the bind-mount so a Docker Desktop Resource Saver restart never leaves a stale mount
    $bindCmd = 'mkdir -p /mnt/host/wsl/box-binds && chmod 0700 /mnt/host/wsl/box-binds && umount /mnt/host/wsl/box-binds/dd-upstream.sock 2>/dev/null || true; rm -f /mnt/host/wsl/box-binds/dd-upstream.sock && touch /mnt/host/wsl/box-binds/dd-upstream.sock && chmod 0600 /mnt/host/wsl/box-binds/dd-upstream.sock && mount --bind /tmp/docker-desktop-root/run/docker.sock /mnt/host/wsl/box-binds/dd-upstream.sock'
    & wsl.exe -d docker-desktop -- sh -c $bindCmd
    return ($LASTEXITCODE -eq 0)
}

function Get-GlobalWslConfigWarnings {
    $warnings = @()
    $wslCfg = Join-Path $env:USERPROFILE '.wslconfig'
    if (Test-Path -LiteralPath $wslCfg -PathType Leaf) {
        $content = Get-Content -LiteralPath $wslCfg -Raw -ErrorAction SilentlyContinue
        if ($content -match '(?im)^\s*networkingMode\s*=\s*mirrored\b') {
            # Informational only: box-hardening.sh blocks oifname "loopback0" for agent UID in mirrored mode
            # while keeping Windows -> WSL localhost browsing and WSL-internal lo working.
        }
        if ($content -match '(?im)^\s*localhostForwarding\s*=\s*false\b') {
            $warnings += "Global '$wslCfg' sets localhostForwarding=false. Browsing WSL localhost websites from Windows requires localhostForwarding=true."
        }
    }
    return $warnings
}

function Sync-HostIpsIfChanged {
    param([Parameter(Mandatory)]$Config)
    $distro = $Config.distroName
    if (-not (Test-WslDistroExists -DistroName $distro)) {
        return
    }
    $desired = ((Get-WindowsHostIPs) -join "`n") + "`n"
    $current = (& wsl.exe -d $distro -u root -- sh -c "cat /etc/wsl-agent-sandbox/host_ips.txt 2>/dev/null || true" | Out-String)
    $currentNorm = (($current -replace "`r`n", "`n") -replace "`r", "`n").TrimEnd("`n")
    $desiredNorm = $desired.TrimEnd("`n")
    if ($currentNorm -ne $desiredNorm) {
        Write-Host "[sync] Windows host IPs changed; refreshing host_ips.txt and reloading box-hardening.sh..."
        Copy-TextToWsl -DistroName $distro -Content $desired -RemotePath '/etc/wsl-agent-sandbox/host_ips.txt' -Mode '0600'
        Invoke-WslRootBash -DistroName $distro -Script '/usr/local/sbin/box-hardening.sh && if grep -q -- "--render-env-only" /usr/local/sbin/box-apply-policy.sh 2>/dev/null; then /usr/local/sbin/box-apply-policy.sh --render-env-only; fi'
    }
}
