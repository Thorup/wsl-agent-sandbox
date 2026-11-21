#Requires -Version 5.1
Set-StrictMode -Version Latest

function Get-WindowsTerminalSettingsPaths {
    $candidates = @(
        (Join-Path $env:LOCALAPPDATA 'Packages\Microsoft.WindowsTerminal_8wekyb3d8bbwe\LocalState\settings.json'),
        (Join-Path $env:LOCALAPPDATA 'Packages\Microsoft.WindowsTerminalPreview_8wekyb3d8bbwe\LocalState\settings.json')
    )
    return @($candidates | Where-Object { Test-Path -LiteralPath $_ -PathType Leaf })
}

function Get-DeterministicTerminalProfileGuid {
    param([Parameter(Mandatory)][string]$DistroName)
    $sha = [System.Security.Cryptography.SHA256]::Create()
    try {
        $bytes = [System.Text.Encoding]::UTF8.GetBytes("wsl-agent-sandbox:$DistroName")
        $hash = $sha.ComputeHash($bytes)
        $hex = ([BitConverter]::ToString($hash) -replace '-', '').ToLowerInvariant().Substring(0, 32)
        return "{$($hex.Substring(0,8))-$($hex.Substring(8,4))-$($hex.Substring(12,4))-$($hex.Substring(16,4))-$($hex.Substring(20,12))}"
    } finally {
        $sha.Dispose()
    }
}

function Register-WindowsTerminalProfile {
    param(
        [Parameter(Mandatory)]$Config,
        [string[]]$SettingsPaths = @(),
        [switch]$Unregister
    )
    if ($SettingsPaths.Count -eq 0) {
        $SettingsPaths = @(Get-WindowsTerminalSettingsPaths)
    }
    if ($SettingsPaths.Count -eq 0) {
        Write-Host "[register-terminal] Windows Terminal settings.json not found; skipping."
        return @()
    }

    $distro = $Config.distroName
    $agent = $Config.agentUser.name
    $guid = Get-DeterministicTerminalProfileGuid -DistroName $distro
    $profileName = "$distro (Sandboxed)"
    $cmdLine = "wsl.exe -d $distro -u $agent --cd ~"
    $updated = New-Object System.Collections.Generic.List[string]

    foreach ($settingsPath in $SettingsPaths) {
        if (-not (Test-Path -LiteralPath $settingsPath -PathType Leaf)) {
            continue
        }
        $raw = Get-Content -LiteralPath $settingsPath -Raw -Encoding UTF8
        $json = $raw | ConvertFrom-Json

        if (-not $json.PSObject.Properties['profiles'] -or $null -eq $json.profiles) {
            if ($Unregister) { continue }
            $json | Add-Member -NotePropertyName 'profiles' -NotePropertyValue ([pscustomobject]@{ list = @() }) -Force
        }
        if (-not $json.profiles.PSObject.Properties['list'] -or $null -eq $json.profiles.list) {
            if ($Unregister) { continue }
            $json.profiles | Add-Member -NotePropertyName 'list' -NotePropertyValue @() -Force
        }

        $stamp = Get-Date -Format 'yyyyMMdd-HHmmss'
        $backupPath = "${settingsPath}.bak-${stamp}"
        Copy-Item -LiteralPath $settingsPath -Destination $backupPath -Force

        $list = New-Object System.Collections.Generic.List[object]
        $found = $false
        foreach ($entry in @($json.profiles.list)) {
            if ($null -eq $entry) { continue }
            $entryGuid = if ($entry.PSObject.Properties['guid']) { [string]$entry.guid } else { '' }
            if ($entryGuid.Equals($guid, [System.StringComparison]::OrdinalIgnoreCase)) {
                $found = $true
                if (-not $Unregister) {
                    $list.Add([ordered]@{
                        guid        = $guid
                        name        = $profileName
                        commandline = $cmdLine
                        tabColor    = '#1B4332'
                        hidden      = $false
                    })
                }
            } else {
                $list.Add($entry)
            }
        }

        if (-not $Unregister -and -not $found) {
            $list.Add([ordered]@{
                guid        = $guid
                name        = $profileName
                commandline = $cmdLine
                tabColor    = '#1B4332'
                hidden      = $false
            })
        }

        $json.profiles.list = @($list.ToArray())
        $outJson = $json | ConvertTo-Json -Depth 20
        [System.IO.File]::WriteAllText($settingsPath, $outJson + "`n", (New-Object System.Text.UTF8Encoding($false)))
        $updated.Add($settingsPath)

        if ($Unregister) {
            if ($found) {
                Write-Host "[register-terminal] Removed '$profileName' ($guid) from '$settingsPath' (backup: $backupPath)."
            } else {
                Write-Host "[register-terminal] Profile '$profileName' ($guid) not present in '$settingsPath'."
            }
        } else {
            $verb = if ($found) { 'Updated' } else { 'Added' }
            Write-Host "[register-terminal] $verb '$profileName' ($guid) in '$settingsPath' (backup: $backupPath)."
        }
    }

    return $updated.ToArray()
}
