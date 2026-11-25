#Requires -Version 5.1
Set-StrictMode -Version Latest

function Get-WindowsTerminalSettingsPaths {
    if ([string]::IsNullOrWhiteSpace($env:LOCALAPPDATA)) {
        return @()
    }
    $candidates = @(
        (Join-Path $env:LOCALAPPDATA 'Packages\Microsoft.WindowsTerminal_8wekyb3d8bbwe\LocalState\settings.json'),
        (Join-Path $env:LOCALAPPDATA 'Packages\Microsoft.WindowsTerminalPreview_8wekyb3d8bbwe\LocalState\settings.json'),
        (Join-Path $env:LOCALAPPDATA 'Microsoft\Windows Terminal\settings.json')
    )
    return @($candidates | Where-Object { Test-Path -LiteralPath $_ -PathType Leaf })
}

function ConvertFrom-Jsonc {
    param([Parameter(Mandatory)][AllowEmptyString()][string]$Text)

    # Pass 1: Strip // line comments and /* ... */ block comments outside string literals
    $sb = New-Object System.Text.StringBuilder($Text.Length)
    $len = $Text.Length
    $i = 0
    $inString = $false
    $escaped = $false
    while ($i -lt $len) {
        $ch = $Text[$i]
        if ($inString) {
            [void]$sb.Append($ch)
            if ($escaped) {
                $escaped = $false
            } elseif ($ch -eq '\') {
                $escaped = $true
            } elseif ($ch -eq '"') {
                $inString = $false
            }
            $i++
            continue
        }
        if ($ch -eq '"') {
            $inString = $true
            [void]$sb.Append($ch)
            $i++
            continue
        }
        if ($ch -eq '/' -and ($i + 1) -lt $len) {
            $next = $Text[$i + 1]
            if ($next -eq '/') {
                $i += 2
                while ($i -lt $len -and $Text[$i] -ne "`n" -and $Text[$i] -ne "`r") {
                    $i++
                }
                continue
            }
            if ($next -eq '*') {
                $i += 2
                while (($i + 1) -lt $len -and -not ($Text[$i] -eq '*' -and $Text[$i + 1] -eq '/')) {
                    $i++
                }
                if (($i + 1) -lt $len) {
                    $i += 2
                } else {
                    $i = $len
                }
                continue
            }
        }
        [void]$sb.Append($ch)
        $i++
    }

    # Pass 2: Strip trailing commas before } or ] outside string literals
    $noComments = $sb.ToString()
    $out = New-Object System.Text.StringBuilder($noComments.Length)
    $nLen = $noComments.Length
    $inString = $false
    $escaped = $false
    for ($j = 0; $j -lt $nLen; $j++) {
        $c = $noComments[$j]
        if ($inString) {
            [void]$out.Append($c)
            if ($escaped) {
                $escaped = $false
            } elseif ($c -eq '\') {
                $escaped = $true
            } elseif ($c -eq '"') {
                $inString = $false
            }
            continue
        }
        if ($c -eq '"') {
            $inString = $true
            [void]$out.Append($c)
            continue
        }
        if ($c -eq ',') {
            $k = $j + 1
            while ($k -lt $nLen -and [char]::IsWhiteSpace($noComments[$k])) {
                $k++
            }
            if ($k -lt $nLen -and ($noComments[$k] -eq '}' -or $noComments[$k] -eq ']')) {
                continue
            }
        }
        [void]$out.Append($c)
    }

    return ($out.ToString() | ConvertFrom-Json)
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

function Merge-TerminalProfileEntry {
    param(
        [Parameter(Mandatory)]$Entry,
        [Parameter(Mandatory)][string]$Guid,
        [Parameter(Mandatory)][string]$Name,
        [Parameter(Mandatory)][string]$CommandLine
    )
    $Entry | Add-Member -NotePropertyName 'guid' -NotePropertyValue $Guid -Force
    $Entry | Add-Member -NotePropertyName 'name' -NotePropertyValue $Name -Force
    $Entry | Add-Member -NotePropertyName 'commandline' -NotePropertyValue $CommandLine -Force
    if (-not $Entry.PSObject.Properties['tabColor']) {
        $Entry | Add-Member -NotePropertyName 'tabColor' -NotePropertyValue '#1B4332' -Force
    }
    if (-not $Entry.PSObject.Properties['hidden']) {
        $Entry | Add-Member -NotePropertyName 'hidden' -NotePropertyValue $false -Force
    }
    return $Entry
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
        $json = ConvertFrom-Jsonc -Text $raw

        if (-not $json.PSObject.Properties['profiles'] -or $null -eq $json.profiles) {
            if ($Unregister) {
                Write-Host "[register-terminal] Profile '$profileName' ($guid) not present in '$settingsPath'."
                continue
            }
            $json | Add-Member -NotePropertyName 'profiles' -NotePropertyValue ([pscustomobject]@{ list = @() }) -Force
        }

        $isLegacyArray = ($json.profiles -is [System.Collections.IEnumerable]) -and ($json.profiles -isnot [string]) -and (-not $json.profiles.PSObject.Properties['list'])
        if ($isLegacyArray) {
            $sourceEntries = @($json.profiles)
        } else {
            if (-not $json.profiles.PSObject.Properties['list'] -or $null -eq $json.profiles.list) {
                if ($Unregister) {
                    Write-Host "[register-terminal] Profile '$profileName' ($guid) not present in '$settingsPath'."
                    continue
                }
                $json.profiles | Add-Member -NotePropertyName 'list' -NotePropertyValue @() -Force
            }
            $sourceEntries = @($json.profiles.list)
        }

        $list = New-Object System.Collections.Generic.List[object]
        $found = $false
        foreach ($entry in $sourceEntries) {
            if ($null -eq $entry) { continue }
            $entryGuid = if ($entry.PSObject.Properties['guid']) { [string]$entry.guid } else { '' }
            if ($entryGuid.Equals($guid, [System.StringComparison]::OrdinalIgnoreCase)) {
                $found = $true
                if (-not $Unregister) {
                    $list.Add((Merge-TerminalProfileEntry -Entry $entry -Guid $guid -Name $profileName -CommandLine $cmdLine))
                }
            } else {
                $list.Add($entry)
            }
        }

        if ($Unregister -and -not $found) {
            Write-Host "[register-terminal] Profile '$profileName' ($guid) not present in '$settingsPath'."
            continue
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

        $stamp = Get-Date -Format 'yyyyMMdd-HHmmss'
        $backupPath = "${settingsPath}.bak-${stamp}"
        Copy-Item -LiteralPath $settingsPath -Destination $backupPath -Force

        $outArr = @($list.ToArray())
        if ($isLegacyArray) {
            $json.profiles = $outArr
        } else {
            $json.profiles.list = $outArr
        }
        $outJson = $json | ConvertTo-Json -Depth 20
        [System.IO.File]::WriteAllText($settingsPath, $outJson + "`n", (New-Object System.Text.UTF8Encoding($false)))
        $updated.Add($settingsPath)

        if ($Unregister) {
            Write-Host "[register-terminal] Removed '$profileName' ($guid) from '$settingsPath' (backup: $backupPath)."
        } else {
            $verb = if ($found) { 'Updated' } else { 'Added' }
            Write-Host "[register-terminal] $verb '$profileName' ($guid) in '$settingsPath' (backup: $backupPath)."
        }
    }

    return $updated.ToArray()
}

function Get-IdeUserSettingsPaths {
    if ([string]::IsNullOrWhiteSpace($env:APPDATA)) {
        return @()
    }
    $candidates = @(
        (Join-Path $env:APPDATA 'Code\User\settings.json'),
        (Join-Path $env:APPDATA 'Code - Insiders\User\settings.json'),
        (Join-Path $env:APPDATA 'Antigravity\User\settings.json')
    )
    return @($candidates | Where-Object { Test-Path -LiteralPath $_ -PathType Leaf })
}

function Test-ShouldConfigureIdeRemoteWsl {
    param($Config)
    if ($null -eq $Config) {
        return $false
    }
    if ($Config.PSObject.Properties['ide'] -and $null -ne $Config.ide -and
        $Config.ide.PSObject.Properties['configureRemoteWsl'] -and ($Config.ide.configureRemoteWsl -eq $true)) {
        return $true
    }
    if ($Config.PSObject.Properties['packages'] -and $null -ne $Config.packages -and
        $Config.packages.PSObject.Properties['configureVsCodeRemoteWsl'] -and ($Config.packages.configureVsCodeRemoteWsl -eq $true)) {
        return $true
    }
    return $false
}

function Edit-JsoncRootBooleanProperty {
    param(
        [Parameter(Mandatory)][AllowEmptyString()][string]$Text,
        [Parameter(Mandatory)][string]$PropertyName,
        [Parameter(Mandatory)][bool]$Value
    )

    $valLiteral = if ($Value) { 'true' } else { 'false' }
    if ([string]::IsNullOrWhiteSpace($Text)) {
        return "{`n  `"$PropertyName`": $valLiteral`n}`n"
    }

    $len = $Text.Length
    $i = 0
    $depth = 0
    $rootOpenIdx = -1
    $rootCloseIdx = -1
    $lastRootTokenChar = [char]0
    $lastRootTokenEndIdx = -1
    $firstPropIndent = ''

    while ($i -lt $len) {
        $ch = $Text[$i]
        if ([char]::IsWhiteSpace($ch)) {
            $i++
            continue
        }
        if ($ch -eq '/' -and ($i + 1) -lt $len) {
            $next = $Text[$i + 1]
            if ($next -eq '/') {
                $i += 2
                while ($i -lt $len -and $Text[$i] -ne "`n" -and $Text[$i] -ne "`r") {
                    $i++
                }
                continue
            }
            if ($next -eq '*') {
                $i += 2
                while (($i + 1) -lt $len -and -not ($Text[$i] -eq '*' -and $Text[$i + 1] -eq '/')) {
                    $i++
                }
                $i = if (($i + 1) -lt $len) { $i + 2 } else { $len }
                continue
            }
        }

        if ($ch -eq '"') {
            $strStart = $i
            $i++
            $escaped = $false
            while ($i -lt $len) {
                $sc = $Text[$i]
                if ($escaped) {
                    $escaped = $false
                } elseif ($sc -eq '\') {
                    $escaped = $true
                } elseif ($sc -eq '"') {
                    $i++
                    break
                }
                $i++
            }
            $strEnd = $i

            if ($depth -eq 1) {
                $k = $strEnd
                while ($k -lt $len) {
                    $kc = $Text[$k]
                    if ([char]::IsWhiteSpace($kc)) {
                        $k++
                        continue
                    }
                    if ($kc -eq '/' -and ($k + 1) -lt $len) {
                        if ($Text[$k + 1] -eq '/') {
                            $k += 2
                            while ($k -lt $len -and $Text[$k] -ne "`n" -and $Text[$k] -ne "`r") { $k++ }
                            continue
                        }
                        if ($Text[$k + 1] -eq '*') {
                            $k += 2
                            while (($k + 1) -lt $len -and -not ($Text[$k] -eq '*' -and $Text[$k + 1] -eq '/')) { $k++ }
                            $k = if (($k + 1) -lt $len) { $k + 2 } else { $len }
                            continue
                        }
                    }
                    break
                }

                if ($k -lt $len -and $Text[$k] -eq ':') {
                    if ($firstPropIndent -eq '') {
                        $lineStart = $Text.LastIndexOf("`n", [Math]::Max(0, $strStart - 1))
                        $lineStart = if ($lineStart -lt 0) { 0 } else { $lineStart + 1 }
                        $prefix = $Text.Substring($lineStart, $strStart - $lineStart)
                        if ($prefix -match '^[ \t]+$') {
                            $firstPropIndent = $prefix
                        }
                    }

                    $keyRaw = $Text.Substring($strStart, $strEnd - $strStart)
                    $keyName = $null
                    try {
                        $keyName = ($keyRaw | ConvertFrom-Json)
                    } catch {
                        $keyName = $null
                    }
                    if ($keyName -eq $PropertyName) {
                        $v = $k + 1
                        while ($v -lt $len) {
                            $vc = $Text[$v]
                            if ([char]::IsWhiteSpace($vc)) {
                                $v++
                                continue
                            }
                            if ($vc -eq '/' -and ($v + 1) -lt $len) {
                                if ($Text[$v + 1] -eq '/') {
                                    $v += 2
                                    while ($v -lt $len -and $Text[$v] -ne "`n" -and $Text[$v] -ne "`r") { $v++ }
                                    continue
                                }
                                if ($Text[$v + 1] -eq '*') {
                                    $v += 2
                                    while (($v + 1) -lt $len -and -not ($Text[$v] -eq '*' -and $Text[$v + 1] -eq '/')) { $v++ }
                                    $v = if (($v + 1) -lt $len) { $v + 2 } else { $len }
                                    continue
                                }
                            }
                            break
                        }
                        if ($v -lt $len) {
                            $valStart = $v
                            $valEnd = $v
                            $vFirst = $Text[$v]
                            if ($vFirst -eq '"') {
                                $valEnd++
                                $vEsc = $false
                                while ($valEnd -lt $len) {
                                    $vc2 = $Text[$valEnd]
                                    if ($vEsc) {
                                        $vEsc = $false
                                    } elseif ($vc2 -eq '\') {
                                        $vEsc = $true
                                    } elseif ($vc2 -eq '"') {
                                        $valEnd++
                                        break
                                    }
                                    $valEnd++
                                }
                            } elseif ($vFirst -eq '{' -or $vFirst -eq '[') {
                                $vDepth = 0
                                $vInStr = $false
                                $vEsc = $false
                                while ($valEnd -lt $len) {
                                    $vc2 = $Text[$valEnd]
                                    if ($vInStr) {
                                        if ($vEsc) { $vEsc = $false }
                                        elseif ($vc2 -eq '\') { $vEsc = $true }
                                        elseif ($vc2 -eq '"') { $vInStr = $false }
                                    } else {
                                        if ($vc2 -eq '"') { $vInStr = $true }
                                        elseif ($vc2 -eq '{' -or $vc2 -eq '[') { $vDepth++ }
                                        elseif ($vc2 -eq '}' -or $vc2 -eq ']') {
                                            $vDepth--
                                            if ($vDepth -eq 0) {
                                                $valEnd++
                                                break
                                            }
                                        }
                                    }
                                    $valEnd++
                                }
                            } else {
                                while ($valEnd -lt $len) {
                                    $vc2 = $Text[$valEnd]
                                    if ([char]::IsWhiteSpace($vc2) -or $vc2 -eq ',' -or $vc2 -eq '}' -or $vc2 -eq '/') {
                                        break
                                    }
                                    $valEnd++
                                }
                            }
                            if ($valEnd -gt $valStart) {
                                return $Text.Substring(0, $valStart) + $valLiteral + $Text.Substring($valEnd)
                            }
                        }
                    }
                }
                $lastRootTokenChar = '"'
                $lastRootTokenEndIdx = $strEnd
            }
            continue
        }

        if ($ch -eq '{' -or $ch -eq '[') {
            if ($depth -eq 0 -and $ch -eq '{' -and $rootOpenIdx -lt 0) {
                $rootOpenIdx = $i
                $lastRootTokenChar = '{'
                $lastRootTokenEndIdx = $i + 1
            }
            $depth++
            $i++
            continue
        }

        if ($ch -eq '}' -or $ch -eq ']') {
            $depth--
            if ($depth -eq 0 -and $ch -eq '}' -and $rootOpenIdx -ge 0) {
                $rootCloseIdx = $i
                break
            }
            if ($depth -eq 1) {
                $lastRootTokenChar = $ch
                $lastRootTokenEndIdx = $i + 1
            }
            $i++
            continue
        }

        if ($depth -eq 1) {
            $lastRootTokenChar = $ch
            $lastRootTokenEndIdx = $i + 1
        }
        $i++
    }

    if ($rootOpenIdx -lt 0 -or $rootCloseIdx -lt 0) {
        return $null
    }

    $nl = if ($Text.Contains("`r`n")) { "`r`n" } else { "`n" }
    $indent = if ($firstPropIndent -ne '') { $firstPropIndent } else { '  ' }
    $needsComma = ($lastRootTokenChar -ne '{' -and $lastRootTokenChar -ne ',' -and $lastRootTokenEndIdx -gt 0)

    $closeLineStart = $Text.LastIndexOf("`n", [Math]::Max(0, $rootCloseIdx - 1))
    $closeLineStart = if ($closeLineStart -lt 0) { 0 } else { $closeLineStart + 1 }
    $closeLinePrefix = $Text.Substring($closeLineStart, $rootCloseIdx - $closeLineStart)
    $closeOnOwnLine = ($closeLineStart -gt 0 -and $closeLinePrefix -match '^[ \t]*$')

    $insertPos = if ($closeOnOwnLine) { $closeLineStart } else { $rootCloseIdx }
    $entryText = if ($closeOnOwnLine) {
        "$indent`"$PropertyName`": $valLiteral$nl"
    } else {
        "$nl$indent`"$PropertyName`": $valLiteral$nl"
    }

    $sb = New-Object System.Text.StringBuilder($Text.Length + $PropertyName.Length + 32)
    if ($needsComma -and $lastRootTokenEndIdx -le $insertPos) {
        [void]$sb.Append($Text.Substring(0, $lastRootTokenEndIdx))
        [void]$sb.Append(',')
        [void]$sb.Append($Text.Substring($lastRootTokenEndIdx, $insertPos - $lastRootTokenEndIdx))
    } else {
        [void]$sb.Append($Text.Substring(0, $insertPos))
    }
    [void]$sb.Append($entryText)
    [void]$sb.Append($Text.Substring($insertPos))
    return $sb.ToString()
}

function Sync-IdeWslScriptlessStartup {
    param(
        [string[]]$SettingsPaths = @()
    )
    if ($SettingsPaths.Count -eq 0) {
        $SettingsPaths = @(Get-IdeUserSettingsPaths)
    }
    $updated = New-Object System.Collections.Generic.List[string]
    $settingKey = 'remote.WSL.experimental.scriptLessStartup'

    foreach ($settingsPath in $SettingsPaths) {
        if (-not (Test-Path -LiteralPath $settingsPath -PathType Leaf)) {
            continue
        }
        $raw = Get-Content -LiteralPath $settingsPath -Raw -Encoding UTF8
        $json = if ([string]::IsNullOrWhiteSpace($raw)) {
            [pscustomobject]@{}
        } else {
            ConvertFrom-Jsonc -Text $raw
        }
        if ($null -eq $json) {
            $json = [pscustomobject]@{}
        }
        if ($json.PSObject.Properties[$settingKey] -and ($json.$settingKey -eq $true)) {
            continue
        }

        $stamp = Get-Date -Format 'yyyyMMdd-HHmmss'
        $backupPath = "${settingsPath}.bak-${stamp}"
        Copy-Item -LiteralPath $settingsPath -Destination $backupPath -Force

        $outText = Edit-JsoncRootBooleanProperty -Text $raw -PropertyName $settingKey -Value $true
        $validSurgical = $false
        if ($null -ne $outText) {
            try {
                $reparsed = ConvertFrom-Jsonc -Text $outText
                if ($null -ne $reparsed -and $reparsed.PSObject.Properties[$settingKey] -and ($reparsed.$settingKey -eq $true)) {
                    $validSurgical = $true
                }
            } catch {
                $validSurgical = $false
            }
        }
        if (-not $validSurgical) {
            $json | Add-Member -NotePropertyName $settingKey -NotePropertyValue $true -Force
            $outText = ($json | ConvertTo-Json -Depth 20) + "`n"
        }

        [System.IO.File]::WriteAllText($settingsPath, $outText, (New-Object System.Text.UTF8Encoding($false)))
        $updated.Add($settingsPath)
        Write-Host "[ide-wsl] Enabled '$settingKey'=true in '$settingsPath' (backup: $backupPath)."
    }

    return $updated.ToArray()
}
