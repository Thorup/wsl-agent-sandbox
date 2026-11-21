#Requires -Version 5.1
Set-StrictMode -Version Latest

function Enable-ModernTls {
    try {
        [Net.ServicePointManager]::SecurityProtocol = [Net.ServicePointManager]::SecurityProtocol -bor [Net.SecurityProtocolType]::Tls12
    } catch {}
    try {
        # TLS 1.3 enum value (12288) on newer .NET runtimes
        [Net.ServicePointManager]::SecurityProtocol = [Net.ServicePointManager]::SecurityProtocol -bor 12288
    } catch {}
}

function Invoke-HttpGetText {
    param([Parameter(Mandatory)][string]$Url)
    Enable-ModernTls
    $wc = New-Object System.Net.WebClient
    $wc.Encoding = [System.Text.Encoding]::UTF8
    $wc.Headers.Add('User-Agent', 'wsl-agent-sandbox/1.0')
    try {
        return $wc.DownloadString($Url)
    } finally {
        $wc.Dispose()
    }
}

function Get-FileSha256Hex {
    param([Parameter(Mandatory)][string]$Path)
    $sha = [System.Security.Cryptography.SHA256]::Create()
    $stream = [System.IO.File]::OpenRead($Path)
    try {
        $hashBytes = $sha.ComputeHash($stream)
        return ([BitConverter]::ToString($hashBytes) -replace '-', '').ToLowerInvariant()
    } finally {
        $stream.Dispose()
        $sha.Dispose()
    }
}

function Invoke-FileDownload {
    param(
        [Parameter(Mandatory)][string]$Url,
        [Parameter(Mandatory)][string]$DestinationPath
    )
    $curlCmd = Get-Command curl.exe -ErrorAction SilentlyContinue
    if ($curlCmd) {
        & curl.exe -fSL --retry 3 --retry-delay 2 -o $DestinationPath $Url
        if ($LASTEXITCODE -ne 0) {
            throw "curl.exe failed downloading $Url (exit code $LASTEXITCODE)"
        }
        return
    }
    Enable-ModernTls
    $wc = New-Object System.Net.WebClient
    $wc.Headers.Add('User-Agent', 'wsl-agent-sandbox/1.0')
    try {
        $wc.DownloadFile($Url, $DestinationPath)
    } finally {
        $wc.Dispose()
    }
}

function Resolve-UbuntuWslImage {
    param(
        [Parameter(Mandatory)]$Config,
        [Parameter(Mandatory)][string]$RepoRoot
    )

    $cacheDir = Expand-BoxPath -RawPath $Config.image.cacheDir -BaseDir $RepoRoot
    if (-not (Test-Path -LiteralPath $cacheDir)) {
        New-Item -ItemType Directory -Path $cacheDir -Force | Out-Null
    }

    $release = $Config.image.release
    $arch = $Config.image.arch
    $downloadUrl = $Config.image.url
    $expectedSha = $Config.image.sha256

    if ([string]::IsNullOrWhiteSpace($downloadUrl)) {
        Write-Host "[image] Discovering official Ubuntu $release LTS ($arch) WSL image..."
        $errors = New-Object System.Collections.Generic.List[string]
        $found = $false

        # 1. Try Canonical SHA256SUMS first (gets newest point release e.g. 26.04.1)
        $baseUrls = @(
            "https://releases.ubuntu.com/$release/",
            "https://cdimages.ubuntu.com/releases/$release/release/",
            "https://cdimage.ubuntu.com/releases/$release/release/"
        )
        $pattern = "^([0-9a-fA-F]{64})\s+\*?(ubuntu-$([regex]::Escape($release))[0-9.]*-wsl-$([regex]::Escape($arch))\.(?:wsl|rootfs\.tar\.gz))$"

        foreach ($base in $baseUrls) {
            try {
                $sumsUrl = "${base}SHA256SUMS"
                $sumsText = Invoke-HttpGetText -Url $sumsUrl
                $lines = $sumsText -split "`r?`n"
                foreach ($line in $lines) {
                    if ($line.Trim() -match $pattern) {
                        $expectedSha = $Matches[1].ToLowerInvariant()
                        $fileName = $Matches[2]
                        $downloadUrl = "${base}${fileName}"
                        $found = $true
                        Write-Host "[image] Discovered via Canonical SHA256SUMS: $downloadUrl"
                        break
                    }
                }
                if ($found) { break }
                $errors.Add("${sumsUrl}: no matching ubuntu-${release}*-wsl-${arch}.wsl entry")
            } catch {
                $errors.Add("${base}SHA256SUMS: $($_.Exception.Message)")
            }
        }

        # 2. Fallback to Microsoft's official WSL DistributionInfo.json manifest
        if (-not $found) {
            $manifestUrl = "https://raw.githubusercontent.com/microsoft/WSL/master/distributions/DistributionInfo.json"
            try {
                $manifestJson = Invoke-HttpGetText -Url $manifestUrl | ConvertFrom-Json
                $targetName = "Ubuntu-$release"
                foreach ($entry in @($manifestJson.ModernDistributions.Ubuntu)) {
                    if ($entry.Name -eq $targetName) {
                        $urlObj = if ($arch -eq 'arm64') { $entry.Arm64Url } else { $entry.Amd64Url }
                        if ($urlObj -and $urlObj.Url) {
                            $downloadUrl = $urlObj.Url
                            if ($urlObj.Sha256) {
                                $expectedSha = $urlObj.Sha256.ToLowerInvariant()
                            }
                            $found = $true
                            Write-Host "[image] Discovered via Microsoft WSL manifest: $downloadUrl"
                            break
                        }
                    }
                }
            } catch {
                $errors.Add("${manifestUrl}: $($_.Exception.Message)")
            }
        }

        if (-not $found) {
            $detail = ($errors -join "; ")
            throw "Could not auto-discover Ubuntu $release ($arch) WSL image ($detail). Set image.url (and optionally image.sha256) in box.json."
        }
    }

    $uri = [Uri]$downloadUrl
    $leafName = [System.IO.Path]::GetFileName($uri.AbsolutePath)
    if ([string]::IsNullOrWhiteSpace($leafName)) {
        $leafName = "ubuntu-${release}-wsl-${arch}.wsl"
    }
    $localPath = Join-Path $cacheDir $leafName

    if (Test-Path -LiteralPath $localPath -PathType Leaf) {
        if (-not [string]::IsNullOrWhiteSpace($expectedSha)) {
            $actual = Get-FileSha256Hex -Path $localPath
            if ($actual -eq $expectedSha.ToLowerInvariant()) {
                Write-Host "[image] Using verified cached image: $localPath"
                return $localPath
            }
            Write-Warning "[image] Cached file SHA256 mismatch (expected $expectedSha, got $actual). Re-downloading..."
            Remove-Item -LiteralPath $localPath -Force
        } else {
            Write-Host "[image] Using cached image (no SHA256 pinned): $localPath"
            return $localPath
        }
    }

    Write-Host "[image] Downloading $downloadUrl -> $localPath ..."
    Invoke-FileDownload -Url $downloadUrl -DestinationPath $localPath

    if (-not [string]::IsNullOrWhiteSpace($expectedSha)) {
        Write-Host "[image] Verifying SHA256 checksum..."
        $actual = Get-FileSha256Hex -Path $localPath
        if ($actual -ne $expectedSha.ToLowerInvariant()) {
            Remove-Item -LiteralPath $localPath -Force -ErrorAction SilentlyContinue
            throw "SHA256 checksum mismatch for $downloadUrl! Expected: $expectedSha, Actual: $actual"
        }
        Write-Host "[image] SHA256 verified: $actual"
    }

    return $localPath
}
