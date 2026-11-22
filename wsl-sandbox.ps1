#Requires -Version 5.1
Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

& (Join-Path $PSScriptRoot 'box.ps1') @args
if (Test-Path variable:LASTEXITCODE) {
    exit $LASTEXITCODE
} else {
    exit 0
}
