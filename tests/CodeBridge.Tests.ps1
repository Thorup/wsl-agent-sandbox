#Requires -Version 5.1
Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

$RepoRoot = Split-Path -Parent $PSScriptRoot
. (Join-Path $RepoRoot 'scripts\lib\Wsl.ps1')

# Load code-bridge helper functions from box.ps1 via AST without executing CLI dispatch
$boxPath = Join-Path $RepoRoot 'box.ps1'
$tokens = $null
$parseErrors = $null
$ast = [System.Management.Automation.Language.Parser]::ParseFile($boxPath, [ref]$tokens, [ref]$parseErrors)
if ($parseErrors.Count -gt 0) {
    throw "Syntax error parsing box.ps1: $($parseErrors -join '; ')"
}
$targetFuncs = @(
    'Assert-SafeBoxBranchName',
    'Resolve-WslWorkRelPath',
    'Resolve-SandboxCheckoutBranch',
    'Resolve-PullTargetBranchName'
)
$funcAsts = $ast.FindAll({
    param($node)
    $node -is [System.Management.Automation.Language.FunctionDefinitionAst] -and ($targetFuncs -contains $node.Name)
}, $true)
foreach ($fn in $funcAsts) {
    . ([scriptblock]::Create($fn.Extent.Text))
}

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
    param([string]$Name, [scriptblock]$Block, [string]$ExpectedPattern = '')
    try {
        & $Block
        Write-Host "  [FAIL] $Name (expected exception, none thrown)"
        $script:Failed++
    } catch {
        if ($ExpectedPattern -and $_.Exception.Message -notmatch $ExpectedPattern) {
            Write-Host "  [FAIL] $Name (unexpected error: $($_.Exception.Message))"
            $script:Failed++
        } else {
            Write-Host "  [PASS] $Name"
            $script:Passed++
        }
    }
}

Write-Host "=== Running CodeBridge Automated Tests ==="

# 1. Wsl.ps1 streaming helpers
Assert-True "Copy-BytesToWsl function is defined" ($null -ne (Get-Command Copy-BytesToWsl -ErrorAction SilentlyContinue))
Assert-True "Copy-FileToWsl function is defined" ($null -ne (Get-Command Copy-FileToWsl -ErrorAction SilentlyContinue))
Assert-True "Copy-TextToWsl function is defined" ($null -ne (Get-Command Copy-TextToWsl -ErrorAction SilentlyContinue))

# 2. Resolve-WslWorkRelPath
Assert-True "Resolve-WslWorkRelPath applies DefaultPrefix for bare name" ((Resolve-WslWorkRelPath -RawPath 'my-repo' -DefaultPrefix 'work') -eq 'work/my-repo')
Assert-True "Resolve-WslWorkRelPath strips ~/ and trailing slash" ((Resolve-WslWorkRelPath -RawPath '~/work/my-repo/') -eq 'work/my-repo')
Assert-True "Resolve-WslWorkRelPath normalizes backslashes" ((Resolve-WslWorkRelPath -RawPath 'work\sub\repo') -eq 'work/sub/repo')
Assert-Throws "Resolve-WslWorkRelPath rejects path traversal" { Resolve-WslWorkRelPath -RawPath '../evil' } 'safe relative path'
Assert-Throws "Resolve-WslWorkRelPath rejects absolute path" { Resolve-WslWorkRelPath -RawPath '/etc/passwd' } 'safe relative path'
Assert-Throws "Resolve-WslWorkRelPath rejects leading dash" { Resolve-WslWorkRelPath -RawPath '-rf' } 'safe relative path'

# 3. Assert-SafeBoxBranchName
Assert-True "Assert-SafeBoxBranchName accepts feat/42_fix" ((Assert-SafeBoxBranchName -Name 'feat/42_fix') -eq 'feat/42_fix')
Assert-True "Assert-SafeBoxBranchName accepts refs/heads/main" ((Assert-SafeBoxBranchName -Name 'refs/heads/main') -eq 'refs/heads/main')
Assert-Throws "Assert-SafeBoxBranchName rejects leading dash" { Assert-SafeBoxBranchName -Name '-bad' } 'Invalid git'
Assert-Throws "Assert-SafeBoxBranchName rejects .." { Assert-SafeBoxBranchName -Name 'a..b' } 'Invalid git'
Assert-Throws "Assert-SafeBoxBranchName rejects @{" { Assert-SafeBoxBranchName -Name 'HEAD@{1}' } 'Invalid git'
Assert-Throws "Assert-SafeBoxBranchName rejects .lock" { Assert-SafeBoxBranchName -Name 'feat.lock' } 'Invalid git'
Assert-Throws "Assert-SafeBoxBranchName rejects shell metacharacters" { Assert-SafeBoxBranchName -Name 'main;rm' } 'Invalid git'

# 4. Resolve-SandboxCheckoutBranch
Assert-True "Resolve-SandboxCheckoutBranch uses symbolic HEAD when on branch" ((Resolve-SandboxCheckoutBranch -SafeBranch 'HEAD' -SymbolicHead 'feat/demo') -eq 'feat/demo')
Assert-True "Resolve-SandboxCheckoutBranch falls back to sandbox-base on detached HEAD" ((Resolve-SandboxCheckoutBranch -SafeBranch 'HEAD' -SymbolicHead '') -eq 'sandbox-base')
Assert-True "Resolve-SandboxCheckoutBranch falls back to sandbox-base on HEAD^" ((Resolve-SandboxCheckoutBranch -SafeBranch 'HEAD^') -eq 'sandbox-base')
Assert-True "Resolve-SandboxCheckoutBranch falls back to sandbox-base on main~1" ((Resolve-SandboxCheckoutBranch -SafeBranch 'main~1') -eq 'sandbox-base')
Assert-True "Resolve-SandboxCheckoutBranch falls back to sandbox-base on raw commit SHA" ((Resolve-SandboxCheckoutBranch -SafeBranch 'deadbeef1234') -eq 'sandbox-base')
Assert-True "Resolve-SandboxCheckoutBranch strips refs/heads/ prefix" ((Resolve-SandboxCheckoutBranch -SafeBranch 'refs/heads/feat/42_fix') -eq 'feat/42_fix')

# 5. Resolve-PullTargetBranchName
Assert-True "Resolve-PullTargetBranchName defaults to sandbox/<name> for HEAD" ((Resolve-PullTargetBranchName -RepoLeafName 'my-repo' -SafeBranch 'HEAD') -eq 'sandbox/my-repo')
Assert-True "Resolve-PullTargetBranchName includes branch suffix when specified" ((Resolve-PullTargetBranchName -RepoLeafName 'my-repo' -SafeBranch 'feat/42_fix') -eq 'sandbox/my-repo-feat/42_fix')
Assert-True "Resolve-PullTargetBranchName strips refs/heads/ in branch suffix" ((Resolve-PullTargetBranchName -RepoLeafName 'my-repo' -SafeBranch 'refs/heads/feat/42_fix') -eq 'sandbox/my-repo-feat/42_fix')

# 6. End-to-end local git bundle + refs/sandbox/base + origin/main + worktree test
$tmpRoot = Join-Path ([System.IO.Path]::GetTempPath()) ("cb-test-" + [Guid]::NewGuid().ToString('N').Substring(0, 8))
$srcRepo = Join-Path $tmpRoot 'src-repo'
$dstRepo = Join-Path $tmpRoot 'dst-repo'
$wtRepo = Join-Path $tmpRoot 'wt-repo'
$bundlePath = Join-Path $tmpRoot 'push.bundle'

try {
    New-Item -ItemType Directory -Path $srcRepo -Force | Out-Null
    & git -C $srcRepo init -q -b main
    & git -C $srcRepo config user.name 'Test User'
    & git -C $srcRepo config user.email 'test@example.com'
    Set-Content -LiteralPath (Join-Path $srcRepo 'README.md') -Value 'init' -Encoding UTF8
    & git -C $srcRepo add README.md
    & git -C $srcRepo commit -q -m 'initial commit'
    $mainOid = (& git -C $srcRepo rev-parse HEAD).Trim()

    & git -C $srcRepo checkout -q -b feat/demo
    Set-Content -LiteralPath (Join-Path $srcRepo 'feature.txt') -Value 'demo' -Encoding UTF8
    & git -C $srcRepo add feature.txt
    & git -C $srcRepo commit -q -m 'feat commit'
    $featOid = (& git -C $srcRepo rev-parse HEAD).Trim()

    & git -C $srcRepo bundle create $bundlePath HEAD refs/heads/main 2>$null
    Assert-True "git bundle create succeeds with HEAD and refs/heads/main" ($LASTEXITCODE -eq 0 -and (Test-Path -LiteralPath $bundlePath))

    $headsText = (& git bundle list-heads $bundlePath | Out-String)
    Assert-True "Bundle contains HEAD ref" ($headsText -match [regex]::Escape("$featOid HEAD"))
    Assert-True "Bundle contains refs/heads/main ref" ($headsText -match [regex]::Escape("$mainOid refs/heads/main"))

    New-Item -ItemType Directory -Path $dstRepo -Force | Out-Null
    & git -C $dstRepo init -q
    & git -C $dstRepo config user.name 'Test User'
    & git -C $dstRepo config user.email 'test@example.com'
    & git -C $dstRepo fetch -q $bundlePath HEAD
    & git -C $dstRepo fetch -q $bundlePath refs/heads/main
    & git -C $dstRepo checkout -q -B feat/demo $featOid
    & git -C $dstRepo update-ref refs/sandbox/base $featOid
    & git -C $dstRepo update-ref refs/remotes/origin/main $mainOid

    $resolvedBase = (& git -C $dstRepo rev-parse --verify refs/sandbox/base).Trim()
    $resolvedOriginMain = (& git -C $dstRepo rev-parse --verify refs/remotes/origin/main).Trim()
    Assert-True "refs/sandbox/base points to pushed feature commit" ($resolvedBase -eq $featOid)
    Assert-True "refs/remotes/origin/main points to main commit" ($resolvedOriginMain -eq $mainOid)

    & git -C $dstRepo worktree add -q -b feat/wt $wtRepo origin/main
    Assert-True "git worktree add against origin/main succeeds" ($LASTEXITCODE -eq 0 -and (Test-Path -LiteralPath (Join-Path $wtRepo 'README.md')))

    # Simulate committed agent change on feat/demo and verify refs/sandbox/base..HEAD diff
    Set-Content -LiteralPath (Join-Path $dstRepo 'agent.txt') -Value 'agent work' -Encoding UTF8
    & git -C $dstRepo add agent.txt
    & git -C $dstRepo commit -q -m 'agent commit'
    $committedDiff = (& git -C $dstRepo diff --stat refs/sandbox/base..HEAD | Out-String)
    Assert-True "refs/sandbox/base..HEAD diff includes committed agent file" ($committedDiff -match 'agent\.txt')
} finally {
    Remove-Item -LiteralPath $tmpRoot -Recurse -Force -ErrorAction SilentlyContinue
}

Write-Host ""
Write-Host "CodeBridge Tests: $script:Passed passed, $script:Failed failed."
if ($script:Failed -gt 0) {
    exit 1
}
