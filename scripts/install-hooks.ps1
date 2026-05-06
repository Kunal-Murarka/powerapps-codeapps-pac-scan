#Requires -Version 5.1
# install-hooks.ps1 — Installs the pac-scan pre-commit git hook (Windows PowerShell)
#
# Usage:
#   .\scripts\install-hooks.ps1
#
# Run from the root of the repository that contains the Power Apps Code App.
# Git for Windows uses sh.exe to execute hooks, so the hook is a POSIX shell
# script even on Windows.

param(
    [switch]$Force
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

$HookDir  = Join-Path $PWD ".git\hooks"
$HookFile = Join-Path $HookDir "pre-commit"

if (-not (Test-Path (Join-Path $PWD ".git"))) {
    Write-Error "No .git directory found. Run this script from the root of a git repository."
    exit 1
}

if ((Test-Path $HookFile) -and -not $Force) {
    Write-Host "⚠  Pre-commit hook already exists at: $HookFile" -ForegroundColor Yellow
    $confirm = Read-Host "   Overwrite? [y/N]"
    if ($confirm -notmatch '^[yY]') {
        Write-Host "   Aborted."
        exit 0
    }
}

New-Item -ItemType Directory -Force -Path $HookDir | Out-Null

# The hook content must use Unix line endings (LF only) so sh.exe can run it
$HookContent = "#!/bin/sh`necho `"🔍 pac-scan: Running Power Apps security scan...`"`n`npac-scan run --env dev --output .pac-scan/last-commit-reports`n`nEXIT_CODE=`$?`n`nif [ `$EXIT_CODE -ne 0 ]; then`n  echo `"`"`n  echo `"❌ pac-scan FAILED — commit blocked`"`n  echo `"   Fix the issues above, then commit again.`"`n  echo `"   Full report: .pac-scan/last-commit-reports/`"`n  echo `"`"`n  exit 1`nfi`n`necho `"✅ pac-scan PASSED — proceeding with commit`"`nexit 0`n"

# Write with LF line endings — critical for sh.exe compatibility on Windows
$Utf8NoBom = New-Object System.Text.UTF8Encoding $false
[System.IO.File]::WriteAllText($HookFile, $HookContent.Replace("`r`n", "`n"), $Utf8NoBom)

Write-Host "✅ pac-scan pre-commit hook installed at: $HookFile" -ForegroundColor Green
Write-Host ""
Write-Host "   The hook runs: pac-scan run --env dev"
Write-Host "   To skip (emergency only): git commit --no-verify"
Write-Host ""
Write-Host "   NOTE: Git for Windows uses sh.exe — the hook is a POSIX shell script." -ForegroundColor DarkGray
