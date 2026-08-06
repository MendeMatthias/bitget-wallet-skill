<#
    Verify-ReadOnly.ps1 — prove to yourself that the audit scripts only READ.

    Do not take my word for it. This scans Invoke-WindowsAudit.ps1 and
    Invoke-WindowsAudit-Admin.ps1 for every state-changing form I could think of
    and reports any hit. It also runs a negative control against a block of
    known-bad lines, so you can see the detector actually fires rather than
    silently matching nothing.

    EXPECTED RESULT:
      Invoke-WindowsAudit.ps1        -> 0 mutating hits, 1 disclosed Out-File
      Invoke-WindowsAudit-Admin.ps1  -> 0 mutating hits, 1 disclosed Out-File
      negative control               -> 8 caught

    The disclosed Out-File in each is the transcript write into your own user
    profile. That is the only thing either script creates.

    USAGE:
        powershell -ExecutionPolicy Bypass -File .\Verify-ReadOnly.ps1
#>

[CmdletBinding()]
param()

$ErrorActionPreference = 'Continue'
$here = Split-Path -Parent $MyInvocation.MyCommand.Path

# State-changing PowerShell and native command forms.
# Deliberately excludes read-only verbs (Get-, Test-, Confirm-, Select-,
# Measure-, Sort-, Where-, Format-, Import-, Out-String) and the harmless
# Set-StrictMode / Set-Location.
$mutating = @(
    'Set-(?!StrictMode|Location\b)[A-Za-z]+'
    'New-(?!Object\b|TimeSpan\b)[A-Za-z]+'
    'Remove-[A-Za-z]+'
    'Clear-[A-Za-z]+'
    'Enable-[A-Za-z]+'
    'Disable-[A-Za-z]+'
    'Stop-[A-Za-z]+'
    'Start-(?!Sleep\b)[A-Za-z]+'
    'Restart-[A-Za-z]+'
    'Suspend-[A-Za-z]+'
    'Resume-[A-Za-z]+'
    'Add-[A-Za-z]+'
    'Register-[A-Za-z]+'
    'Unregister-[A-Za-z]+'
    'Rename-[A-Za-z]+'
    'Move-Item'
    'Copy-Item'
    'Invoke-CimMethod'
    'Invoke-WmiMethod'
    '\.Delete\(\)'
    '\.Create\('
    '\breg(\.exe)?\s+(add|delete|import|copy)\b'
    '\bnetsh\b[^\r\n]*\b(set|add|delete)\b'
    '\bbcdedit\b[^\r\n]*\/(set|deletevalue|import)\b'
    '\bmanage-bde\b[^\r\n]*\s-(on|off|forcerecovery|changepin|changepassword)\b'
    '\bsc(\.exe)?\s+(config|create|delete|start|stop)\b'
    '\bauditpol\b[^\r\n]*\/set\b'
    '\bcmdkey\b[^\r\n]*\/(add|generic|delete)\b'
    '\bnet\s+(user|localgroup|accounts)\b[^\r\n]*\/'
    '\btakeown\b|\bicacls\b[^\r\n]*\/grant'
) -join '|'

function Scan-File {
    param([string]$File)

    Write-Host ''
    Write-Host "== $File ==" -ForegroundColor Cyan
    $full = Join-Path $here $File
    if (-not (Test-Path $full)) {
        Write-Host '  file not found'
        return
    }

    $lines = Get-Content $full
    $hits = @()
    $writes = @()
    for ($i = 0; $i -lt $lines.Count; $i++) {
        $line = $lines[$i]
        # skip comment lines and the block-comment header
        if ($line -match '^\s*#') { continue }
        if ($line -match $mutating) { $hits += "$($i+1): $($line.Trim())" }
        if ($line -match 'Out-File') { $writes += "$($i+1): $($line.Trim())" }
    }

    if ($hits.Count -eq 0) {
        Write-Host '  0 mutating hits — no state-changing command forms found.' -ForegroundColor Green
    } else {
        foreach ($h in $hits) { Write-Host "  HIT $h" -ForegroundColor Red }
        Write-Host "  ($($hits.Count) hit(s)) — investigate before running this script." -ForegroundColor Red
    }

    if ($writes.Count -gt 0) {
        Write-Host "  disclosed write(s) — the transcript file in your profile:" -ForegroundColor Yellow
        foreach ($w in $writes) { Write-Host "    $w" }
    }
}

Write-Host '###############################################################'
Write-Host '#  Read-only verification'
Write-Host '###############################################################'

Scan-File 'Invoke-WindowsAudit.ps1'
Scan-File 'Invoke-WindowsAudit-Admin.ps1'

Write-Host ''
Write-Host '== negative control (detector sanity check) ==' -ForegroundColor Cyan
$control = @(
    'Set-ItemProperty -Path HKLM:\SOFTWARE\... -Name EnableLUA -Value 0'
    'Remove-Item C:\Windows\System32\something.dll'
    'Set-MpPreference -DisableRealtimeMonitoring $true'
    'reg add HKLM\Software\Foo /v Bar /d 1'
    'bcdedit /set testsigning on'
    'Disable-NetFirewallRule -DisplayName "Block inbound"'
    'netsh advfirewall set allprofiles state off'
    'Stop-Service WinDefend'
)
$caught = 0
foreach ($c in $control) {
    if ($c -match $mutating) { Write-Host "  CAUGHT $c"; $caught++ }
    else { Write-Host "  MISSED $c" -ForegroundColor Red }
}
Write-Host "  $caught of $($control.Count) caught."
if ($caught -lt $control.Count) {
    Write-Host '  DETECTOR IS BROKEN — do not trust the scan above.' -ForegroundColor Red
}

Write-Host ''
Write-Host '== no-delete check on Quarantine.ps1 ==' -ForegroundColor Cyan
$q = Join-Path $here 'Quarantine.ps1'
if (Test-Path $q) {
    $qhits = Get-Content $q | Select-String -Pattern 'Remove-Item|\.Delete\(|\brmdir\b|Clear-Content' |
             Where-Object { $_.Line -notmatch '^\s*#' -and $_.Line -notmatch 'Select-String' }
    if ($qhits) {
        Write-Host '  WARNING: found a delete in Quarantine.ps1 — it is supposed to have none.' -ForegroundColor Red
        $qhits | ForEach-Object { Write-Host "    $($_.LineNumber): $($_.Line.Trim())" }
    } else {
        Write-Host '  0 hits — Quarantine.ps1 deletes nothing. It only moves.' -ForegroundColor Green
    }
} else {
    Write-Host '  Quarantine.ps1 not found'
}

Write-Host ''
Write-Host 'Done.'
