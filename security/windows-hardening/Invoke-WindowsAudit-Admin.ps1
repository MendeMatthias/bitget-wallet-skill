<#
    Invoke-WindowsAudit-Admin.ps1 — the checks that genuinely require elevation.

    Deliberately short so you can read every line before granting admin.

    READ-ONLY: every command below is a status query. There is no Set-*, New-*,
    Remove-*, Enable-*, Disable-*, Start-*, Stop-*, reg add or netsh set.

    ONE DISCLOSED WRITE: the last block writes the transcript file into your own
    user profile. Nothing else is written anywhere.

    SECRET SAFETY: prints no key material. BitLocker recovery passwords are
    explicitly filtered out — only protector TYPE and escrow status are shown.
    The SAM/SECURITY hives are never read. LSASS is never touched.

    USAGE (from an elevated PowerShell):
        powershell -ExecutionPolicy Bypass -File .\Invoke-WindowsAudit-Admin.ps1
#>

[CmdletBinding()]
param()

$ErrorActionPreference = 'Continue'
$ProgressPreference    = 'SilentlyContinue'

$isAdmin = ([Security.Principal.WindowsPrincipal] `
    [Security.Principal.WindowsIdentity]::GetCurrent()
    ).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)

if (-not $isAdmin) {
    Write-Host 'ERROR: this half must run elevated.' -ForegroundColor Red
    Write-Host 'Right-click PowerShell > Run as administrator, then re-run.'
    exit 1
}

$ts      = Get-Date -Format 'yyyyMMdd-HHmmss'
$OutFile = Join-Path $env:USERPROFILE "windows-audit-admin-$env:COMPUTERNAME-$ts.txt"
$script:Buffer = New-Object System.Collections.Generic.List[string]

function Write-Out {
    param([string]$Text = '')
    $script:Buffer.Add($Text) | Out-Null
    Write-Host $Text
}

function Invoke-Check {
    param([string]$Label, [string]$Command)
    Write-Out ''
    Write-Out "### $Label"
    Write-Out "PS> $Command"
    try {
        $raw = Invoke-Expression $Command 2>&1 | Out-String
        if ([string]::IsNullOrWhiteSpace($raw)) { Write-Out '  (no output)' }
        else { foreach ($line in ($raw.TrimEnd() -split "`r?`n")) { Write-Out "  $line" } }
    } catch {
        Write-Out "  [ERROR] $($_.Exception.Message)"
    }
}

function Write-Note { param([string]$Text) Write-Out ''; Write-Out "  NOTE: $Text" }

Write-Out '###############################################################'
Write-Out '#  Windows 11 audit — elevated checks (READ-ONLY)'
Write-Out "#  generated: $(Get-Date)"
Write-Out "#  host: $env:COMPUTERNAME   user: $env:USERDOMAIN\$env:USERNAME"
Write-Out '###############################################################'

Write-Out ''
Write-Out '== BITLOCKER DETAIL =='
Invoke-Check 'Full BitLocker status (recovery passwords excluded by projection)' `
    'Get-BitLockerVolume -ErrorAction SilentlyContinue | Select-Object MountPoint,VolumeType,VolumeStatus,ProtectionStatus,LockStatus,EncryptionMethod,EncryptionPercentage,MetadataVersion | Format-Table -AutoSize | Out-String'
Invoke-Check 'Protector types and IDs (NOT the recovery key itself)' `
    'Get-BitLockerVolume -ErrorAction SilentlyContinue | ForEach-Object { $mp = $_.MountPoint; $_.KeyProtector | ForEach-Object { "{0}  type={1}  id={2}" -f $mp, $_.KeyProtectorType, $_.KeyProtectorId } } | Out-String'
Write-Note 'KeyProtectorType TpmPin or TpmStartupKey is materially stronger than Tpm alone: Tpm-only unlocks the disk automatically at boot, so a stolen laptop that is merely asleep or powered off still boots to the lock screen with the volume already unlocked, exposing it to DMA and lock-screen attacks.'
Invoke-Check 'Is the recovery key escrowed to Entra ID / AD / Microsoft account?' `
    'manage-bde -protectors -get C: -Type RecoveryPassword 2>&1 | Select-String -Pattern "Backed up|Numerical Password|ID:" | Out-String'
Write-Note 'Only backup-status lines and protector IDs are selected. The numerical password itself is filtered out and does not reach the transcript.'

Write-Out ''
Write-Out '== AUDIT POLICY (can you reconstruct an incident afterwards?) =='
Invoke-Check 'Effective audit policy' `
    'auditpol /get /category:* 2>&1 | Out-String'
Invoke-Check 'Security event log size and retention' `
    'Get-WinEvent -ListLog Security,System,Application,"Windows PowerShell","Microsoft-Windows-PowerShell/Operational" -ErrorAction SilentlyContinue | Select-Object LogName,IsEnabled,LogMode,MaximumSizeInBytes,RecordCount | Format-Table -AutoSize | Out-String'
Write-Note 'A Security log capped at the 20 MB default on a busy machine holds only a few days. If an incident is discovered later than that, the evidence is already gone.'

Write-Out ''
Write-Out '== CREDENTIAL EXPOSURE =='
Invoke-Check 'WDigest cleartext credential caching (must be 0 or absent)' `
    '"UseLogonCredential: " + (Get-ItemProperty "HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\WDigest" -ErrorAction SilentlyContinue).UseLogonCredential'
Write-Note 'UseLogonCredential set to 1 makes Windows keep your password in LSASS in CLEARTEXT. Combined with LSA Protection being off, an admin-level process recovers your actual password, not just a hash.'
Invoke-Check 'Cached domain logon count' `
    '"CachedLogonsCount: " + (Get-ItemProperty "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon" -ErrorAction SilentlyContinue).CachedLogonsCount'
Invoke-Check 'LAPS (local admin password rotation) present?' `
    'Get-ItemProperty "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\LAPS\Config" -ErrorAction SilentlyContinue | Select-Object * -ExcludeProperty PS* | Format-List | Out-String'
Invoke-Check 'AlwaysInstallElevated (a standard-user-to-SYSTEM privilege escalation)' `
    '"HKLM: " + (Get-ItemProperty "HKLM:\SOFTWARE\Policies\Microsoft\Windows\Installer" -ErrorAction SilentlyContinue).AlwaysInstallElevated; "HKCU: " + (Get-ItemProperty "HKCU:\SOFTWARE\Policies\Microsoft\Windows\Installer" -ErrorAction SilentlyContinue).AlwaysInstallElevated'
Write-Note 'If both are 1, any standard user installs an MSI as SYSTEM. That is a complete local privilege escalation in one step, and it is a documented Microsoft anti-pattern.'

Write-Out ''
Write-Out '== ADVANCED PERSISTENCE =='
Invoke-Check 'WMI permanent event subscriptions (fileless persistence)' `
    '"--- __EventFilter ---"; Get-CimInstance -Namespace root\subscription -ClassName __EventFilter -ErrorAction SilentlyContinue | Select-Object Name,Query | Format-List | Out-String; "--- CommandLineEventConsumer ---"; Get-CimInstance -Namespace root\subscription -ClassName CommandLineEventConsumer -ErrorAction SilentlyContinue | Select-Object Name,CommandLineTemplate | Format-List | Out-String; "--- ActiveScriptEventConsumer ---"; Get-CimInstance -Namespace root\subscription -ClassName ActiveScriptEventConsumer -ErrorAction SilentlyContinue | Select-Object Name,ScriptText | Format-List | Out-String; "--- Bindings ---"; Get-CimInstance -Namespace root\subscription -ClassName __FilterToConsumerBinding -ErrorAction SilentlyContinue | Select-Object Filter,Consumer | Format-List | Out-String'
Write-Note 'On a clean consumer Windows 11 machine these are usually empty or contain only Microsoft/BVTFilter entries. A CommandLineEventConsumer running PowerShell is high-confidence malware — it survives reboots, leaves no file on disk and is invisible to Task Manager and the Startup tab.'
Invoke-Check 'LSA security and notification packages' `
    'Get-ItemProperty "HKLM:\SYSTEM\CurrentControlSet\Control\Lsa" -ErrorAction SilentlyContinue | Select-Object "Security Packages","Notification Packages","Authentication Packages" | Format-List | Out-String'
Write-Note 'An unexpected DLL in Notification Packages receives every password change in cleartext. That is how password filters are abused for persistent credential capture.'
Invoke-Check 'Print monitors and LSA extension points' `
    'Get-ChildItem "HKLM:\SYSTEM\CurrentControlSet\Control\Print\Monitors" -ErrorAction SilentlyContinue | ForEach-Object { $d = (Get-ItemProperty $_.PSPath -ErrorAction SilentlyContinue).Driver; "{0} -> {1}" -f $_.PSChildName, $d }'
Invoke-Check 'Services whose binaries live in user-writable locations' `
    'Get-CimInstance Win32_Service -ErrorAction SilentlyContinue | Where-Object { $_.PathName -match "AppData|\\Users\\|\\Temp\\|\\ProgramData\\" } | Select-Object Name,State,StartMode,StartName,PathName | Format-List | Out-String'

Write-Out ''
Write-Out '== FIREWALL AND REMOTE ACCESS, AUTHORITATIVE =='
Invoke-Check 'Remote Desktop effective state' `
    '"fDenyTSConnections: " + (Get-ItemProperty "HKLM:\System\CurrentControlSet\Control\Terminal Server").fDenyTSConnections; Get-Service TermService | Select-Object Name,Status,StartType | Format-Table -AutoSize | Out-String'
Invoke-Check 'Inbound allow rules for RDP / SMB / WinRM specifically' `
    'Get-NetFirewallRule -Enabled True -Direction Inbound -Action Allow -ErrorAction SilentlyContinue | Where-Object { $_.DisplayName -match "Remote Desktop|File and Printer|Windows Remote Management|SSH" } | Select-Object DisplayName,Profile,Enabled | Format-Table -AutoSize | Out-String'
Invoke-Check 'All listening ports with full process attribution' `
    'Get-NetTCPConnection -State Listen -ErrorAction SilentlyContinue | Sort-Object LocalPort | Select-Object LocalAddress,LocalPort,@{n="PID";e={$_.OwningProcess}},@{n="Process";e={(Get-Process -Id $_.OwningProcess -ErrorAction SilentlyContinue).Path}} | Format-Table -AutoSize | Out-String'

Write-Out ''
Write-Out '== DEFENDER, AUTHORITATIVE =='
Invoke-Check 'Defender threat detection history' `
    'Get-MpThreatDetection -ErrorAction SilentlyContinue | Sort-Object InitialDetectionTime -Descending | Select-Object -First 20 ThreatID,InitialDetectionTime,ProcessName,DomainUser | Format-Table -AutoSize | Out-String'
Invoke-Check 'Known threats Defender has seen on this machine' `
    'Get-MpThreat -ErrorAction SilentlyContinue | Select-Object -First 20 ThreatName,SeverityID,IsActive,DidThreatExecute | Format-Table -AutoSize | Out-String'
Write-Note 'DidThreatExecute True on any entry means malware ran on this machine before it was caught. That changes the entire posture: assume credential theft occurred and rotate accordingly.'

Write-Out ''
Write-Out "=== END (elevated section) — $(Get-Date) ==="

try {
    $script:Buffer | Out-File -FilePath $OutFile -Encoding utf8
    Write-Host ''
    Write-Host ">>> Saved to: $OutFile" -ForegroundColor Green
} catch {
    Write-Host "Could not write transcript: $($_.Exception.Message)" -ForegroundColor Red
}
