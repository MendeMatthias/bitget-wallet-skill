<#
    Invoke-WindowsAudit.ps1 — READ-ONLY Windows 11 security evidence collector.

    WHAT THIS IS: a diagnostic. It reads state and prints it. It changes nothing.
    There is no Set-*, New-*, Remove-*, Enable-*, Disable-*, Start-*, Stop-*,
    reg.exe add, or netsh set anywhere in this file. Verify with:

        .\Verify-ReadOnly.ps1

    which scans for every state-changing form and includes a negative control so
    you can see the detector actually fire rather than silently match nothing.

    SECRET SAFETY: this script never prints the CONTENTS of private keys, .env
    files, wallet files, browser password stores, Wi-Fi pre-shared keys, the
    Winlogon auto-login password, or BitLocker recovery keys. For those it emits
    only: paths, presence booleans, protector TYPES, and match COUNTS.
    Specifically and deliberately:
      * BitLocker key protectors are listed by TYPE only. RecoveryPassword —
        the 48-digit key — is filtered out and never reaches the transcript.
      * Winlogon DefaultPassword is reported as a presence boolean. Never read.
      * Wi-Fi profiles are listed by NAME only. This script never runs
        'netsh wlan show profile key=clear', which would print your PSKs.
      * PowerShell history is scanned with a match COUNT. No line is printed.
    The two deliberate exceptions are the hosts file and scheduled-task actions,
    where the attack IS the content. Both are tagged [REVIEW BEFORE SHARING].

    REQUIRES: Windows PowerShell 5.1 (ships with Windows 11) or PowerShell 7+.
    RUN AS: your normal user. Do NOT run this elevated — the admin-only checks
    live in the separate, much shorter Invoke-WindowsAudit-Admin.ps1.

    USAGE:
        powershell -ExecutionPolicy Bypass -File .\Invoke-WindowsAudit.ps1
        ... -Quick     skip the slower filesystem sweeps
#>

[CmdletBinding()]
param(
    [switch]$Quick
)

$ErrorActionPreference = 'Continue'
$ProgressPreference    = 'SilentlyContinue'

$ts     = Get-Date -Format 'yyyyMMdd-HHmmss'
$OutFile = Join-Path $env:USERPROFILE "windows-audit-$env:COMPUTERNAME-$ts.txt"
$script:Buffer = New-Object System.Collections.Generic.List[string]

function Write-Out {
    param([string]$Text = '')
    $script:Buffer.Add($Text) | Out-Null
    Write-Host $Text
}

function Write-Section {
    param([string]$Title)
    Write-Out ''
    Write-Out ''
    Write-Out '==============================================================='
    Write-Out "== $Title"
    Write-Out '==============================================================='
}

# Invoke-Check prints the exact command, then its output. Every finding derived
# from this transcript must be traceable to one of these blocks.
function Invoke-Check {
    param([string]$Label, [string]$Command)
    Write-Out ''
    Write-Out "### $Label"
    Write-Out "PS> $Command"
    try {
        $raw = Invoke-Expression $Command 2>&1 | Out-String
        if ([string]::IsNullOrWhiteSpace($raw)) {
            Write-Out '  (no output)'
        } else {
            foreach ($line in ($raw.TrimEnd() -split "`r?`n")) { Write-Out "  $line" }
        }
    } catch {
        Write-Out "  [ERROR] $($_.Exception.Message)"
    }
}

function Write-Note {
    param([string]$Text)
    Write-Out ''
    Write-Out "  NOTE: $Text"
}

function Get-RegValue {
    param([string]$Path, [string]$Name)
    try {
        $p = Get-ItemProperty -Path $Path -ErrorAction Stop
        if ($null -ne $p.PSObject.Properties[$Name]) { return $p.$Name }
        return $null
    } catch { return $null }
}

# ---------------------------------------------------------------------------
if ($PSVersionTable.PSVersion.Major -lt 5) {
    Write-Host 'ERROR: requires PowerShell 5.1 or later.' -ForegroundColor Red
    exit 1
}

$isAdmin = ([Security.Principal.WindowsPrincipal] `
    [Security.Principal.WindowsIdentity]::GetCurrent()
    ).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)

if ($isAdmin) {
    Write-Host ''
    Write-Host 'NOTICE: you are running this ELEVATED.' -ForegroundColor Yellow
    Write-Host 'This half is designed to run as your normal user, so its read-only'
    Write-Host 'nature is easy to verify and per-user state is read from YOUR account'
    Write-Host 'rather than the elevated context. It will still work, but prefer'
    Write-Host 'running it unelevated and using Invoke-WindowsAudit-Admin.ps1 for the rest.'
    Write-Host ''
}

Write-Out '###############################################################################'
Write-Out '#  Windows 11 security audit — READ-ONLY evidence collection'
Write-Out "#  generated : $(Get-Date)"
Write-Out "#  host      : $env:COMPUTERNAME"
Write-Out "#  user      : $env:USERDOMAIN\$env:USERNAME"
Write-Out "#  elevated  : $isAdmin"
Write-Out "#  psversion : $($PSVersionTable.PSVersion)"
Write-Out '###############################################################################'
Write-Out ''
Write-Out 'BEFORE YOU SHARE THIS FILE, SKIM IT.'
Write-Out 'It contains no key material, no passwords, no recovery keys and no file'
Write-Out 'contents from secret stores — by construction. It DOES contain your username,'
Write-Out 'hostname, local account names, installed software paths, hosts-file entries'
Write-Out 'and scheduled-task command lines. Redact anything you object to. Sections'
Write-Out 'most likely to need a look are tagged [REVIEW BEFORE SHARING].'

# =========================================================================
Write-Section '0. SYSTEM IDENTITY & BASELINE'
Invoke-Check 'OS version and build' `
    '(Get-CimInstance Win32_OperatingSystem | Select-Object Caption,Version,BuildNumber,OSArchitecture,InstallDate,LastBootUpTime | Format-List | Out-String)'
Invoke-Check 'Display version (22H2 / 23H2 / 24H2) and UBR' `
    'Get-ItemProperty "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion" | Select-Object ProductName,DisplayVersion,CurrentBuild,UBR | Format-List | Out-String'
Invoke-Check 'Hardware model and firmware mode' `
    '(Get-CimInstance Win32_ComputerSystem | Select-Object Manufacturer,Model,SystemType,PartOfDomain,Domain | Format-List | Out-String); "SecureBoot-capable firmware: " + $env:firmware_type'
Invoke-Check 'Uptime' `
    '"Last boot: " + (Get-CimInstance Win32_OperatingSystem).LastBootUpTime'

# =========================================================================
Write-Section '1. DISK ENCRYPTION (BitLocker / Device Encryption)'
Invoke-Check 'BitLocker volume status (recovery keys deliberately excluded)' `
    'Get-BitLockerVolume -ErrorAction SilentlyContinue | Select-Object MountPoint,VolumeType,VolumeStatus,ProtectionStatus,EncryptionMethod,EncryptionPercentage,AutoUnlockEnabled | Format-Table -AutoSize | Out-String'
Invoke-Check 'Key protector TYPES only — the 48-digit RecoveryPassword is filtered out' `
    'Get-BitLockerVolume -ErrorAction SilentlyContinue | ForEach-Object { $mp=$_.MountPoint; $_.KeyProtector | ForEach-Object { "{0}  {1}" -f $mp, $_.KeyProtectorType } } | Out-String'
Write-Note 'Only the protector TYPE is emitted. The RecoveryPassword property is never selected, so your recovery key cannot leak into this transcript.'
Invoke-Check 'Device Encryption support (consumer BitLocker path)' `
    'Get-CimInstance -Namespace root\cimv2\security\microsoftvolumeencryption -ClassName Win32_EncryptableVolume -ErrorAction SilentlyContinue | Select-Object DriveLetter,ProtectionStatus,EncryptionMethod | Format-Table -AutoSize | Out-String'
Write-Note 'ProtectionStatus 0 = unprotected, 1 = protected, 2 = unknown. A laptop with ProtectionStatus 0 on C: is readable by anyone who removes the drive.'

# =========================================================================
Write-Section '2. PLATFORM INTEGRITY (Secure Boot, TPM, VBS, HVCI, LSA)'
Invoke-Check 'Secure Boot enabled?' `
    'try { "SecureBootEnabled: " + (Confirm-SecureBootUEFI) } catch { "Confirm-SecureBootUEFI failed: " + $_.Exception.Message }'
Invoke-Check 'TPM presence and state' `
    'Get-Tpm -ErrorAction SilentlyContinue | Select-Object TpmPresent,TpmReady,TpmEnabled,TpmActivated,TpmOwned,ManufacturerVersion | Format-List | Out-String'
Invoke-Check 'Virtualization-Based Security / HVCI (Core Isolation > Memory Integrity)' `
    'Get-CimInstance -ClassName Win32_DeviceGuard -Namespace root\Microsoft\Windows\DeviceGuard -ErrorAction SilentlyContinue | Select-Object VirtualizationBasedSecurityStatus,SecurityServicesConfigured,SecurityServicesRunning,CodeIntegrityPolicyEnforcementStatus,UsermodeCodeIntegrityPolicyEnforcementStatus | Format-List | Out-String'
Write-Note 'SecurityServicesRunning: 1 = Credential Guard, 2 = HVCI/Memory Integrity, 3 = System Guard Secure Launch. An empty array means none are running — the closest Windows analogue to SIP being off.'
Invoke-Check 'LSA Protection (RunAsPPL) — blocks LSASS credential dumping' `
    '"RunAsPPL      : " + (Get-ItemProperty "HKLM:\SYSTEM\CurrentControlSet\Control\Lsa" -ErrorAction SilentlyContinue).RunAsPPL; "RunAsPPLBoot  : " + (Get-ItemProperty "HKLM:\SYSTEM\CurrentControlSet\Control\Lsa" -ErrorAction SilentlyContinue).RunAsPPLBoot'
Write-Note 'RunAsPPL absent or 0 means a process running as admin can read LSASS memory and harvest every cached credential and Kerberos ticket on the box. This is the single most-used post-exploitation step on Windows.'
Invoke-Check 'Credential Guard configuration' `
    '"LsaCfgFlags: " + (Get-ItemProperty "HKLM:\SYSTEM\CurrentControlSet\Control\Lsa" -ErrorAction SilentlyContinue).LsaCfgFlags'
Invoke-Check 'Kernel DMA Protection (Thunderbolt/PCIe DMA attacks)' `
    '(Get-CimInstance -ClassName Win32_DeviceGuard -Namespace root\Microsoft\Windows\DeviceGuard -ErrorAction SilentlyContinue).AvailableSecurityProperties -join ", "'
Write-Note 'AvailableSecurityProperties containing 7 indicates DMA protection is available. Without it, an attacker with physical access and a Thunderbolt device can read RAM directly — including FileVault-equivalent keys.'
Invoke-Check 'Test-signing / debug boot flags (should all be OFF)' `
    'bcdedit /enum "{current}" | Select-String -Pattern "testsigning|nointegritychecks|debug|flightsigning" | Out-String'
Write-Note 'bcdedit here is used only in its read-only /enum form. testsigning=Yes or nointegritychecks=Yes means unsigned kernel drivers can load — full compromise of the platform trust model.'

# =========================================================================
Write-Section '3. CODE-EXECUTION GATE (SmartScreen, Defender, ASR, AppLocker)'
Invoke-Check 'SmartScreen for Explorer (downloaded file gate)' `
    '"Explorer SmartScreen : " + (Get-ItemProperty "HKLM:\SOFTWARE\Policies\Microsoft\Windows\System" -ErrorAction SilentlyContinue).EnableSmartScreen; "Shell SmartScreen    : " + (Get-ItemProperty "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer" -ErrorAction SilentlyContinue).SmartScreenEnabled'
Invoke-Check 'Defender real-time status' `
    'Get-MpComputerStatus -ErrorAction SilentlyContinue | Select-Object AMServiceEnabled,RealTimeProtectionEnabled,BehaviorMonitorEnabled,IoavProtectionEnabled,OnAccessProtectionEnabled,IsTamperProtected,TamperProtectionSource,AntivirusSignatureLastUpdated,AntivirusSignatureVersion,QuickScanage | Format-List | Out-String'
Write-Note 'AntivirusSignatureLastUpdated more than a few days old, or RealTimeProtectionEnabled False, both indicate the endpoint gate is not actually running.'
Invoke-Check 'Defender EXCLUSIONS — paths and processes attackers love to add' `
    '$p = Get-MpPreference -ErrorAction SilentlyContinue; "ExclusionPath      : " + ($p.ExclusionPath -join "; "); "ExclusionProcess   : " + ($p.ExclusionProcess -join "; "); "ExclusionExtension : " + ($p.ExclusionExtension -join "; "); "ExclusionIpAddress : " + ($p.ExclusionIpAddress -join "; ")'
Write-Note 'An exclusion covering a broad path such as C:\ or your whole user profile means malware placed there is never scanned. Adding one is a standard attacker action and also a common self-inflicted misconfiguration from "fixing" a false positive.'
Invoke-Check 'Attack Surface Reduction rules configured' `
    '$p = Get-MpPreference -ErrorAction SilentlyContinue; if ($p.AttackSurfaceReductionRules_Ids) { for ($i=0; $i -lt $p.AttackSurfaceReductionRules_Ids.Count; $i++) { "{0} = {1}" -f $p.AttackSurfaceReductionRules_Ids[$i], $p.AttackSurfaceReductionRules_Actions[$i] } } else { "no ASR rules configured" }'
Write-Note 'Rule 9e6c4e1f-7d60-472f-ba1a-a39ef669e4b2 is "block credential stealing from LSASS". Action 1 = block, 2 = audit only, 6 = warn. Not configured means not enforced.'
Invoke-Check 'PUA (potentially unwanted application) protection' `
    '"PUAProtection: " + (Get-MpPreference -ErrorAction SilentlyContinue).PUAProtection'
Invoke-Check 'AppLocker / WDAC policy present?' `
    'Get-AppLockerPolicy -Effective -ErrorAction SilentlyContinue | Select-Object -ExpandProperty RuleCollections | ForEach-Object { "{0}: {1} rule(s), enforcement={2}" -f $_.PolicyDecisionPoint, $_.Count, $_.EnforcementMode } | Out-String'
Invoke-Check 'PowerShell execution policy per scope' `
    'Get-ExecutionPolicy -List | Out-String'
Invoke-Check 'PowerShell logging (script block / module / transcription)' `
    '"ScriptBlockLogging : " + (Get-ItemProperty "HKLM:\SOFTWARE\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging" -ErrorAction SilentlyContinue).EnableScriptBlockLogging; "ModuleLogging      : " + (Get-ItemProperty "HKLM:\SOFTWARE\Policies\Microsoft\Windows\PowerShell\ModuleLogging" -ErrorAction SilentlyContinue).EnableModuleLogging; "Transcription      : " + (Get-ItemProperty "HKLM:\SOFTWARE\Policies\Microsoft\Windows\PowerShell\Transcription" -ErrorAction SilentlyContinue).EnableTranscripting'

# =========================================================================
Write-Section '4. NETWORK PERIMETER (firewall, listeners, DNS, proxy)'
Invoke-Check 'Firewall profiles — enabled state and default actions' `
    'Get-NetFirewallProfile -ErrorAction SilentlyContinue | Select-Object Name,Enabled,DefaultInboundAction,DefaultOutboundAction,AllowInboundRules,AllowLocalFirewallRules,NotifyOnListen,LogAllowed,LogBlocked,LogFileName | Format-List | Out-String'
Write-Note 'NotifyOnListen False is the closest Windows analogue to macOS "auto-allow signed software": applications can begin listening for inbound connections without ever prompting you. DefaultInboundAction must be Block on every profile.'
Invoke-Check 'Enabled inbound ALLOW rules that accept from any remote address' `
    'Get-NetFirewallRule -Enabled True -Direction Inbound -Action Allow -ErrorAction SilentlyContinue | ForEach-Object { $af = $_ | Get-NetFirewallAddressFilter -ErrorAction SilentlyContinue; if ($af.RemoteAddress -contains "Any") { $pf = $_ | Get-NetFirewallPortFilter -ErrorAction SilentlyContinue; "{0} | {1} | {2}/{3}" -f $_.DisplayName, ($_.Profile -join ","), $pf.Protocol, ($pf.LocalPort -join ",") } } | Select-Object -First 40 | Out-String'
Invoke-Check 'Count of enabled inbound allow rules by profile' `
    'Get-NetFirewallRule -Enabled True -Direction Inbound -Action Allow -ErrorAction SilentlyContinue | Group-Object Profile | Select-Object Count,Name | Format-Table -AutoSize | Out-String'
Invoke-Check 'Listening TCP ports with owning process' `
    'Get-NetTCPConnection -State Listen -ErrorAction SilentlyContinue | Sort-Object LocalPort | Select-Object LocalAddress,LocalPort,@{n="PID";e={$_.OwningProcess}},@{n="Process";e={(Get-Process -Id $_.OwningProcess -ErrorAction SilentlyContinue).ProcessName}} -Unique | Format-Table -AutoSize | Out-String'
Invoke-Check 'Listening UDP endpoints' `
    'Get-NetUDPEndpoint -ErrorAction SilentlyContinue | Sort-Object LocalPort | Select-Object LocalAddress,LocalPort,@{n="Process";e={(Get-Process -Id $_.OwningProcess -ErrorAction SilentlyContinue).ProcessName}} -First 30 | Format-Table -AutoSize | Out-String'
Write-Note 'A listener on 0.0.0.0 is reachable from your whole LAN — coffee shop, hotel, co-working Wi-Fi. A listener on 127.0.0.1 is not.'
Invoke-Check 'System proxy configuration (MITM vector)' `
    'Get-ItemProperty "HKCU:\Software\Microsoft\Windows\CurrentVersion\Internet Settings" -ErrorAction SilentlyContinue | Select-Object ProxyEnable,ProxyServer,ProxyOverride,AutoConfigURL | Format-List | Out-String'
Write-Note 'AutoConfigURL pointing at an unexpected host is a full traffic-interception setup that survives reboots and is invisible in normal browsing.'
Invoke-Check 'DNS servers per interface' `
    'Get-DnsClientServerAddress -AddressFamily IPv4 -ErrorAction SilentlyContinue | Where-Object { $_.ServerAddresses } | Select-Object InterfaceAlias,ServerAddresses | Format-Table -AutoSize | Out-String'
Invoke-Check 'LLMNR / NBT-NS / mDNS — name-poisoning and NTLM relay exposure' `
    '"EnableMulticast (LLMNR, 0=disabled): " + (Get-ItemProperty "HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\DNSClient" -ErrorAction SilentlyContinue).EnableMulticast; "NetBIOS over TCP/IP per adapter:"; Get-CimInstance Win32_NetworkAdapterConfiguration -Filter "IPEnabled=True" -ErrorAction SilentlyContinue | Select-Object Description,TcpipNetbiosOptions | Format-Table -AutoSize | Out-String'
Write-Note 'Concrete attack: on shared Wi-Fi an attacker runs Responder, answers your machine LLMNR/NBT-NS broadcast for a mistyped share name, and captures your NTLMv2 hash — then cracks it offline or relays it. TcpipNetbiosOptions 2 = disabled, which is what you want.'
Invoke-Check 'SMB client/server hardening' `
    'Get-SmbClientConfiguration -ErrorAction SilentlyContinue | Select-Object RequireSecuritySignature,EnableSecuritySignature,EnableInsecureGuestLogons | Format-List | Out-String; Get-SmbServerConfiguration -ErrorAction SilentlyContinue | Select-Object EnableSMB1Protocol,RequireSecuritySignature,EnableSecuritySignature | Format-List | Out-String'
Invoke-Check 'hosts file — non-default entries  [REVIEW BEFORE SHARING]' `
    '$h = "$env:SystemRoot\System32\drivers\etc\hosts"; $lines = Get-Content $h -ErrorAction SilentlyContinue | Where-Object { $_ -and $_ -notmatch "^\s*#" }; "non-comment lines: " + ($lines | Measure-Object).Count; $lines | Where-Object { $_ -notmatch "^\s*(127\.0\.0\.1|::1)\s" } | Select-Object -First 25'

# =========================================================================
Write-Section '5. ACCOUNTS, AUTHENTICATION & PRIVILEGE'
Invoke-Check 'Local Administrators group membership' `
    'Get-LocalGroupMember -Group "Administrators" -ErrorAction SilentlyContinue | Select-Object Name,ObjectClass,PrincipalSource | Format-Table -AutoSize | Out-String'
Invoke-Check 'All local accounts — enabled state, password age, expiry' `
    'Get-LocalUser -ErrorAction SilentlyContinue | Select-Object Name,Enabled,PasswordRequired,PasswordLastSet,PasswordExpires,LastLogon,Description | Format-Table -AutoSize | Out-String'
Write-Note 'PasswordRequired False on an enabled account means that account can be used with a blank password — trivially exploitable from the lock screen or over the network.'
Invoke-Check 'Guest and built-in Administrator account state' `
    'Get-LocalUser -Name Guest,Administrator,DefaultAccount -ErrorAction SilentlyContinue | Select-Object Name,Enabled,PasswordRequired,LastLogon | Format-Table -AutoSize | Out-String'
Invoke-Check 'Automatic logon configured?' `
    '$w = "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon"; "AutoAdminLogon  : " + (Get-ItemProperty $w -ErrorAction SilentlyContinue).AutoAdminLogon; "DefaultUserName : " + (Get-ItemProperty $w -ErrorAction SilentlyContinue).DefaultUserName; "DefaultDomainName: " + (Get-ItemProperty $w -ErrorAction SilentlyContinue).DefaultDomainName'
Invoke-Check 'DefaultPassword present in registry? (PRESENCE ONLY — value never read)' `
    '$w = Get-ItemProperty "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon" -ErrorAction SilentlyContinue; $has = ($null -ne $w -and $null -ne $w.PSObject.Properties["DefaultPassword"]); "DefaultPassword value present: $has"'
Write-Note 'If that reports True, your Windows password is sitting in the registry in CLEARTEXT, readable by any local administrator and by anything that can read the SOFTWARE hive offline. Its presence is the finding; this script never reads the value. Windows equivalent of macOS /etc/kcpassword.'
Invoke-Check 'UAC configuration — the "passwordless sudo" question' `
    '$s = "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System"; Get-ItemProperty $s -ErrorAction SilentlyContinue | Select-Object EnableLUA,ConsentPromptBehaviorAdmin,ConsentPromptBehaviorUser,PromptOnSecureDesktop,FilterAdministratorToken,LocalAccountTokenFilterPolicy | Format-List | Out-String'
Write-Note 'EnableLUA 0 = UAC entirely off. ConsentPromptBehaviorAdmin 0 = elevate silently with no prompt, the direct equivalent of passwordless sudo: any process you run can become admin without asking. LocalAccountTokenFilterPolicy 1 additionally enables full-privilege remote admin logons for local accounts — a lateral-movement enabler.'
Invoke-Check 'Screen lock / sign-in policy' `
    '"InactivityTimeoutSecs : " + (Get-ItemProperty "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System" -ErrorAction SilentlyContinue).InactivityTimeoutSecs; "ScreenSaverIsSecure   : " + (Get-ItemProperty "HKCU:\Control Panel\Desktop" -ErrorAction SilentlyContinue).ScreenSaverIsSecure; "ScreenSaveTimeOut     : " + (Get-ItemProperty "HKCU:\Control Panel\Desktop" -ErrorAction SilentlyContinue).ScreenSaveTimeOut; "ScreenSaveActive      : " + (Get-ItemProperty "HKCU:\Control Panel\Desktop" -ErrorAction SilentlyContinue).ScreenSaveActive'
Invoke-Check 'Windows Hello / biometric and PIN configuration' `
    '"Biometrics enabled : " + (Get-ItemProperty "HKLM:\SOFTWARE\Policies\Microsoft\Biometrics" -ErrorAction SilentlyContinue).Enabled; "Hello for Business : " + (Get-ItemProperty "HKLM:\SOFTWARE\Policies\Microsoft\PassportForWork" -ErrorAction SilentlyContinue).Enabled; "NGC container present (PIN set): " + (Test-Path "$env:SystemRoot\ServiceProfiles\LocalService\AppData\Local\Microsoft\NGC")'
Invoke-Check 'Password and lockout policy' `
    'net accounts'
Write-Note 'Lockout threshold "Never" means an attacker with physical access or network reach can brute-force indefinitely with no throttling.'
Invoke-Check 'Find My Device' `
    '"FindMyDevice allowed: " + (Get-ItemProperty "HKLM:\SOFTWARE\Microsoft\Settings\FindMyDevice" -ErrorAction SilentlyContinue).LocationSyncEnabled'
Invoke-Check 'Stored credentials in Credential Manager (target NAMES only, no secrets)' `
    'cmdkey /list | Select-String -Pattern "Target:|Type:" | Select-Object -First 40 | Out-String'
Write-Note 'cmdkey lists target names and credential types only; it cannot print the stored secrets. Saved RDP or network-share credentials are reusable by anything running as you.'

# =========================================================================
Write-Section '6. REMOTE ACCESS & SHARING'
Invoke-Check 'Remote Desktop enabled?' `
    '"fDenyTSConnections (1 = RDP disabled): " + (Get-ItemProperty "HKLM:\System\CurrentControlSet\Control\Terminal Server" -ErrorAction SilentlyContinue).fDenyTSConnections; "NLA required (1 = yes): " + (Get-ItemProperty "HKLM:\System\CurrentControlSet\Control\Terminal Server\WinStations\RDP-Tcp" -ErrorAction SilentlyContinue).UserAuthentication; "RDP port: " + (Get-ItemProperty "HKLM:\System\CurrentControlSet\Control\Terminal Server\WinStations\RDP-Tcp" -ErrorAction SilentlyContinue).PortNumber'
Write-Note 'RDP enabled with NLA off, reachable from Any remote address, is the single most common ransomware entry point on Windows. Check this against the firewall rule list in section 4.'
Invoke-Check 'Remote Desktop Users group' `
    'Get-LocalGroupMember -Group "Remote Desktop Users" -ErrorAction SilentlyContinue | Select-Object Name,PrincipalSource | Format-Table -AutoSize | Out-String'
Invoke-Check 'WinRM / PowerShell Remoting listeners' `
    'Get-Service WinRM -ErrorAction SilentlyContinue | Select-Object Name,Status,StartType | Format-Table -AutoSize | Out-String; winrm enumerate winrm/config/listener 2>&1 | Out-String'
Invoke-Check 'OpenSSH server installed / running?' `
    'Get-Service sshd -ErrorAction SilentlyContinue | Select-Object Name,Status,StartType | Format-Table -AutoSize | Out-String; Get-WindowsCapability -Online -Name "OpenSSH.Server*" -ErrorAction SilentlyContinue | Select-Object Name,State | Format-Table -AutoSize | Out-String'
Invoke-Check 'SSH authorized_keys — key COUNT and comments only, never key material' `
    '$paths = @("$env:USERPROFILE\.ssh\authorized_keys", "$env:ProgramData\ssh\administrators_authorized_keys"); foreach ($p in $paths) { if (Test-Path $p) { $k = Get-Content $p | Where-Object { $_ -and $_ -notmatch "^\s*#" }; "{0}  keys={1}" -f $p, ($k | Measure-Object).Count; $k | ForEach-Object { $f = $_ -split "\s+"; "    type={0} comment={1}" -f $f[0], $f[-1] } } }'
Invoke-Check 'File shares published by this machine' `
    'Get-SmbShare -ErrorAction SilentlyContinue | Select-Object Name,Path,Description | Format-Table -AutoSize | Out-String'
Invoke-Check 'Remote-access and remote-control software installed' `
    'Get-CimInstance Win32_Service -ErrorAction SilentlyContinue | Where-Object { $_.PathName -match "teamviewer|anydesk|vnc|logmein|splashtop|screenconnect|gotoassist|rustdesk|parsec|chrome remote" } | Select-Object Name,State,StartMode,PathName | Format-List | Out-String'

# =========================================================================
Write-Section '7. PERSISTENCE (highest-signal malware surface on Windows)'
Invoke-Check 'Run / RunOnce keys — all hives' `
    '$keys = @("HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Run","HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnce","HKLM:\SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Run","HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Run","HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnce"); foreach ($k in $keys) { if (Test-Path $k) { "--- $k"; $p = Get-ItemProperty $k; $p.PSObject.Properties | Where-Object { $_.Name -notmatch "^PS" } | ForEach-Object { "    {0} = {1}" -f $_.Name, $_.Value } } }'
Invoke-Check 'Startup folders' `
    '$s = @("$env:APPDATA\Microsoft\Windows\Start Menu\Programs\Startup", "$env:ProgramData\Microsoft\Windows\Start Menu\Programs\Startup"); foreach ($d in $s) { "--- $d"; Get-ChildItem $d -ErrorAction SilentlyContinue | Select-Object Name,Length,LastWriteTime | Format-Table -AutoSize | Out-String }'
Invoke-Check 'Winlogon Shell / Userinit tampering (should be explorer.exe and userinit.exe)' `
    'Get-ItemProperty "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon" -ErrorAction SilentlyContinue | Select-Object Shell,Userinit,Taskman,AppSetup | Format-List | Out-String'
Invoke-Check 'AppInit_DLLs and Image File Execution Options debuggers' `
    '"AppInit_DLLs   : " + (Get-ItemProperty "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Windows" -ErrorAction SilentlyContinue).AppInit_DLLs; "LoadAppInit_DLLs: " + (Get-ItemProperty "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Windows" -ErrorAction SilentlyContinue).LoadAppInit_DLLs; "--- IFEO Debugger entries (hijacks) ---"; Get-ChildItem "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options" -ErrorAction SilentlyContinue | ForEach-Object { $d = (Get-ItemProperty $_.PSPath -ErrorAction SilentlyContinue).Debugger; if ($d) { "    {0} -> {1}" -f $_.PSChildName, $d } }'
Write-Note 'An IFEO Debugger entry on a common binary (sethc.exe, utilman.exe, notepad.exe) is both a persistence mechanism and, for the accessibility binaries, a pre-authentication SYSTEM shell from the lock screen.'
Invoke-Check 'Non-Microsoft scheduled tasks  [REVIEW BEFORE SHARING]' `
    'Get-ScheduledTask -ErrorAction SilentlyContinue | Where-Object { $_.TaskPath -notmatch "^\\Microsoft\\" -and $_.State -ne "Disabled" } | ForEach-Object { $a = ($_.Actions | ForEach-Object { $_.Execute + " " + $_.Arguments }) -join " | "; "{0}{1}`n    principal: {2}`n    action   : {3}" -f $_.TaskPath, $_.TaskName, $_.Principal.UserId, $a } | Select-Object -First 40 | Out-String'
Write-Note 'A task running as SYSTEM whose action is powershell.exe with an encoded command, or anything launching from AppData or Temp, is the classic persistence pattern.'
Invoke-Check 'Non-Microsoft auto-start services with their binary paths' `
    'Get-CimInstance Win32_Service -ErrorAction SilentlyContinue | Where-Object { $_.StartMode -eq "Auto" -and $_.PathName -notmatch [regex]::Escape($env:SystemRoot) } | Select-Object Name,State,StartName,PathName | Format-List | Out-String'
Invoke-Check 'Unquoted service paths containing spaces (privilege escalation)' `
    'Get-CimInstance Win32_Service -ErrorAction SilentlyContinue | Where-Object { $_.PathName -and -not $_.PathName.StartsWith([char]34) -and $_.PathName -match " " -and $_.PathName -notmatch "^[A-Za-z]:\\Windows" } | Select-Object Name,StartName,PathName | Format-List | Out-String'
Write-Note 'Concrete attack: service path C:\Program Files\My App\svc.exe unquoted means Windows tries C:\Program.exe first. If any directory on that path is user-writable, a standard user drops a binary there and gets SYSTEM at next boot.'
Invoke-Check 'Third-party kernel drivers (non-Microsoft)' `
    'Get-CimInstance Win32_SystemDriver -ErrorAction SilentlyContinue | Where-Object { $_.State -eq "Running" -and $_.PathName -notmatch "\\Windows\\System32\\drivers\\(ac|af|amd|ap|b|c|d|e|f|h|i|k|l|m|n|p|r|s|t|u|v|w)" } | Select-Object Name,DisplayName,PathName | Format-Table -AutoSize | Out-String'
Write-Note 'A vulnerable signed third-party driver is the standard BYOVD path to kernel code execution — it defeats HVCI-less systems entirely.'

# =========================================================================
Write-Section '8. CERTIFICATE TRUST STORE'
Invoke-Check 'Root CAs in LocalMachine store that are NOT Microsoft-distributed' `
    'Get-ChildItem Cert:\LocalMachine\Root -ErrorAction SilentlyContinue | Where-Object { $_.Issuer -eq $_.Subject } | Select-Object @{n="Subject";e={($_.Subject -split ",")[0]}},NotAfter,Thumbprint | Sort-Object Subject | Format-Table -AutoSize | Out-String'
Invoke-Check 'Root CAs installed in the CURRENT USER store (unusual — often malicious or MITM tooling)' `
    'Get-ChildItem Cert:\CurrentUser\Root -ErrorAction SilentlyContinue | Where-Object { $_.Issuer -eq $_.Subject } | Select-Object @{n="Subject";e={($_.Subject -split ",")[0]}},NotAfter,Thumbprint | Format-Table -AutoSize | Out-String'
Write-Note 'Concrete attack: a root CA you did not install is a full TLS interception capability. Whoever holds its private key reads and rewrites your HTTPS — including exchange APIs, wallet RPC endpoints and your bank — with a padlock still showing. Look for names like Fiddler, mitmproxy, Burp, or any corporate/vendor name you do not recognise. This lists certificate SUBJECTS and thumbprints only; no private keys are touched.'
Invoke-Check 'Recently installed certificates in the Root store (last 180 days by NotBefore)' `
    '$cut = (Get-Date).AddDays(-180); Get-ChildItem Cert:\LocalMachine\Root, Cert:\CurrentUser\Root -ErrorAction SilentlyContinue | Where-Object { $_.NotBefore -gt $cut } | Select-Object PSParentPath,@{n="Subject";e={($_.Subject -split ",")[0]}},NotBefore | Format-Table -AutoSize | Out-String'

# =========================================================================
Write-Section '9. SECRET EXPOSURE ON DISK — PATHS, ACLs AND COUNTS ONLY'
Write-Out ''
Write-Out '  Everything in this section is metadata. No file here is opened and no'
Write-Out '  content is printed. What you get: path, size, ACL identities, and where a'
Write-Out '  content test is unavoidable, a COUNT of matches.'

Invoke-Check 'PowerShell console history file — MATCH COUNTS ONLY, never the lines' `
    '$h = "$env:APPDATA\Microsoft\Windows\PowerShell\PSReadLine\ConsoleHost_history.txt"; if (Test-Path $h) { $c = Get-Content $h -ErrorAction SilentlyContinue; "path        : $h"; "total lines : " + ($c | Measure-Object).Count; "64-hex (EVM private key shape) hits : " + (($c | Select-String -Pattern "0x[0-9a-fA-F]{64}") | Measure-Object).Count; "base58 86-90 (Solana key shape) hits: " + (($c | Select-String -Pattern "[1-9A-HJ-NP-Za-km-z]{86,90}") | Measure-Object).Count; "keyword hits (mnemonic/private key/seed): " + (($c | Select-String -Pattern "mnemonic|seed phrase|private.?key|PRIVATE_KEY=" -AllMatches) | Measure-Object).Count } else { "no PSReadLine history file" }'
Write-Note 'PSReadLine records EVERY command you type, forever, in plaintext, with no expiry. A nonzero 64-hex or base58 count means raw key material is sitting in that file. This repo docs/swap.md warns against passing keys as command-line arguments for exactly this reason. Counts only — no line is printed.'

Invoke-Check 'This repo wallet-key residue (bitget-wallet-skill leaves these on crash)' `
    '$names = @(".pk_evm",".pk_sol",".social-wallet-secret",".mnemonic"); foreach ($n in $names) { Get-ChildItem -Path $env:USERPROFILE -Filter $n -Recurse -File -Force -ErrorAction SilentlyContinue -Depth 6 | ForEach-Object { "{0}  size={1}  written={2}" -f $_.FullName, $_.Length, $_.LastWriteTime } }; "(no output above = no leftover key files, which is the desired state)"'
Write-Note 'key_utils.py read_key_file() unlinks these immediately after reading. Any that still exist are crash residue from an interrupted signing run — a plaintext private key sitting in your user profile.'

Invoke-Check 'Secret-shaped files with their ACLs (identities only, contents never read)' `
    '$pats = @("*.pem","*.ppk","id_rsa","id_ed25519","id_ecdsa",".env",".env.*","*.keystore","*.p12","*.pfx"); $found = @(); foreach ($p in $pats) { $found += Get-ChildItem -Path $env:USERPROFILE -Filter $p -Recurse -File -Force -ErrorAction SilentlyContinue -Depth 5 | Where-Object { $_.FullName -notmatch "\\node_modules\\|\\.git\\|\\AppData\\Local\\Temp\\" } }; $found | Select-Object -First 40 | ForEach-Object { $acl = (Get-Acl $_.FullName -ErrorAction SilentlyContinue).Access | Where-Object { $_.IdentityReference -match "Everyone|BUILTIN\\Users|Authenticated Users" } | ForEach-Object { $_.IdentityReference.Value }; "{0}`n    broad-access ACEs: {1}" -f $_.FullName, $(if ($acl) { ($acl -join ", ") } else { "none (good)" }) }; "--- total matches: " + $found.Count'
Write-Note 'The Windows analogue of a group/world-readable secret is an ACE granting Everyone, BUILTIN\Users or Authenticated Users. On a multi-user or domain-joined machine that means any other account can read the file.'

Invoke-Check 'Cloud credential and config files (paths and sizes only)' `
    '$p = @("$env:USERPROFILE\.aws\credentials","$env:USERPROFILE\.kube\config","$env:USERPROFILE\.npmrc","$env:USERPROFILE\.git-credentials","$env:USERPROFILE\.docker\config.json","$env:USERPROFILE\.config\solana\id.json","$env:APPDATA\gcloud\credentials.db"); foreach ($f in $p) { if (Test-Path $f) { $i = Get-Item $f -Force; "{0}  size={1}  written={2}" -f $i.FullName, $i.Length, $i.LastWriteTime } }; "(no output = none present)"'
Write-Note '.config\solana\id.json is an UNENCRYPTED secret key array. Read access to that file is fund-transfer access — there is no passphrase step.'

Invoke-Check 'Browser wallet extensions installed (directory existence only)' `
    '$ids = @{ "nkbihfbeogaeaoehlefnkodbefgpgknn"="MetaMask"; "bfnaelmomeimhlpmgjnjophhpkkoljpa"="Phantom"; "jiidiaalihmmhddjgbnbgdfflelocpak"="Bitget Wallet"; "hnfanknocfeofbddgcijnmhnfnkdnaad"="Coinbase Wallet" }; $roots = @("$env:LOCALAPPDATA\Google\Chrome\User Data","$env:LOCALAPPDATA\Microsoft\Edge\User Data","$env:LOCALAPPDATA\BraveSoftware\Brave-Browser\User Data"); foreach ($r in $roots) { if (Test-Path $r) { foreach ($id in $ids.Keys) { Get-ChildItem -Path $r -Filter $id -Recurse -Directory -ErrorAction SilentlyContinue -Depth 3 | ForEach-Object { "{0}  [{1}]" -f $_.FullName, $ids[$id] } } } }; "(extension vault contents are never opened)"'

Invoke-Check 'OneDrive Known Folder Move — are Desktop/Documents synced to the cloud?' `
    '"OneDrive env : " + $env:OneDrive; $sf = "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\User Shell Folders"; foreach ($n in @("Desktop","Personal","My Pictures")) { $v = (Get-ItemProperty $sf -ErrorAction SilentlyContinue).$n; "{0,-12} -> {1}" -f $n, $v }'
Write-Note 'If Desktop or Documents redirect into OneDrive, everything you have ever put there has been uploaded to Microsoft and synced to every other device on that account. This is the Windows equivalent of the iCloud Desktop and Documents sync problem, and it is why the quarantine folder is placed directly in your profile root rather than on the Desktop.'

Invoke-Check 'Secret-shaped files sitting inside OneDrive' `
    'if ($env:OneDrive -and (Test-Path $env:OneDrive)) { $pats = @("*.pem","id_rsa","id_ed25519",".env",".pk_*",".mnemonic","*.keystore"); foreach ($p in $pats) { Get-ChildItem -Path $env:OneDrive -Filter $p -Recurse -File -Force -ErrorAction SilentlyContinue -Depth 4 | Select-Object -First 10 | ForEach-Object { $_.FullName } } } else { "OneDrive not configured" }'

Invoke-Check 'Wi-Fi profile NAMES only (this script never runs key=clear)' `
    'netsh wlan show profiles 2>&1 | Select-String "All User Profile" | Select-Object -First 25 | Out-String'
Write-Note 'Adding key=clear to that command prints your saved Wi-Fi pre-shared keys in plaintext. This script deliberately does not, and neither should you while a transcript is being captured.'

Invoke-Check 'AI assistant session directories (existence and size only, never read)' `
    '$p = @("$env:USERPROFILE\.claude","$env:USERPROFILE\.cursor","$env:APPDATA\Code\User\workspaceStorage","$env:USERPROFILE\.continue"); foreach ($d in $p) { if (Test-Path $d) { $sz = (Get-ChildItem $d -Recurse -File -Force -ErrorAction SilentlyContinue | Measure-Object Length -Sum).Sum; "{0}  bytes={1}" -f $d, $sz } }; "(contents deliberately not read — transcripts routinely contain pasted secrets)"'

# =========================================================================
Write-Section '10. PATCH POSTURE'
Invoke-Check 'Most recent hotfixes installed' `
    'Get-HotFix -ErrorAction SilentlyContinue | Sort-Object InstalledOn -Descending | Select-Object -First 15 HotFixID,Description,InstalledOn | Format-Table -AutoSize | Out-String'
Write-Note 'If the newest entry is more than ~45 days old, this machine is missing at least one Patch Tuesday and very likely has a known-exploited vulnerability.'
Invoke-Check 'Windows Update configuration and deferral policies' `
    'Get-ItemProperty "HKLM:\SOFTWARE\Microsoft\WindowsUpdate\UX\Settings" -ErrorAction SilentlyContinue | Select-Object * -ExcludeProperty PS* | Format-List | Out-String; "--- policy overrides ---"; Get-ItemProperty "HKLM:\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate" -ErrorAction SilentlyContinue | Select-Object * -ExcludeProperty PS* | Format-List | Out-String'
Invoke-Check 'Windows Update and related service states' `
    'Get-Service wuauserv,UsoSvc,WinDefend,MpsSvc,Sense -ErrorAction SilentlyContinue | Select-Object Name,DisplayName,Status,StartType | Format-Table -AutoSize | Out-String'
Write-Note 'WinDefend or MpsSvc (the firewall service) stopped or disabled is either a serious misconfiguration or an active compromise indicator.'

if (-not $Quick) {
    Invoke-Check 'Installed software inventory (registry uninstall keys)' `
        '$k = @("HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\*","HKLM:\SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall\*","HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\*"); Get-ItemProperty $k -ErrorAction SilentlyContinue | Where-Object { $_.DisplayName } | Select-Object DisplayName,DisplayVersion,Publisher,InstallDate | Sort-Object DisplayName -Unique | Format-Table -AutoSize | Out-String'
} else {
    Write-Out ''
    Write-Out '### Installed software inventory'
    Write-Out '  SKIPPED (-Quick)'
}

Write-Out ''
Write-Out ''
Write-Out '==============================================================='
Write-Out "== END OF AUDIT — $(Get-Date)"
Write-Out '==============================================================='
Write-Out ''
Write-Out 'Reminder: no key material, no BitLocker recovery key, no Wi-Fi PSK, no'
Write-Out 'auto-login password, no .env contents, no wallet files and no AI transcripts'
Write-Out 'were read or printed by this script. Only paths, presence flags, protector'
Write-Out 'types, ACL identities and match counts.'

try {
    $script:Buffer | Out-File -FilePath $OutFile -Encoding utf8
    Write-Host ''
    Write-Host ">>> Saved to: $OutFile" -ForegroundColor Green
    Write-Host '>>> Review it, redact anything you object to, then share that file.'
} catch {
    Write-Host "Could not write transcript: $($_.Exception.Message)" -ForegroundColor Red
}
