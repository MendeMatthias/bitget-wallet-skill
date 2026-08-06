# Windows 11 hardening audit toolkit

Read-only evidence collection for a security review of a Windows 11 machine, plus
a reversible quarantine helper for whatever the review turns up.

**Why this is scripts rather than a report:** the review was requested from a
Claude Code session running in an ephemeral Linux container in the cloud. That
session has no path to the Windows machine — no `/mnt/c`, no WSL interop, no
`powershell.exe`. Rather than guess at findings, the audit is packaged to run on
the actual machine and return real evidence.

## The files

| Script | Privilege | What it does |
|---|---|---|
| `Verify-ReadOnly.ps1` | none | Proves the collectors only read. Run this **first**. |
| `Invoke-WindowsAudit.ps1` | your user | Most of the audit. Warns if you run it elevated. |
| `Invoke-WindowsAudit-Admin.ps1` | admin | The checks that genuinely need it. ~120 lines, readable in one sitting. |
| `Quarantine.ps1` | as needed | Reversible removal. For the remediation phase — not now. |

## Order of operations

```powershell
cd security\windows-hardening

# 1. Verify the claims before trusting the scripts.
powershell -ExecutionPolicy Bypass -File .\Verify-ReadOnly.ps1

# 2. Main audit — as your normal user, NOT elevated.
powershell -ExecutionPolicy Bypass -File .\Invoke-WindowsAudit.ps1
#    add -Quick to skip the slower filesystem sweeps

# 3. The elevated remainder. Read it first.
#    (right-click PowerShell > Run as administrator)
powershell -ExecutionPolicy Bypass -File .\Invoke-WindowsAudit-Admin.ps1
```

`-ExecutionPolicy Bypass` applies to that single process only — it does not change
the machine's execution policy. The audit *reports* your execution policy in
section 3; it never sets it.

Transcripts land in your user profile as
`%USERPROFILE%\windows-audit-<host>-<timestamp>.txt` and
`windows-audit-admin-<host>-<timestamp>.txt`.

**Skim before sharing.** Sections likely to want redaction are tagged
`[REVIEW BEFORE SHARING]`. The transcripts contain your username, hostname, local
account names, installed software, hosts-file entries and scheduled-task command
lines.

## Guarantees, and how to check them

**Read-only.** No `Set-*`, `New-*`, `Remove-*`, `Enable-*`, `Disable-*`, `Start-*`,
`Stop-*`, `reg add`, `netsh set`, `bcdedit /set`, or `sc config`. Native tools
appear only in read-only forms — `bcdedit /enum`, `auditpol /get`, `manage-bde
-status`, `cmdkey /list`, `netsh wlan show profiles`.

`Verify-ReadOnly.ps1` scans for every state-changing form and includes a negative
control so you can confirm the detector fires. Expected: **0 mutating hits** in
each collector, **1 disclosed `Out-File`** each (the transcript write into your own
profile — the only thing either script creates), and **8 of 8** controls caught.

**No secrets in the transcript.** The collectors never print the contents of
private keys, `.env` files, wallet files, browser password stores, Wi-Fi PSKs,
the auto-login password, or BitLocker recovery keys. Specifically:

- **BitLocker recovery keys** are filtered out. Key protectors are projected to
  `KeyProtectorType` and `KeyProtectorId` only; the `RecoveryPassword` property is
  never selected. The escrow check greps `manage-bde` output for backup-status
  lines and drops the numerical password.
- **Winlogon `DefaultPassword`** is reported as a presence boolean. The value is
  never read. Its presence *is* the finding — that's your Windows password sitting
  in the registry in cleartext.
- **Wi-Fi profiles** are listed by name only. The script never runs
  `netsh wlan show profile key=clear`, which would print your PSKs.
- **PowerShell history** (`ConsoleHost_history.txt`) is scanned with match counts
  for 64-hex and base58 key shapes. No line is ever printed. PSReadLine records
  every command you type, forever, in plaintext — so a nonzero count is a real
  finding, and printing the lines would be the exact mistake being tested for.
- **Secret files** are reported by path, size and ACL identities. The Windows
  analogue of "world-readable" is an ACE granting Everyone, `BUILTIN\Users` or
  Authenticated Users, so that's what gets flagged.
- **LSASS is never touched** and the SAM/SECURITY hives are never read.

The deliberate exceptions are the hosts file and scheduled-task actions, where the
attack *is* the content. Both are tagged `[REVIEW BEFORE SHARING]`.

**Nothing is deleted, ever.** `Quarantine.ps1` contains no `Remove-Item`, no
`.Delete()`, no `rmdir`, no `Clear-Content` — verified by `Verify-ReadOnly.ps1`.
It moves items to `%USERPROFILE%\Security-Quarantine-<timestamp>\`, preserving the
original directory structure, and writes:

- `MANIFEST.csv` — original path, quarantined path, size, SHA-256, ACL SDDL, timestamp
- `Restore.ps1` — puts everything back and verifies each file against its hash

The quarantine root sits in your profile root, deliberately **not** on the Desktop
and **not** in Documents, because OneDrive Known Folder Move redirects both into
the cloud. The script refuses to run if its root would land inside OneDrive,
Dropbox, Google Drive or Box.

```powershell
.\Quarantine.ps1 -Path 'C:\path\to\thing'            # DRY RUN — default, moves nothing
.\Quarantine.ps1 -Path 'C:\path\to\thing' -Commit    # actually move
& "$env:USERPROFILE\Security-Quarantine-*\Restore.ps1"   # undo
```

Safety guards:

- refuses `C:\`, `C:\Windows`, `System32`, `SysWOW64`, Program Files, ProgramData,
  `C:\Users`, your profile, AppData roots
- refuses any **directory** less than three levels deep — covers the class rather
  than an enumerable list; individual files at any depth are fine
- refuses to overwrite anything already at the destination
- **moving a file does not unregister it.** A Run key, scheduled task or service
  can still point at the old path. The script *prints* the commands to find those
  references and leaves the decision to you, because unregistering is a state
  change.

## Verification status — read this

The bash toolkit in `../macos-hardening/` was executed and tested end to end. **These
PowerShell scripts were not**, because the container that produced them has no
PowerShell and no package source for one. What *was* verified, statically:

- the read-only property, using an independent reimplementation of the detector
  regex — 0 mutating hits in both collectors, 8/8 negative controls caught
- no deletion primitives anywhere in `Quarantine.ps1`
- quote balance across every logical line (here-string and backtick-escape aware)
- brace, parenthesis and bracket balance in all four scripts

Not verified: runtime behaviour on a real Windows 11 host. Individual checks may
need adjusting for your build — a cmdlet absent on Home edition, a registry path
that differs on 24H2. Each check is wrapped in its own try/catch and prints
`[ERROR] <message>` rather than aborting the run, so a failing check costs you
that one line and nothing else. Send the transcript including any `[ERROR]` lines
and they can be fixed.

## What this toolkit does not do

It does not decide anything. It collects evidence. Interpretation — which findings
are real, which have a genuine exploit path, and which are noise — is the next
phase.
