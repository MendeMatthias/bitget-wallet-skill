<#
    Quarantine.ps1 — reversible removal. MOVES things aside. Never deletes.

    There is no Remove-Item, no del, no rmdir, no .Delete() anywhere in this
    script. Verify before trusting it:

        Select-String -Path .\Quarantine.ps1 -Pattern 'Remove-Item|\.Delete\(|\bdel\b|rmdir|Clear-Content'

    Everything moved is recorded in a manifest and can be put back by the
    generated Restore.ps1, which verifies each file against its recorded
    SHA-256 hash.

    The quarantine folder is created directly in your user profile root —
    deliberately NOT on the Desktop and NOT in Documents, because OneDrive
    Known Folder Move redirects both of those into the cloud. The script
    refuses to run if its own root would land inside a synced location.

    USAGE:
        .\Quarantine.ps1 -Path 'C:\path\to\thing'                 # DRY RUN (default)
        .\Quarantine.ps1 -Path 'C:\a','C:\b' -Commit              # actually move
        & "$env:USERPROFILE\Security-Quarantine-*\Restore.ps1"    # undo

    Nothing moves unless you pass -Commit. Run it once without, read what it
    says it will do, then run it again with.

    NOTE ON PERSISTENCE: moving a file does NOT remove a registry Run entry, a
    scheduled task, or a service registration that points at it. For those this
    script PRINTS the command you would run and leaves the decision to you —
    unregistering is a state change and stays yours.
#>

[CmdletBinding()]
param(
    [Parameter(Mandatory = $true)]
    [string[]]$Path,

    [switch]$Commit
)

$ErrorActionPreference = 'Continue'

# --- resolve quarantine root ----------------------------------------------
$ts     = Get-Date -Format 'yyyyMMdd-HHmmss'
$QRoot  = Join-Path $env:USERPROFILE "Security-Quarantine-$ts"

# Guard: never place quarantined material anywhere that syncs to the cloud.
$syncMarkers = @('OneDrive', 'Dropbox', 'Google Drive', 'Box Sync', 'iCloudDrive')
foreach ($m in $syncMarkers) {
    if ($QRoot -like "*\$m\*" -or $QRoot -like "*\$m") {
        Write-Host "REFUSING: quarantine root '$QRoot' is inside a cloud-synced path." -ForegroundColor Red
        Write-Host 'Quarantined material must not be uploaded anywhere. Aborting.'
        exit 1
    }
}
# Also catch a redirected profile that resolves under OneDrive.
if ($env:OneDrive -and $QRoot.StartsWith($env:OneDrive, [StringComparison]::OrdinalIgnoreCase)) {
    Write-Host "REFUSING: your user profile resolves inside OneDrive ($env:OneDrive)." -ForegroundColor Red
    Write-Host 'Pick a non-synced location manually before quarantining anything.'
    exit 1
}

$ManifestPath = Join-Path $QRoot 'MANIFEST.csv'
$RestorePath  = Join-Path $QRoot 'Restore.ps1'

# Paths that must never be moved, whatever the caller passes.
$protected = @(
    $env:SystemDrive + '\',
    $env:SystemRoot,
    (Join-Path $env:SystemRoot 'System32'),
    (Join-Path $env:SystemRoot 'SysWOW64'),
    $env:ProgramFiles,
    ${env:ProgramFiles(x86)},
    $env:ProgramData,
    $env:USERPROFILE,
    (Join-Path $env:SystemDrive 'Users'),
    $env:APPDATA,
    $env:LOCALAPPDATA
) | Where-Object { $_ } | ForEach-Object { $_.TrimEnd('\') }

$records  = New-Object System.Collections.Generic.List[object]
$moved    = 0
$skipped  = 0

if ($Commit) {
    try {
        New-Item -ItemType Directory -Path $QRoot -Force -ErrorAction Stop | Out-Null
    } catch {
        Write-Host "Cannot create quarantine root: $($_.Exception.Message)" -ForegroundColor Red
        exit 1
    }
    Write-Host "Quarantine root: $QRoot" -ForegroundColor Cyan
} else {
    Write-Host '=== DRY RUN — nothing will be moved. Re-run with -Commit to act. ===' -ForegroundColor Yellow
    Write-Host "Would create quarantine root: $QRoot"
}
Write-Host ''

foreach ($p in $Path) {

    if (-not (Test-Path -LiteralPath $p)) {
        Write-Host "  SKIP  $p  (does not exist)"
        $skipped++
        continue
    }

    $item = Get-Item -LiteralPath $p -Force -ErrorAction SilentlyContinue
    if (-not $item) {
        Write-Host "  SKIP  $p  (cannot resolve)"
        $skipped++
        continue
    }

    $abs = $item.FullName.TrimEnd('\')

    # --- guard 1: explicit protected paths --------------------------------
    if ($protected -contains $abs) {
        Write-Host "  REFUSE $abs  (protected path — moving this would break Windows or your profile)" -ForegroundColor Red
        $skipped++
        continue
    }

    # --- guard 2: never move a shallow DIRECTORY --------------------------
    # Covers the whole class rather than an enumerable list. Individual FILES
    # at any depth are fine — that is the normal case.
    $isDir = $item.PSIsContainer
    if ($isDir) {
        $segments = ($abs -replace '^[A-Za-z]:\\', '') -split '\\' | Where-Object { $_ }
        if ($segments.Count -le 2) {
            Write-Host "  REFUSE $abs  (directory only $($segments.Count) level(s) deep — too broad to quarantine safely)" -ForegroundColor Red
            $skipped++
            continue
        }
    }

    # --- build destination, preserving structure --------------------------
    # C:\Users\bob\evil.exe  ->  <QRoot>\C\Users\bob\evil.exe
    $relative = $abs -replace '^([A-Za-z]):\\', '$1\'
    $dest     = Join-Path $QRoot $relative
    $destDir  = Split-Path $dest -Parent

    $len  = if ($isDir) { $null } else { $item.Length }
    $sddl = try { (Get-Acl -LiteralPath $abs -ErrorAction Stop).Sddl } catch { '' }

    if (-not $Commit) {
        Write-Host "  WOULD MOVE  $abs"
        Write-Host "              -> $dest"
        Write-Host "              type=$(if ($isDir) {'directory'} else {"file, $len bytes"})"
        if ($abs -match '\.(exe|dll|ps1|bat|cmd|vbs|js)$') {
            Write-Host '              after moving, check for a registration still pointing at it:'
            Write-Host '                Get-CimInstance Win32_Service | Where-Object PathName -match ([regex]::Escape($abs))'
            Write-Host '                Get-ScheduledTask | Where-Object { $_.Actions.Execute -eq $abs }'
        }
        $moved++
        continue
    }

    if (Test-Path -LiteralPath $dest) {
        Write-Host "  SKIP  $abs  (destination already exists in quarantine — not overwriting)"
        $skipped++
        continue
    }

    try {
        if (-not (Test-Path -LiteralPath $destDir)) {
            New-Item -ItemType Directory -Path $destDir -Force -ErrorAction Stop | Out-Null
        }
    } catch {
        Write-Host "  FAIL  $abs  (cannot create $destDir): $($_.Exception.Message)" -ForegroundColor Red
        $skipped++
        continue
    }

    # Hash before moving, for restore-time integrity verification.
    # A SHA-256 is not reversible: it records integrity without exposing content.
    $sha = ''
    if (-not $isDir -and $len -ne $null -and $len -lt 52428800) {
        try { $sha = (Get-FileHash -LiteralPath $abs -Algorithm SHA256 -ErrorAction Stop).Hash } catch { $sha = '' }
    }

    try {
        Move-Item -LiteralPath $abs -Destination $dest -Force:$false -ErrorAction Stop
        $records.Add([pscustomobject]@{
            OriginalPath    = $abs
            QuarantinedPath = $dest
            IsDirectory     = $isDir
            Length          = $len
            Sha256          = $sha
            Sddl            = $sddl
            MovedAtUtc      = (Get-Date).ToUniversalTime().ToString('o')
        }) | Out-Null
        Write-Host "  MOVED $abs" -ForegroundColor Green
        Write-Host "        -> $dest"
        $moved++

        if ($abs -match '\.(exe|dll|ps1|bat|cmd|vbs|js)$') {
            Write-Host '        NOTE: a service, scheduled task or Run key may still reference this path.'
            Write-Host '              Moving the file does not unregister it. To find references:'
            Write-Host "                Get-CimInstance Win32_Service | Where-Object PathName -match ([regex]::Escape('$abs'))"
        }
    } catch {
        Write-Host "  FAIL  $abs  ($($_.Exception.Message))" -ForegroundColor Red
        Write-Host '        if this is Access Denied, re-run in an elevated PowerShell.'
        $skipped++
    }
}

Write-Host ''

if (-not $Commit) {
    Write-Host "DRY RUN complete: $moved item(s) would move, $skipped skipped. Nothing changed." -ForegroundColor Yellow
    exit 0
}

# --- write manifest --------------------------------------------------------
try {
    $records | Export-Csv -Path $ManifestPath -NoTypeInformation -Encoding UTF8
} catch {
    Write-Host "WARNING: could not write manifest: $($_.Exception.Message)" -ForegroundColor Red
}

# --- generate the restore script ------------------------------------------
$restoreBody = @'
<#
    Restore.ps1 — put every quarantined item back exactly where it came from.
    Reads MANIFEST.csv next to this script. Never deletes; refuses to overwrite
    anything that has reappeared at the original path. Verifies each restored
    file against its recorded SHA-256.
#>
[CmdletBinding()]
param()

$here     = Split-Path -Parent $MyInvocation.MyCommand.Path
$manifest = Join-Path $here 'MANIFEST.csv'

if (-not (Test-Path $manifest)) {
    Write-Host "manifest not found: $manifest" -ForegroundColor Red
    exit 1
}

$rows = Import-Csv $manifest
foreach ($r in $rows) {
    if (-not (Test-Path -LiteralPath $r.QuarantinedPath)) {
        Write-Host "  MISSING in quarantine: $($r.QuarantinedPath)" -ForegroundColor Yellow
        continue
    }
    if (Test-Path -LiteralPath $r.OriginalPath) {
        Write-Host "  SKIP (something is back at) $($r.OriginalPath)" -ForegroundColor Yellow
        continue
    }
    $parent = Split-Path $r.OriginalPath -Parent
    if (-not (Test-Path -LiteralPath $parent)) {
        try { New-Item -ItemType Directory -Path $parent -Force -ErrorAction Stop | Out-Null } catch { }
    }
    try {
        Move-Item -LiteralPath $r.QuarantinedPath -Destination $r.OriginalPath -ErrorAction Stop
        if ($r.Sha256) {
            $now = (Get-FileHash -LiteralPath $r.OriginalPath -Algorithm SHA256 -ErrorAction SilentlyContinue).Hash
            if ($now -eq $r.Sha256) {
                Write-Host "  RESTORED (hash verified) $($r.OriginalPath)" -ForegroundColor Green
            } else {
                Write-Host "  RESTORED (HASH MISMATCH — inspect) $($r.OriginalPath)" -ForegroundColor Red
            }
        } else {
            Write-Host "  RESTORED $($r.OriginalPath)" -ForegroundColor Green
        }
    } catch {
        Write-Host "  FAILED (try an elevated PowerShell) $($r.OriginalPath): $($_.Exception.Message)" -ForegroundColor Red
    }
}
Write-Host ''
Write-Host 'Restore pass complete. Re-run elevated if any item reported FAILED.'
'@

try {
    $restoreBody | Out-File -FilePath $RestorePath -Encoding utf8
} catch {
    Write-Host "WARNING: could not write Restore.ps1: $($_.Exception.Message)" -ForegroundColor Red
}

Write-Host "Complete: $moved moved, $skipped skipped." -ForegroundColor Cyan
Write-Host "  quarantine : $QRoot"
Write-Host "  manifest   : $ManifestPath"
Write-Host "  undo with  : & '$RestorePath'"
