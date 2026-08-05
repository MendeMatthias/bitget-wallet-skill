#!/bin/bash
# quarantine.sh — reversible removal. MOVES things aside. Never deletes.
#
# There is no `rm` in this script. Not for files, not for directories, not for
# temp files. Verify before trusting it:
#     grep -n 'rm ' quarantine.sh          # expect: no hits outside comments
#
# Everything moved is recorded in a manifest and can be put back byte-for-byte
# by the generated restore.sh. The quarantine folder lives directly in your
# home directory — NOT on the Desktop and NOT in Documents, because those two
# are uploaded to Apple when iCloud "Desktop & Documents" sync is enabled.
#
# Usage:
#   bash quarantine.sh <path> [<path> ...]              # DRY RUN (default)
#   bash quarantine.sh --commit <path> [<path> ...]     # actually move
#   sudo bash quarantine.sh --commit /Library/LaunchDaemons/x.plist
#
# Nothing is moved unless you pass --commit. Run it once without, read what it
# says it will do, then run it again with.

set -u

COMMIT=0
ARGS=()
for a in "$@"; do
  case "$a" in
    --commit) COMMIT=1 ;;
    --dry-run) COMMIT=0 ;;
    -h|--help) sed -n '2,22p' "$0"; exit 0 ;;
    -*) echo "unknown option: $a" >&2; exit 2 ;;
    *) ARGS+=("$a") ;;
  esac
done

if [ "${#ARGS[@]}" -eq 0 ]; then
  echo "usage: bash quarantine.sh [--commit] <path> [<path> ...]" >&2
  exit 2
fi

# Resolve the human's home even when invoked under sudo.
REAL_USER="${SUDO_USER:-$(id -un)}"
if [ -n "${SUDO_USER:-}" ]; then
  REAL_HOME=$(dscl . -read "/Users/$SUDO_USER" NFSHomeDirectory 2>/dev/null | awk '{print $2}')
  [ -z "$REAL_HOME" ] && REAL_HOME="/Users/$SUDO_USER"
else
  REAL_HOME="$HOME"
fi

TS=$(date +%Y%m%d-%H%M%S)
QROOT="$REAL_HOME/Security-Quarantine-$TS"

# --- guard: the quarantine must not land in a cloud-synced location --------
case "$QROOT" in
  *"/Mobile Documents/"*|*"/CloudStorage/"*|*"/Dropbox/"*|*"/Google Drive"*|*"/OneDrive"*|*"/Desktop/"*|*"/Documents/"*)
    echo "REFUSING: quarantine root '$QROOT' is inside a cloud-synced path." >&2
    echo "Quarantined material must not be uploaded anywhere. Aborting." >&2
    exit 1 ;;
esac

MANIFEST="$QROOT/MANIFEST.tsv"
RESTORE="$QROOT/restore.sh"
NEEDS_ROOT=0

if [ "$COMMIT" = "1" ]; then
  mkdir -p "$QROOT" || { echo "cannot create $QROOT" >&2; exit 1; }
  chmod 700 "$QROOT"
  printf 'original_path\tquarantined_path\tmode\towner\tgroup\tsize\tsha256\tmoved_at\n' > "$MANIFEST"
  printf '%s\n' "# quarantine created $(date) by $REAL_USER" >> "$QROOT/README.txt"
  echo "Quarantine root: $QROOT"
else
  echo "=== DRY RUN — nothing will be moved. Re-run with --commit to act. ==="
  echo "Would create quarantine root: $QROOT"
fi
echo

moved=0
skipped=0

for src in "${ARGS[@]}"; do
  if [ ! -e "$src" ] && [ ! -L "$src" ]; then
    printf '  SKIP  %s  (does not exist)\n' "$src"
    skipped=$((skipped+1))
    continue
  fi

  # Absolute path without following the final symlink (we move links as links).
  case "$src" in
    /*) abs="$src" ;;
    *)  abs="$(pwd)/$src" ;;
  esac
  # Strip trailing slashes so "/etc/" is treated identically to "/etc",
  # then refuse the filesystem root outright before any further processing.
  while [ "$abs" != "/" ] && [ "${abs%/}" != "$abs" ]; do abs="${abs%/}"; done
  if [ "$abs" = "/" ]; then
    printf '  REFUSE /  (the filesystem root)\n'
    skipped=$((skipped+1))
    continue
  fi

  parent=$(dirname "$abs")
  base=$(basename "$abs")
  rparent=$(cd "$parent" 2>/dev/null && pwd -P) || rparent="$parent"
  # NOTE: when the parent is "/", naive "$rparent/$base" yields "//etc", which
  # silently defeated the protected-path guard below. Normalise it.
  if [ "$rparent" = "/" ]; then abs="/$base"; else abs="$rparent/$base"; fi

  # --- guard 1: explicit protected paths -----------------------------------
  case "$abs" in
    /|/System|/System/*|/usr|/usr/bin|/usr/lib|/usr/local|/bin|/sbin|/etc|/var|/private|/dev|/opt|/Volumes|/Users|/Applications|/Library|"$REAL_HOME"|"$REAL_HOME/Library"|"$REAL_HOME/Library/LaunchAgents")
      printf '  REFUSE %s  (protected path — quarantining this would break the OS or your account)\n' "$abs"
      skipped=$((skipped+1))
      continue ;;
  esac

  # --- guard 2: never move a shallow DIRECTORY ------------------------------
  # Catches the whole class rather than an enumerable list: /etc, /Library,
  # /Library/LaunchDaemons, /usr/local ... all have <=2 path components.
  # Individual FILES at any depth are fine (that is the normal case:
  # /Library/LaunchDaemons/com.evil.plist has 3).
  if [ -d "$abs" ] && [ ! -L "$abs" ]; then
    depth=$(printf '%s' "${abs#/}" | awk -F/ '{print NF}')
    if [ "${depth:-0}" -le 2 ]; then
      printf '  REFUSE %s  (directory only %s level(s) deep — too broad to quarantine safely)\n' "$abs" "$depth"
      skipped=$((skipped+1))
      continue
    fi
  fi

  dest="$QROOT$abs"
  destdir=$(dirname "$dest")

  # Sanitise metadata to a single clean token. The manifest is TAB-separated;
  # a newline or tab from a misbehaving stat would corrupt it and break restore.
  meta() { printf '%s' "$1" | tr -d '\t\n\r' | head -c 64; }
  mode=$(meta "$(stat -f '%Lp' "$abs" 2>/dev/null | head -1)")
  owner=$(meta "$(stat -f '%Su' "$abs" 2>/dev/null | head -1)")
  group=$(meta "$(stat -f '%Sg' "$abs" 2>/dev/null | head -1)")
  size=$(meta "$(stat -f '%z' "$abs" 2>/dev/null | head -1)")
  case "$mode" in ''|*[!0-7]*) mode='?' ;; esac
  case "$size" in ''|*[!0-9]*) size='?' ;; esac
  [ -z "$owner" ] && owner='?'
  [ -z "$group" ] && group='?'

  # Writability check on the SOURCE DIRECTORY — that is what a move needs.
  if [ ! -w "$rparent" ]; then
    printf '  NEEDS ROOT  %s  (cannot write to %s as %s)\n' "$abs" "$rparent" "$(id -un)"
    NEEDS_ROOT=1
    skipped=$((skipped+1))
    continue
  fi

  if [ "$COMMIT" = "0" ]; then
    printf '  WOULD MOVE  %s\n              -> %s   (mode=%s owner=%s size=%s)\n' "$abs" "$dest" "$mode" "$owner" "$size"
    case "$abs" in
      *.plist)
        printf '              after moving, unload it yourself with:\n'
        printf '                sudo launchctl bootout system %s   # or: launchctl bootout gui/$(id -u) %s\n' "$abs" "$abs" ;;
    esac
    moved=$((moved+1))
    continue
  fi

  if [ -e "$dest" ]; then
    printf '  SKIP  %s  (destination already exists in quarantine — not overwriting)\n' "$abs"
    skipped=$((skipped+1))
    continue
  fi

  mkdir -p "$destdir" || { printf '  FAIL  %s (cannot create %s)\n' "$abs" "$destdir"; skipped=$((skipped+1)); continue; }

  # Hash before moving, for restore-time integrity verification.
  # A SHA-256 is not reversible: this records integrity without exposing content.
  sha=""
  if [ -f "$abs" ] && [ "$size" != '?' ] && [ "$size" -lt 52428800 ]; then
    sha=$(shasum -a 256 "$abs" 2>/dev/null | awk '{print $1}')
  fi

  if mv "$abs" "$dest"; then
    printf '%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\n' \
      "$abs" "$dest" "${mode:-?}" "${owner:-?}" "${group:-?}" "${size:-?}" "${sha:-n/a}" "$(date -u +%Y-%m-%dT%H:%M:%SZ)" >> "$MANIFEST"
    printf '  MOVED %s\n        -> %s\n' "$abs" "$dest"
    moved=$((moved+1))
    case "$abs" in
      *.plist)
        printf '        NOTE: the job may still be loaded in launchd until reboot. To unload now:\n'
        printf '              sudo launchctl bootout system %s\n' "$abs" ;;
    esac
  else
    printf '  FAIL  %s (move failed)\n' "$abs"
    skipped=$((skipped+1))
  fi
done

echo
if [ "$COMMIT" = "0" ]; then
  printf 'DRY RUN complete: %d item(s) would move, %d skipped. Nothing changed.\n' "$moved" "$skipped"
  [ "$NEEDS_ROOT" = "1" ] && printf 'Some items are in root-owned directories — re-run those with sudo.\n'
  exit 0
fi

# --- generate the restore script ------------------------------------------
cat > "$RESTORE" <<'RESTORE_EOF'
#!/bin/bash
# restore.sh — put every quarantined item back exactly where it came from.
# Reads MANIFEST.tsv next to this script. Never deletes; refuses to overwrite
# anything that has reappeared at the original path.
set -u
HERE=$(cd "$(dirname "$0")" && pwd -P)
M="$HERE/MANIFEST.tsv"
[ -f "$M" ] || { echo "manifest not found: $M" >&2; exit 1; }
tail -n +2 "$M" | while IFS=$'\t' read -r orig dest mode owner group size sha when; do
  [ -n "${orig:-}" ] || continue
  if [ ! -e "$dest" ]; then echo "  MISSING in quarantine: $dest"; continue; fi
  if [ -e "$orig" ]; then echo "  SKIP (something is back at) $orig"; continue; fi
  mkdir -p "$(dirname "$orig")" 2>/dev/null
  if mv "$dest" "$orig" 2>/dev/null; then
    [ "$mode"  != "?" ] && chmod "$mode" "$orig" 2>/dev/null
    [ "$owner" != "?" ] && chown "$owner:$group" "$orig" 2>/dev/null
    if [ "$sha" != "n/a" ] && [ -f "$orig" ]; then
      now=$(shasum -a 256 "$orig" 2>/dev/null | awk '{print $1}')
      if [ "$now" = "$sha" ]; then echo "  RESTORED (hash verified) $orig"
      else echo "  RESTORED (HASH MISMATCH — inspect) $orig"; fi
    else
      echo "  RESTORED $orig"
    fi
  else
    echo "  FAILED (try sudo) $orig"
  fi
done
echo "Restore pass complete. Re-run with sudo if any item reported FAILED."
RESTORE_EOF
chmod +x "$RESTORE"

# Hand ownership back to the human if we ran under sudo.
if [ -n "${SUDO_USER:-}" ]; then
  chown -R "$SUDO_USER" "$QROOT" 2>/dev/null
fi

printf 'Complete: %d moved, %d skipped.\n' "$moved" "$skipped"
printf '  quarantine : %s\n' "$QROOT"
printf '  manifest   : %s\n' "$MANIFEST"
printf '  undo with  : bash %s\n' "$RESTORE"
[ "$NEEDS_ROOT" = "1" ] && printf '\nSome items need root — re-run those paths with: sudo bash %s --commit <path>\n' "$0"
exit 0
