#!/bin/bash
# macos-audit-sudo.sh — the ONLY checks that genuinely require root.
#
# Deliberately short so you can read every line before granting root.
#
# READ-ONLY: every macOS command below is a status query. There is no write,
# no delete, no enable/disable, no load/unload.
#
# ONE DISCLOSED EXCEPTION: the last line runs `chown` on the OUTPUT TRANSCRIPT
# in your home directory, so the file this script writes ends up owned by you
# instead of by root. It touches nothing else. That is the single hit you will
# see from the checker:
#     bash verify-readonly.sh          # expected: exactly 1 hit here, the chown
#
# SECRET SAFETY: prints no key material. The TCC queries return application
# identifiers and permission verdicts, not data. `profiles` returns payload
# metadata. `sfltool dumpbtm` returns program paths.
#
# Usage:  sudo bash macos-audit-sudo.sh
# Output: ~/macos-audit-sudo-<timestamp>.txt  (owned by you, not root)

set -u

if [ "$(uname -s)" != "Darwin" ]; then
  echo "ERROR: macOS-only. Detected: $(uname -s)" >&2; exit 1
fi
if [ "$(id -u)" != "0" ]; then
  echo "ERROR: this half must run as root:  sudo bash $0" >&2; exit 1
fi

REAL_USER="${SUDO_USER:-$(stat -f '%Su' /dev/console)}"
REAL_HOME=$(dscl . -read "/Users/$REAL_USER" NFSHomeDirectory 2>/dev/null | awk '{print $2}')
[ -z "$REAL_HOME" ] && REAL_HOME="/Users/$REAL_USER"
TS=$(date +%Y%m%d-%H%M%S)
OUT="$REAL_HOME/macos-audit-sudo-$TS.txt"

run() {
  printf '\n### %s\n$ %s\n' "$1" "$2"
  local out rc
  out=$(eval "$2" </dev/null 2>&1); rc=$?
  if [ -z "$out" ]; then printf '  (no output)   [exit %d]\n' "$rc"
  else printf '%s\n' "$out" | sed 's/^/  /'; printf '  [exit %d]\n' "$rc"; fi
}

main() {
printf '###############################################################\n'
printf '#  macOS audit — root-only checks (READ-ONLY)\n'
printf '#  generated: %s\n' "$(date)"
printf '#  invoking user: %s   home: %s\n' "$REAL_USER" "$REAL_HOME"
printf '###############################################################\n'

printf '\n== FILEVAULT DETAIL ==\n'
run "Users who can unlock FileVault (account names only)" "fdesetup list"
run "Personal recovery key exists?"      "fdesetup haspersonalrecoverykey"
run "Institutional recovery key exists?" "fdesetup hasinstitutionalrecoverykey"

printf '\n== BOOT SECURITY ==\n'
run "Apple Silicon boot policy" "bputil -d 2>&1 | head -30"
run "Intel firmware password set?" "firmwarepasswd -check 2>&1"

printf '\n== REMOTE ACCESS (authoritative answers) ==\n'
run "Remote Login (SSH)"        "systemsetup -getremotelogin"
run "Remote Apple Events"       "systemsetup -getremoteappleevents"
run "Disabled/enabled system launchd services of interest" \
    "launchctl print-disabled system 2>/dev/null | grep -iE 'ssh|screensharing|smbd|AppleFileServer|ARD|RemoteDesktop|vnc'"

printf '\n== FULL LISTENER ATTRIBUTION ==\n'
run "Every listening socket with its owning process" \
    "lsof -nP -iTCP -sTCP:LISTEN 2>/dev/null | head -40"
run "Processes listening on UDP" "lsof -nP -iUDP 2>/dev/null | head -25"

printf '\n== PRIVILEGE ==\n'
run "NOPASSWD rules in sudoers (grep only — files are not dumped)" \
    "grep -rn 'NOPASSWD' /etc/sudoers /etc/sudoers.d/ 2>/dev/null || echo 'no NOPASSWD rules found'"
run "sudoers.d contents inventory (names, modes, owners)" "ls -la /etc/sudoers.d/"

printf '\n== MANAGEMENT / PROFILES ==\n'
run "All installed configuration profiles" "profiles list -all 2>&1 | head -60"
run "MDM enrolment detail" "profiles status -type enrollment 2>&1"

printf '\n== BACKGROUND ITEMS (Ventura+) ==\n'
run "Registered background/login items" \
    "sfltool dumpbtm 2>/dev/null | grep -E '^[[:space:]]*(Name|Program|Developer Name|Type|Disposition):' | head -80"

printf '\n== PRIVACY GRANTS (TCC) — app identifiers and verdicts only ==\n'
run "SYSTEM-wide Full Disk Access grants" \
    "sqlite3 '/Library/Application Support/com.apple.TCC/TCC.db' \"select service, client, auth_value from access where service in ('kTCCServiceSystemPolicyAllFiles','kTCCServiceAccessibility','kTCCServiceScreenCapture','kTCCServiceListenEvent') order by service;\" 2>&1 | head -40"
run "USER-level privacy grants for $REAL_USER" \
    "sqlite3 '$REAL_HOME/Library/Application Support/com.apple.TCC/TCC.db' \"select service, client, auth_value from access where service in ('kTCCServiceAccessibility','kTCCServiceScreenCapture','kTCCServiceListenEvent','kTCCServicePostEvent','kTCCServiceSystemPolicyAllFiles') order by service;\" 2>&1 | head -40"
printf '\n  NOTE: auth_value 2 = allowed. kTCCServiceAccessibility + kTCCServiceListenEvent\n'
printf '  together are keylogger-equivalent. kTCCServiceScreenCapture allowed means that\n'
printf '  app can read your screen, including a seed phrase displayed during wallet setup.\n'
printf '  If these queries return "unable to open database file", Terminal itself lacks\n'
printf '  Full Disk Access — that is a GOOD sign, and the check is simply unavailable.\n'

printf '\n== KERNEL ==\n'
run "Loaded non-Apple kexts" "kmutil showloaded --no-kernel-components 2>&1 | grep -v com.apple | head -20"

printf '\n=== END (root section) — %s ===\n' "$(date)"
}

main 2>&1 | tee "$OUT"
chown "$REAL_USER" "$OUT" 2>/dev/null
printf '\n>>> Saved to: %s (owned by %s)\n' "$OUT" "$REAL_USER"
