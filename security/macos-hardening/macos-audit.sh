#!/bin/bash
# macos-audit.sh — READ-ONLY macOS security evidence collector.
#
# WHAT THIS IS: a diagnostic. It reads state and prints it. It changes nothing.
# There is no `defaults write`, no `csrutil enable/disable`, no `launchctl
# bootout`, no `chmod`, no `rm`, no `mv` anywhere in this file. Binaries like
# csrutil, spctl and nvram DO appear — but only in their read-only forms
# (`csrutil status`, `spctl --status`, `nvram boot-args`).
#
# Do not take that on trust. Run the checker:
#     bash verify-readonly.sh          # expected: 0 hits for this file
# It scans for every state-changing form and includes a negative control so you
# can confirm the detector actually fires.
#
# SECRET SAFETY: this script never prints the CONTENTS of private keys, .env
# files, keychains, wallet files, browser password stores, mnemonics, or shell
# history. For those it emits only: file paths, permission modes, byte sizes,
# and match COUNTS. The one deliberate exception is /etc/hosts and crontab,
# where the attack IS the content — those are printed and flagged for your
# review before you share the output.
#
# Usage:
#   bash macos-audit.sh                 # full audit, no network
#   bash macos-audit.sh --updates       # also query Apple for pending updates (slow, network)
#   bash macos-audit.sh --quick         # skip the slow system_profiler / filesystem sweeps
#
# Output goes to stdout AND to ~/macos-audit-<host>-<timestamp>.txt

set -u

WANT_UPDATES=0
QUICK=0
for a in "$@"; do
  case "$a" in
    --updates) WANT_UPDATES=1 ;;
    --quick)   QUICK=1 ;;
    -h|--help) sed -n '2,25p' "$0"; exit 0 ;;
    *) echo "unknown option: $a" >&2; exit 2 ;;
  esac
done

# ---- guards ---------------------------------------------------------------
if [ "$(uname -s)" != "Darwin" ]; then
  echo "ERROR: this script is macOS-only. Detected: $(uname -s)" >&2
  exit 1
fi
if [ "$(id -u)" = "0" ]; then
  cat >&2 <<'EOF'
ERROR: do not run this as root / with sudo.

This half of the audit is designed to run as YOU, unprivileged, so that its
read-only nature is easy to verify and so that per-user state (your keychain
list, your LaunchAgents, your Touch ID enrolment) is read from your account
and not root's. The handful of checks that genuinely need root live in the
separate, much shorter macos-audit-sudo.sh — read that one before running it.
EOF
  exit 1
fi

TS=$(date +%Y%m%d-%H%M%S)
OUT="$HOME/macos-audit-$(hostname -s 2>/dev/null || echo mac)-$TS.txt"

# ---- helpers --------------------------------------------------------------
have() { command -v "$1" >/dev/null 2>&1; }

sec() {
  printf '\n\n===============================================================\n'
  printf '== %s\n' "$1"
  printf '===============================================================\n'
}

# run "<label>" "<shell command>"  — prints the exact command, then its output.
# Every finding downstream must be traceable to one of these blocks.
run() {
  printf '\n### %s\n$ %s\n' "$1" "$2"
  local out rc
  out=$(eval "$2" </dev/null 2>&1); rc=$?
  if [ -z "$out" ]; then
    printf '  (no output)   [exit %d]\n' "$rc"
  else
    printf '%s\n' "$out" | sed 's/^/  /'
    printf '  [exit %d]\n' "$rc"
  fi
}

# runif <required-binary> "<label>" "<shell command>"
runif() {
  if have "$1"; then run "$2" "$3"
  else printf '\n### %s\n  SKIPPED — `%s` not present on this macOS version\n' "$2" "$1"
  fi
}

note() { printf '\n  NOTE: %s\n' "$1"; }

# ---------------------------------------------------------------------------
main() {

cat <<EOF
###############################################################################
#  macOS security audit — READ-ONLY evidence collection
#  generated : $(date)
#  host      : $(hostname 2>/dev/null)
#  user      : $(id -un) (uid $(id -u))
#  script    : $0
###############################################################################

BEFORE YOU SHARE THIS FILE, SKIM IT.
It contains no key material, no passwords and no file contents from secret
stores — by construction. It DOES contain: your username, hostname, local
account names, installed software paths, /etc/hosts entries and crontab lines.
Redact anything you consider sensitive. Sections that most often need a look
before sharing are marked [REVIEW BEFORE SHARING].
EOF

# =========================================================================
sec "0. SYSTEM IDENTITY & BASELINE"
run  "OS version and build"            "sw_vers"
run  "Kernel"                          "uname -a"
run  "Uptime / last boot"              "uptime; who -b 2>/dev/null"
if [ "$QUICK" = "0" ]; then
  run "Hardware (model, chip, serial redacted below)" \
      "system_profiler SPHardwareDataType 2>/dev/null | grep -vE 'Serial Number|Hardware UUID|Provisioning UDID|UDID'"
  run "Activation Lock status" \
      "system_profiler SPHardwareDataType 2>/dev/null | grep -i 'Activation Lock'"
fi
run  "Architecture / Rosetta" "arch; sysctl -n machdep.cpu.brand_string 2>/dev/null; sysctl -n sysctl.proc_translated 2>/dev/null"

# =========================================================================
sec "1. DISK ENCRYPTION (FileVault)"
runif fdesetup "FileVault status" "fdesetup status"
run   "APFS volume encryption state" "diskutil apfs list 2>/dev/null | grep -E 'APFS Volume Disk|FileVault|Encrypted|Unlocked|Name:' | head -40"
run   "Sleep / hibernate key handling (evil-maid relevance)" \
      "pmset -g | grep -E 'hibernatemode|standby|destroyfvkeyonstandby|powernap|standbydelay'"
note  "destroyfvkeyonstandby=0 + hibernatemode=3 means the FileVault key stays in RAM across sleep."

# =========================================================================
sec "2. SYSTEM INTEGRITY (SIP, SSV, boot policy, kernel flags)"
runif csrutil "System Integrity Protection" "csrutil status"
runif csrutil "Signed System Volume (authenticated root)" "csrutil authenticated-root status"
run   "NVRAM boot-args (should be EMPTY on a hardened Mac)" "nvram boot-args 2>&1"
run   "Other security-relevant NVRAM keys (names + presence only, values suppressed)" \
      "nvram -p 2>/dev/null | awk '{print \$1}' | grep -iE 'boot-args|csr-active-config|lpBB|fmm-|SecureBoot|amfi' | sort -u"
note  "csr-active-config present with a nonzero value = SIP partially disabled even if csrutil says 'enabled' for some flags."
run   "AMFI / library validation kernel flags" \
      "sysctl -a 2>/dev/null | grep -iE 'amfi|cs_enforcement|cs_debug|vm.cs_' | head -20"
run   "T2 / bridge secure boot policy (Intel T2 Macs)" \
      "system_profiler SPiBridgeDataType 2>/dev/null | grep -iE 'Secure Boot|External Boot|Model Name'"
note  "Apple Silicon boot policy needs root — see macos-audit-sudo.sh (bputil -d)."

# =========================================================================
sec "3. CODE-SIGNING GATE (Gatekeeper, XProtect, notarization)"
runif spctl "Gatekeeper assessment status" "spctl --status"
runif spctl "Gatekeeper verbose / dev mode" "spctl --status --verbose 2>&1; spctl developer-mode --status 2>&1"
run   "Gatekeeper functional test against a known-good Apple app" \
      "spctl --assess --type execute --verbose=4 /System/Applications/Calculator.app 2>&1 | head -5"
run   "Quarantine attribute enforcement (LSQuarantine)" \
      "defaults read com.apple.LaunchServices LSQuarantine 2>&1"
run   "XProtect signature version" \
      "defaults read /Library/Apple/System/Library/CoreServices/XProtect.bundle/Contents/Info CFBundleShortVersionString 2>/dev/null || defaults read /System/Library/CoreServices/XProtect.bundle/Contents/Info CFBundleShortVersionString 2>&1"
run   "XProtect Remediator version" \
      "defaults read /Library/Apple/System/Library/CoreServices/XProtect.app/Contents/Info CFBundleShortVersionString 2>&1"
run   "MRT / XProtect last-modified (staleness check)" \
      "ls -ld /Library/Apple/System/Library/CoreServices/XProtect.bundle /Library/Apple/System/Library/CoreServices/XProtect.app 2>&1"

# =========================================================================
sec "4. NETWORK PERIMETER (firewall, listeners, DNS, proxy)"
ALF=/usr/libexec/ApplicationFirewall/socketfilterfw
if [ -x "$ALF" ]; then
  run "Application firewall — global state"        "$ALF --getglobalstate"
  run "Application firewall — stealth mode"        "$ALF --getstealthmode"
  run "Application firewall — auto-allow SIGNED built-in software"  "$ALF --getallowsigned"
  run "Application firewall — block all incoming"  "$ALF --getblockall"
  run "Application firewall — logging"             "$ALF --getloggingmode; $ALF --getloggingopt"
  run "Application firewall — per-app allow list (first 40)" "$ALF --listapps 2>&1 | head -40"
else
  printf '\n### Application firewall\n  SKIPPED — %s not found\n' "$ALF"
fi
run "Firewall prefs via defaults (cross-check; may be absent on macOS 15+)" \
    "defaults read /Library/Preferences/com.apple.alf globalstate 2>&1; defaults read /Library/Preferences/com.apple.alf stealthenabled 2>&1"
note "Cross-check matters: --getallowsigned reporting ENABLED means any Apple-signed OR notarised-developer-signed binary is auto-permitted to accept inbound connections without prompting you."

run "Listening TCP sockets (all processes, owner shown only for yours)" \
    "netstat -an -p tcp 2>/dev/null | grep -i LISTEN | head -40"
run "Listening UDP sockets" "netstat -an -p udp 2>/dev/null | head -25"
run "Listening sockets owned by YOUR uid (process names)" \
    "lsof -nP -iTCP -sTCP:LISTEN 2>/dev/null | head -30"
note "Full process attribution for root-owned listeners needs sudo — see macos-audit-sudo.sh."

run "System proxy configuration (MITM vector)" "scutil --proxy"
run "DNS resolvers in effect" "scutil --dns 2>/dev/null | grep -E 'nameserver|domain|if_index' | head -25"
run "Network services and their DNS overrides" \
    "networksetup -listallnetworkservices 2>/dev/null | tail -n +2 | while IFS= read -r s; do printf '%s => ' \"\$s\"; networksetup -getdnsservers \"\$s\" 2>/dev/null | tr '\n' ' '; echo; done"
run "/etc/hosts — non-default entries only  [REVIEW BEFORE SHARING]" \
    "printf 'total non-comment lines: '; grep -cvE '^[[:space:]]*(#|\$)' /etc/hosts; echo '--- entries that are NOT standard loopback ---'; grep -vE '^[[:space:]]*(#|\$)' /etc/hosts | grep -vE '^(127\.0\.0\.1|::1|255\.255\.255\.255|fe80::1%lo0)[[:space:]]' | head -25"
run "Custom /etc/resolver overrides" "ls -la /etc/resolver 2>&1 | head -15"

# =========================================================================
sec "5. ACCOUNTS, AUTHENTICATION & PRIVILEGE"
run "Admin group membership"        "dscl . -read /Groups/admin GroupMembership 2>&1"
run "Local accounts with UID >= 500 (real users)" \
    "dscl . -list /Users UniqueID 2>/dev/null | awk '\$2 >= 500 {printf \"  %-28s uid=%s\n\", \$1, \$2}'"
run "ANY account with UID 0 besides root (critical if more than one)" \
    "dscl . -list /Users UniqueID 2>/dev/null | awk '\$2 == 0'"
run "Login shells of real users (service accounts with shells are suspicious)" \
    "dscl . -list /Users UserShell 2>/dev/null | grep -vE '/usr/bin/false|/sbin/nologin' | head -25"
run "Accounts hidden from the login window" \
    "defaults read /Library/Preferences/com.apple.loginwindow HiddenUsersList 2>&1"

run "Guest account enabled?" \
    "defaults read /Library/Preferences/com.apple.loginwindow GuestEnabled 2>&1; sysadminctl -guestAccount status 2>&1"
run "Guest account present in directory service?" "dscl . -read /Users/Guest RecordName 2>&1 | head -3"

run "Automatic login configured?" \
    "defaults read /Library/Preferences/com.apple.loginwindow autoLoginUser 2>&1"
run "/etc/kcpassword present? (existence + mode ONLY — contents never printed)" \
    "ls -l@ /etc/kcpassword 2>&1"
note "/etc/kcpassword existing means your login password is stored on disk XOR'd with a published static key. Its presence alone is the finding; the file is never read by this script."

run "Screen lock policy" "sysadminctl -screenLock status 2>&1"
run "Screensaver password settings (legacy keys; 'does not exist' is normal on macOS 14+)" \
    "defaults -currentHost read com.apple.screensaver askForPassword 2>&1; defaults -currentHost read com.apple.screensaver askForPasswordDelay 2>&1"
run "Display sleep / lock timing" "pmset -g | grep -E 'displaysleep|sleep|lidwake'"

runif bioutil "Touch ID enrolment (this user)" "bioutil -r 2>&1"
run   "Touch ID for sudo configured?" \
      "ls -l /etc/pam.d/sudo_local 2>&1; grep -c pam_tid.so /etc/pam.d/sudo_local 2>/dev/null || echo 'sudo_local: no pam_tid line'; grep -n pam_tid /etc/pam.d/sudo 2>&1"

run "Passwordless sudo test (non-interactive — will NOT prompt)" \
    "sudo -n -l 2>&1 | head -20"
note "CAVEAT: sudo caches credentials ~5 min. If you ran sudo recently in this terminal this shows success regardless. Re-run in a brand-new terminal for a clean reading."
run "sudoers drop-in files (names + modes only, contents not read)" \
    "ls -la /etc/sudoers.d/ 2>&1"
run "Password policy for this account" "pwpolicy -u \"$(id -un)\" -getaccountpolicies 2>&1 | head -25"

run "Find My Mac / iCloud device locate" \
    "defaults read /Library/Preferences/com.apple.FindMyMac FMMEnabled 2>&1; printf 'fmm nvram token present (count only): '; nvram -p 2>/dev/null | grep -c 'fmm-mobileme-token-FMM'"
note "The FMM nvram token value is a credential; only its presence count is emitted."

# =========================================================================
sec "6. REMOTE ACCESS & SHARING"
run "Remote login (SSH) listener present?" \
    "netstat -an -p tcp 2>/dev/null | grep -E '\.22[[:space:]].*LISTEN' || echo 'no listener on tcp/22'"
run "Screen Sharing / ARD / VNC listeners" \
    "netstat -an -p tcp 2>/dev/null | grep -E '\.(5900|5901|3283|5988|88[0-9][0-9])[[:space:]].*LISTEN' || echo 'no screen-sharing/ARD listeners'"
run "Remote Desktop / ARD configuration present on disk?" \
    "ls -la '/Library/Application Support/Apple/Remote Desktop' 2>&1 | head -10"
run "File sharing (SMB/AFP) listeners" \
    "netstat -an -p tcp 2>/dev/null | grep -E '\.(445|548|139)[[:space:]].*LISTEN' || echo 'no SMB/AFP listeners'"
run "SSH authorized_keys — key COUNT and comments only, no key material" \
    "for f in \"\$HOME\"/.ssh/authorized_keys*; do [ -f \"\$f\" ] || continue; printf '%s  mode=%s  keys=%s\n' \"\$f\" \"\$(stat -f '%Lp' \"\$f\")\" \"\$(grep -cvE '^[[:space:]]*(#|\$)' \"\$f\")\"; awk '{print \"    type=\" \$1 \"  comment=\" \$NF}' \"\$f\"; done 2>/dev/null || echo 'no authorized_keys'"
note "Only the key TYPE and trailing comment are printed. The base64 key body is never emitted (public keys are not secret, but the comment field is what identifies an unexpected grant)."
run "SSH daemon config deviations (non-default lines)" \
    "grep -vE '^[[:space:]]*(#|\$)' /etc/ssh/sshd_config 2>/dev/null | head -25"

# =========================================================================
sec "7. PERSISTENCE (the highest-signal malware surface on macOS)"
run "Third-party LaunchDaemons/LaunchAgents — inventory" \
    "ls -la /Library/LaunchDaemons /Library/LaunchAgents \"\$HOME/Library/LaunchAgents\" 2>&1"

printf '\n### Persistence items resolved to their executable + code signature\n'
printf '$ for each plist in /Library/Launch{Daemons,Agents} and ~/Library/LaunchAgents: PlistBuddy -> codesign\n'
for d in /Library/LaunchDaemons /Library/LaunchAgents "$HOME/Library/LaunchAgents"; do
  [ -d "$d" ] || continue
  for f in "$d"/*.plist; do
    [ -e "$f" ] || continue
    prog=$(/usr/libexec/PlistBuddy -c 'Print :Program' "$f" 2>/dev/null)
    [ -z "$prog" ] && prog=$(/usr/libexec/PlistBuddy -c 'Print :ProgramArguments:0' "$f" 2>/dev/null)
    runatload=$(/usr/libexec/PlistBuddy -c 'Print :RunAtLoad' "$f" 2>/dev/null)
    if [ -n "$prog" ] && [ -e "$prog" ]; then
      auth=$(codesign -dv --verbose=2 "$prog" 2>&1 | grep -E '^(Authority|TeamIdentifier)=' | head -2 | tr '\n' ' ')
      [ -z "$auth" ] && auth="*** NO VALID SIGNATURE ***"
      notar=$(spctl -a -vv -t execute "$prog" 2>&1 | tail -1)
    else
      auth="(executable not found / not resolvable)"
      notar=""
    fi
    printf '  %s\n      exec      : %s\n      RunAtLoad : %s\n      signature : %s\n      gatekeeper: %s\n' \
      "$f" "${prog:-<none>}" "${runatload:-<unset>}" "$auth" "${notar:-n/a}"
  done
done
note "Only the executable PATH from each plist is printed — full ProgramArguments are suppressed because they sometimes embed tokens."

run "User-domain launchd jobs not published by Apple" \
    "launchctl list 2>/dev/null | grep -viE 'com\.apple\.|^PID' | head -30"
run "Login items database location (contents need root — see sudo script)" \
    "ls -la \"\$HOME/Library/Application Support/com.apple.backgroundtaskmanagementagent\" 2>&1"
run "Startup items (legacy) and emond" \
    "ls -la /Library/StartupItems /etc/emond.d/rules 2>&1 | head -15"
run "Cron jobs for this user  [REVIEW BEFORE SHARING]" "crontab -l 2>&1 | cut -c1-160"
run "System cron and periodic scripts" \
    "ls -la /etc/cron* /usr/lib/cron/tabs 2>&1 | head -20; ls /etc/periodic/*/ 2>/dev/null | head -20"
run "at jobs" "ls -la /var/at/jobs 2>&1 | head -10"

run "Shell startup files — metadata + suspicious-pattern COUNTS only (never printed)" \
    "for f in \"\$HOME\"/.zshrc \"\$HOME\"/.zprofile \"\$HOME\"/.zshenv \"\$HOME\"/.bash_profile \"\$HOME\"/.bashrc \"\$HOME\"/.profile /etc/zshenv /etc/zprofile /etc/bashrc; do [ -f \"\$f\" ] || continue; printf '%-38s mode=%s mtime=%s  net/eval hits=%s\n' \"\$f\" \"\$(stat -f '%Lp' \"\$f\")\" \"\$(stat -f '%Sm' -t '%Y-%m-%d' \"\$f\")\" \"\$(grep -cE 'curl|wget|base64 -d|eval |osascript|nc ' \"\$f\" 2>/dev/null)\"; done"
run "Shell startup files that EXPORT credentials (filenames only, via grep -l)" \
    "grep -lE 'export[[:space:]]+[A-Za-z_]*(KEY|TOKEN|SECRET|PASSWORD|PASSWD|MNEMONIC|PRIVATE)' \"\$HOME\"/.zshrc \"\$HOME\"/.zprofile \"\$HOME\"/.zshenv \"\$HOME\"/.bash_profile \"\$HOME\"/.bashrc 2>/dev/null || echo 'none'"
note "grep -l prints filenames only — the matching lines and their values are never emitted."

run "Loaded third-party kernel extensions" \
    "kextstat 2>/dev/null | grep -v com.apple | head -20; echo '--- kmutil ---'; kmutil showloaded --no-kernel-components 2>&1 | grep -v com.apple | head -20"
run "Installed system extensions (network filters, endpoint security)" \
    "systemextensionsctl list 2>&1 | head -30"
note "A third-party NEFilter/NetworkExtension can see all your traffic; an EndpointSecurity extension can see every process and file event."

# =========================================================================
sec "8. TRUST STORE, CERTIFICATES & MANAGEMENT PROFILES"
run "Keychains in this user's search list (paths only)" "security list-keychains 2>&1"
run "User-modified certificate TRUST SETTINGS (admin domain) — cert names only" \
    "security dump-trust-settings -d 2>&1 | head -40"
run "User-modified certificate TRUST SETTINGS (user domain) — cert names only" \
    "security dump-trust-settings 2>&1 | head -40"
note "A root CA you did not install, marked 'Always Trust', is a full TLS interception capability: the holder of its key reads and rewrites your HTTPS, including exchange APIs and wallet RPC endpoints. This dump prints certificate NAMES and trust flags only — no keys."
run "Non-Apple root CAs in the SYSTEM trust store (labels only, count first)" \
    "printf 'total certs in SystemRootCertificates: '; security find-certificate -a /System/Library/Keychains/SystemRootCertificates.keychain 2>/dev/null | grep -c 'labl'; echo '--- certs added to the System keychain (should normally be empty) ---'; security find-certificate -a /Library/Keychains/System.keychain 2>/dev/null | grep '\"labl\"' | head -20"
run "Configuration profiles / MDM enrolment" \
    "profiles status -type enrollment 2>&1; echo '---'; ls -la '/Library/Managed Preferences' 2>&1 | head -15"
note "Full profile payload listing needs root — see macos-audit-sudo.sh (profiles list -all)."

# =========================================================================
sec "9. SECRET EXPOSURE ON DISK  — PATHS, MODES AND COUNTS ONLY"
cat <<'EOF'

  Everything in this section is metadata. No file in this section is opened
  and no content is printed. What you get: path, octal mode, owner, size,
  and where a content test is unavoidable, a COUNT of matches.

EOF

run "SSH private keys — passphrase protection test (never prints key material)" \
    "for k in \"\$HOME\"/.ssh/id_* \"\$HOME\"/.ssh/*.pem; do case \"\$k\" in *.pub) continue;; esac; [ -f \"\$k\" ] || continue; if ssh-keygen -y -P '' -f \"\$k\" >/dev/null 2>&1; then st='*** NO PASSPHRASE — usable the instant it is copied ***'; else st='passphrase-protected or not a private key'; fi; printf '%-46s mode=%s  %s\n' \"\$k\" \"\$(stat -f '%Lp' \"\$k\")\" \"\$st\"; done 2>/dev/null || echo 'no ssh keys found'"
note "ssh-keygen -y derives the PUBLIC key to test decryptability; its output is discarded to /dev/null. The private key never reaches this transcript."

run "~/.ssh directory and file permissions" "ls -la \"\$HOME/.ssh\" 2>&1"

run "THIS repo's wallet-key residue (bitget-wallet-skill leaves these on crash)" \
    "for n in .pk_evm .pk_sol .social-wallet-secret .mnemonic; do find \"\$HOME\" -maxdepth 6 -name \"\$n\" -type f -not -path '*/.Trash/*' 2>/dev/null | while IFS= read -r f; do printf '%-60s mode=%s owner=%s size=%s\n' \"\$f\" \"\$(stat -f '%Lp' \"\$f\")\" \"\$(stat -f '%Su' \"\$f\")\" \"\$(stat -f '%z' \"\$f\")\"; done; done; echo '(empty result = no leftover key files, which is the desired state)'"
note "key_utils.py:read_key_file() unlinks these immediately after reading. Any that still exist are crash residue from an interrupted signing run — a plaintext private key sitting in your home directory."

run "Wallet / keystore directories (existence, mode, file count — never opened)" \
    "for p in \"\$HOME/.config/solana\" \"\$HOME/.ethereum/keystore\" \"\$HOME/Library/Ethereum/keystore\" \"\$HOME/.electrum\" \"\$HOME/Library/Application Support/Electrum\" \"\$HOME/Library/Application Support/Exodus\" \"\$HOME/Library/Application Support/Ledger Live\" \"\$HOME/Library/Application Support/Trezor Suite\" \"\$HOME/Library/Application Support/Bitcoin\" \"\$HOME/wallet\"; do [ -e \"\$p\" ] || continue; printf '%-56s mode=%s  files=%s\n' \"\$p\" \"\$(stat -f '%Lp' \"\$p\")\" \"\$(ls -1 \"\$p\" 2>/dev/null | wc -l | tr -d ' ')\"; done; echo '(no output = none of these wallet stores present)'"
run "Solana CLI default keypair (unencrypted JSON by design)" \
    "ls -l \"\$HOME/.config/solana/id.json\" 2>&1"
note "~/.config/solana/id.json is an UNENCRYPTED secret key array. File-read access to it is fund-transfer access — no passphrase step exists."

run "Browser wallet extensions installed (directory existence only)" \
    "for prof in \"\$HOME/Library/Application Support/Google/Chrome\" \"\$HOME/Library/Application Support/BraveSoftware/Brave-Browser\" \"\$HOME/Library/Application Support/Microsoft Edge\"; do [ -d \"\$prof\" ] || continue; find \"\$prof\" -maxdepth 3 -type d \\( -name 'nkbihfbeogaeaoehlefnkodbefgpgknn' -o -name 'bfnaelmomeimhlpmgjnjophhpkkoljpa' -o -name 'jiidiaalihmmhddjgbnbgdfflelocpak' -o -name 'hnfanknocfeofbddgcijnmhnfnkdnaad' \\) 2>/dev/null | sed 's|'\"\$HOME\"'|~|'; done; echo '(ids: MetaMask / Phantom / Bitget Wallet / Coinbase Wallet)'"

run "Cloud-credential files (paths + modes only)" \
    "for p in \"\$HOME/.aws/credentials\" \"\$HOME/.config/gcloud/credentials.db\" \"\$HOME/.kube/config\" \"\$HOME/.npmrc\" \"\$HOME/.pypirc\" \"\$HOME/.netrc\" \"\$HOME/.git-credentials\" \"\$HOME/.docker/config.json\"; do [ -f \"\$p\" ] || continue; printf '%-48s mode=%s size=%s\n' \"\$p\" \"\$(stat -f '%Lp' \"\$p\")\" \"\$(stat -f '%z' \"\$p\")\"; done; echo '(no output = none present)'"

run ".env files in your working directories — PATHS AND MODES ONLY, never opened" \
    "find \"\$HOME\" -maxdepth 5 -type f -name '.env*' -not -path '*/node_modules/*' -not -path '*/.git/*' -not -path '*/Library/*' -not -path '*/.Trash/*' 2>/dev/null | head -40 | while IFS= read -r f; do printf '%-70s mode=%s\n' \"\$(echo \"\$f\" | sed 's|'\"\$HOME\"'|~|')\" \"\$(stat -f '%Lp' \"\$f\")\"; done; echo '--- count ---'; find \"\$HOME\" -maxdepth 5 -type f -name '.env*' -not -path '*/node_modules/*' -not -path '*/Library/*' 2>/dev/null | wc -l"

run "Group/world-readable secret files (the actual exposure, not the mere existence)" \
    "find \"\$HOME\" -maxdepth 5 -type f \\( -name '.env*' -o -name 'id_rsa' -o -name 'id_ed25519' -o -name 'id_ecdsa' -o -name '*.pem' -o -name '*.p12' -o -name '.pk_*' -o -name '.mnemonic' -o -name '.social-wallet-secret' \\) -not -path '*/node_modules/*' -not -path '*/Library/*' -not -path '*/.Trash/*' -perm +044 2>/dev/null | head -30 | sed 's|'\"\$HOME\"'|~|'; echo '(no output = nothing secret is group/world-readable, which is correct)'"

run "Secrets sitting inside cloud-synced folders (exfiltration by sync)" \
    "SYNCED=''; for d in \"\$HOME/Library/Mobile Documents/com~apple~CloudDocs\" \"\$HOME/Dropbox\" \"\$HOME/Google Drive\" \"\$HOME/OneDrive\" \"\$HOME/Library/CloudStorage\"; do [ -d \"\$d\" ] && SYNCED=\"\$SYNCED \$d\"; done; echo \"sync roots present:\$SYNCED\"; echo '--- iCloud Desktop & Documents sync active? ---'; ls -d \"\$HOME/Library/Mobile Documents/com~apple~CloudDocs/Desktop\" \"\$HOME/Library/Mobile Documents/com~apple~CloudDocs/Documents\" 2>&1; echo '--- secret-shaped files under sync roots ---'; for d in \$SYNCED; do find \"\$d\" -maxdepth 4 -type f \\( -name '.env*' -o -name 'id_rsa' -o -name 'id_ed25519' -o -name '*.pem' -o -name '.pk_*' -o -name '.mnemonic' -o -name '*.key' \\) 2>/dev/null | head -15 | sed 's|'\"\$HOME\"'|~|'; done"
note "If iCloud Desktop & Documents sync is on, anything under ~/Desktop or ~/Documents has been uploaded to Apple and to every other device on that Apple ID."

run "Private key material in shell history — MATCH COUNTS ONLY, never the lines" \
    "for h in \"\$HOME\"/.zsh_history \"\$HOME\"/.bash_history \"\$HOME\"/.local/share/fish/fish_history; do [ -f \"\$h\" ] || continue; evm=\$(grep -cE '0x[0-9a-fA-F]{64}' \"\$h\" 2>/dev/null); b58=\$(grep -cE '[1-9A-HJ-NP-Za-km-z]{86,90}' \"\$h\" 2>/dev/null); words=\$(grep -ciE '(mnemonic|seed phrase|private.?key|--privkey|PRIVATE_KEY=)' \"\$h\" 2>/dev/null); printf '%-44s mode=%s  64-hex-hits=%s  base58-88-hits=%s  keyword-hits=%s\n' \"\$h\" \"\$(stat -f '%Lp' \"\$h\")\" \"\$evm\" \"\$b58\" \"\$words\"; done"
note "Counts only. A nonzero 64-hex or base58-88 count means raw key material is very likely sitting in plaintext shell history — this repo's own docs/swap.md warns against passing keys as CLI arguments precisely because of this."

run "AI assistant session/transcript directories (existence and size only, never read)" \
    "for p in \"\$HOME/.claude\" \"\$HOME/.cursor\" \"\$HOME/.aider.chat.history.md\" \"\$HOME/.codeium\" \"\$HOME/.continue\"; do [ -e \"\$p\" ] || continue; printf '%-32s mode=%s  size=%s\n' \"\$(echo \"\$p\" | sed 's|'\"\$HOME\"'|~|')\" \"\$(stat -f '%Lp' \"\$p\")\" \"\$(du -sh \"\$p\" 2>/dev/null | awk '{print \$1}')\"; done; echo '(contents deliberately not read — transcripts routinely contain pasted secrets)'"

# =========================================================================
sec "10. PATCH POSTURE"
run "Automatic update settings" \
    "defaults read /Library/Preferences/com.apple.SoftwareUpdate 2>&1 | head -30; echo '--- app store autoupdate ---'; defaults read /Library/Preferences/com.apple.commerce AutoUpdate 2>&1"
run "Rapid Security Response / last updates installed" \
    "sw_vers -productVersion; system_profiler SPInstallHistoryDataType 2>/dev/null | grep -B1 -A3 -iE 'XProtect|MRT|Gatekeeper|Security' | head -40"
if [ "$WANT_UPDATES" = "1" ]; then
  run "Pending updates from Apple (network)" "softwareupdate --list 2>&1 | head -25"
else
  printf '\n### Pending updates\n  SKIPPED — re-run with --updates to query Apple (slow, requires network)\n'
fi

# =========================================================================
sec "11. APPLICATION INVENTORY (signing status of installed apps)"
if [ "$QUICK" = "0" ]; then
  printf '\n### /Applications — apps that FAIL Gatekeeper assessment\n'
  printf '$ for each app in /Applications: spctl -a -vv\n'
  found=0
  for app in /Applications/*.app; do
    [ -e "$app" ] || continue
    res=$(spctl -a -vv -t execute "$app" 2>&1 | tail -2 | tr '\n' ' ')
    case "$res" in
      *accepted*) : ;;
      *) printf '  %-52s %s\n' "$(basename "$app")" "$res"; found=1 ;;
    esac
  done
  [ "$found" = "0" ] && printf '  (all apps in /Applications pass Gatekeeper assessment)\n'
  run "Apps installed outside /Applications (common for droppers)" \
      "ls -la \"\$HOME/Applications\" /usr/local/bin 2>&1 | head -25"
else
  printf '\n### Application inventory\n  SKIPPED (--quick)\n'
fi

printf '\n\n===============================================================\n'
printf '== END OF AUDIT — %s\n' "$(date)"
printf '===============================================================\n'
printf '\nReminder: no key material, keychain contents, .env contents, wallet\n'
printf 'files, browser password stores or AI transcripts were read or printed\n'
printf 'by this script. Only paths, modes, sizes and match counts.\n'

}

main 2>&1 | tee "$OUT"
printf '\n>>> Saved to: %s\n' "$OUT"
printf '>>> Review it, redact anything you object to, then share that file.\n'
