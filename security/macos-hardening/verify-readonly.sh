#!/bin/bash
# verify-readonly.sh — prove to yourself that the audit scripts only READ.
#
# Do not take my word for it. This scans macos-audit.sh and macos-audit-sudo.sh
# for every state-changing macOS command form I could think of, and reports any
# hit. It also runs a negative control against a file of known-bad lines, so you
# can see the detector actually fires rather than silently matching nothing.
#
# Expected result:
#   macos-audit.sh      -> 0 hits
#   macos-audit-sudo.sh -> exactly 1 hit, the disclosed `chown` on line ~97
#                          (hands the output transcript back to you so it is not
#                           left owned by root)
#   negative control    -> 6 hits
#
# Usage: bash verify-readonly.sh

set -u
cd "$(dirname "$0")" || exit 1

MUT='(^|[^#])\b(rm|mv|chmod|chown)[[:space:]]|defaults[[:space:]]+(write|delete)|launchctl[[:space:]]+(load|unload|bootout|bootstrap|enable|disable)|csrutil[[:space:]]+(enable|disable|clear)|spctl[[:space:]]+--(master|global)-(en|dis)able|systemsetup[[:space:]]+-set|sysadminctl[[:space:]]+-(addUser|deleteUser|guestAccount[[:space:]]+(on|off))|pmset[[:space:]]+-[abc][[:space:]]|nvram[[:space:]]+[^ -][^ ]*=|fdesetup[[:space:]]+(enable|disable)|profiles[[:space:]]+(install|remove|-I|-R)|security[[:space:]]+(add-trusted-cert|delete-certificate|import)|dscl[[:space:]]+\.[[:space:]]+-(create|delete|append)'

scan() {
  printf '\n== %s ==\n' "$1"
  if [ ! -f "$1" ]; then printf '  file not found\n'; return; fi
  hits=$(grep -nE "$MUT" "$1" | grep -vE '^[0-9]+:[[:space:]]*#')
  if [ -z "$hits" ]; then
    printf '  0 hits — no state-changing command forms found.\n'
  else
    printf '%s\n' "$hits" | sed 's/^/  HIT /'
    printf '  (%s hit(s))\n' "$(printf '%s\n' "$hits" | wc -l | tr -d ' ')"
  fi
}

printf '###############################################################\n'
printf '#  Read-only verification\n'
printf '###############################################################\n'
scan macos-audit.sh
scan macos-audit-sudo.sh

printf '\n== negative control (detector sanity check) ==\n'
TMP=$(mktemp "${TMPDIR:-/tmp}/verifyctl.XXXXXX") || exit 1
cat > "$TMP" <<'X'
csrutil disable
defaults write com.apple.foo bar -bool true
launchctl bootout system /Library/LaunchDaemons/x.plist
nvram boot-args="-arm64e_preview_abi"
spctl --master-disable
chmod 777 /etc/passwd
X
grep -nE "$MUT" "$TMP" | sed 's/^/  CAUGHT /'
printf '  expected: 6 caught. If fewer, the detector is broken — do not trust the scan above.\n'

printf '\n== no-delete check on quarantine.sh ==\n'
if grep -nE '(^|[^#[:alnum:]_])rm[[:space:]]' quarantine.sh | grep -vE '^[0-9]+:[[:space:]]*#'; then
  printf '  WARNING: found an rm in quarantine.sh — it is supposed to have none.\n'
else
  printf '  0 hits — quarantine.sh contains no rm. It only moves.\n'
fi
printf '\nDone.\n'
