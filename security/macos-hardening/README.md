# macOS hardening audit toolkit

Read-only evidence collection for a security review of a Mac, plus a reversible
quarantine helper for whatever the review turns up.

**Why this exists as scripts instead of a report:** the review was requested in a
Claude Code session running in an ephemeral Linux container in the cloud. That
session had no access to the Mac under review — no `csrutil`, no `fdesetup`, no
`/Applications`. Rather than guess at findings, the audit was packaged so it runs
on the actual machine and returns real evidence.

## The three files you run

| Script | Privilege | What it does |
|---|---|---|
| `verify-readonly.sh` | none | Proves the other scripts only read. Run this **first**. |
| `macos-audit.sh` | your user | ~90% of the audit. Refuses to run as root. |
| `macos-audit-sudo.sh` | root | The ~12 checks that genuinely need it. Short enough to read in full. |
| `quarantine.sh` | as needed | Reversible removal. Only for the remediation phase — not now. |

## Order of operations

```sh
cd security/macos-hardening

# 1. Verify the claims before trusting the scripts.
bash verify-readonly.sh

# 2. Main audit — as you, NOT with sudo.
bash macos-audit.sh
#    add --updates to also query Apple for pending patches (slow, network)
#    add --quick   to skip the slow system_profiler and filesystem sweeps

# 3. The root-only remainder. Read it first — it is ~100 lines.
sudo bash macos-audit-sudo.sh
```

Each writes a transcript to your home directory:
`~/macos-audit-<host>-<timestamp>.txt` and `~/macos-audit-sudo-<timestamp>.txt`.

**Skim before sharing.** Sections that most often want redaction are tagged
`[REVIEW BEFORE SHARING]`. The transcripts contain your username, hostname, local
account names, installed software paths, `/etc/hosts` entries and crontab lines.

## Guarantees, and how to check them yourself

**Read-only.** No `defaults write`, no `csrutil enable/disable`, no `launchctl
bootout`, no `chmod`, no `rm`, no `mv`. Binaries like `csrutil`, `spctl` and
`nvram` do appear, but only in read-only forms (`csrutil status`, `spctl
--status`, `nvram boot-args`). `verify-readonly.sh` scans for every
state-changing form and includes a negative control, so you can confirm the
detector actually fires instead of silently matching nothing.

Expected output: `macos-audit.sh` → 0 hits. `macos-audit-sudo.sh` → exactly 1
hit, a disclosed `chown` on its own output transcript so the file ends up owned
by you rather than by root. Negative control → 6 caught.

**No secrets in the transcript.** The audit never prints the contents of private
keys, `.env` files, keychains, wallet files, mnemonics, browser password stores
or AI session transcripts. Where those matter it emits only paths, octal modes,
byte sizes and match counts. Specifically:

- SSH keys are tested for passphrase protection with `ssh-keygen -y -P ''`, whose
  output is discarded — it reports *encrypted / not encrypted*, never key bytes.
- Shell history is checked with `grep -c` for 64-hex and base58 key shapes. You
  get a count, never a line.
- Shell startup files are checked with `grep -l` for exported credentials. You
  get a filename, never the value.
- `/etc/kcpassword` is reported by `ls` only. Its existence is the finding; the
  file is never read.
- The Find My Mac nvram token is reported as a presence *count*, never a value.

The two deliberate exceptions are `/etc/hosts` and `crontab`, where the attack
*is* the content. Both are tagged `[REVIEW BEFORE SHARING]`.

**Nothing is deleted, ever.** `quarantine.sh` contains no `rm` at all — verified
by `verify-readonly.sh`. It moves items to `~/Security-Quarantine-<timestamp>/`,
preserving the original directory structure, and writes:

- `MANIFEST.tsv` — original path, quarantined path, mode, owner, group, size,
  SHA-256, timestamp
- `restore.sh` — puts everything back and verifies each file against its recorded
  hash

The quarantine root is in your home directory, deliberately **not** on the Desktop
and **not** in Documents, since both are uploaded to Apple when iCloud "Desktop &
Documents" sync is on. The script refuses to run if its own root would land inside
any cloud-synced path.

```sh
bash quarantine.sh /path/to/thing              # DRY RUN — default, moves nothing
bash quarantine.sh --commit /path/to/thing     # actually move
bash ~/Security-Quarantine-*/restore.sh        # undo everything
```

Safety guards, all exercised by test:

- refuses `/`, `/System`, `/Library`, `/etc`, `/usr`, `/Applications`, your home
  directory, and `~/Library/LaunchAgents`
- refuses any **directory** less than three levels deep, which covers the whole
  class rather than an enumerable list — individual files at any depth are fine
- refuses to overwrite anything already at the destination
- for `.plist` files it *prints* the `launchctl bootout` command rather than
  running it — unloading a job is a state change and stays your decision

## What this toolkit does not do

It does not decide anything. It collects evidence. Interpretation — which
findings are real, which have a genuine exploit path, and which are noise — is
the next phase, and it needs the transcript plus context on what actually lives
on the machine.
