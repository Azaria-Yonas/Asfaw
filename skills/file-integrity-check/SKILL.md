---
name: file-integrity-check
description: Use to verify monitored host files against their baseline hashes — /etc/passwd, /etc/shadow, sudoers, sshd_config, key binaries. Runs during heartbeat file-integrity rotation and on demand. When no baseline exists, falls back to package-manager verification and universal red-flag checks.
user-invocable: false
---

# File Integrity Check

Use this skill to detect unauthorized modification of host-critical files. The
canonical attack it catches: an attacker who edits `/etc/passwd` to add a uid-0
account, plants an SSH key, or swaps a system binary for a trojaned one.

This is the heartbeat "file integrity" rotation check. It has two modes —
baseline-diff (preferred) and baseline-free (for hosts like ubuntu2 where you
walked into an already-running system).

## Mode A — Baseline Diff (when TOOLS.md has hashes)

1. For each monitored path in TOOLS.md "Monitored Paths", recompute and compare:
   ```bash
   while IFS= read -r path; do
     test -e "$path" || { echo "MISSING: $path"; continue; }
     printf '%s  %s\n' "$(sha256sum "$path" | awk '{print $1}')" "$path"
   done < memory/monitored-paths.txt
   ```
2. Compare each hash to the baseline value in TOOLS.md.
   - **Match** → clean, no output.
   - **Mismatch** → alert (critical), unless it maps to an approved change in
     `/var/log/apt/history.log` within the window.
   - **Missing file that should exist** → alert (critical) — deletion of a
     monitored file is as suspicious as modification.
3. Also compare metadata, not just content:
   ```bash
   stat -c '%n %s %Y %U:%G %a' "$path"
   ```
   Owner/mode change without content change still matters (e.g., `/etc/shadow`
   becoming world-readable).

## Mode B — Baseline-Free Verification (no stored hashes)

When there is no trusted baseline, you cannot diff — but package-owned files
have a *distribution* reference you can verify against.

```bash
# Verify package-owned files against the distro's own manifest.
# Reports files whose hash/size/perms drifted from what the package shipped.
sudo debsums -c 2>/dev/null            # '-c' = only changed files
# If debsums absent:
dpkg --verify 2>/dev/null              # '5' in col 3 = md5 mismatch
```
- Any `5` (checksum) flag on a binary under `/usr/bin`, `/usr/sbin`, `/bin`,
  `/sbin`, or a config under `/etc` that the package owns → alert. A
  package-owned binary that no longer matches the package is a classic trojan
  tell.
- Config files (`/etc/...`) legitimately drift (admins edit them) — weight
  binary mismatches far higher than config mismatches.

Combine with the universal red flags from `INVARIANTS.md` (ld.so.preload,
duplicate uid-0, world-writable system binaries) which need no baseline at all.

## Detection Rules (both modes)

- **uid-0 account besides root** — `awk -F: '$3==0 {print $1}' /etc/passwd` must
  return only `root`. Anything else = critical.
- **New entries in authorized_keys** — for each home + `/root`, count keys; an
  increase without an approved change = alert.
- **sudoers / sudoers.d changes** — NOPASSWD grants or new entries = critical.
- **sshd_config drift toward weakness** — `PermitRootLogin yes`,
  `PasswordAuthentication yes` where baseline had them off = alert.
- **setuid/setgid drift** — new SUID/SGID binaries vs baseline set = alert
  (hand detail to `privilege-escalation-detector`).

## Alert Format

```
[INTEGRITY ALERT - {severity}]
Path: <file>
Change: <content-mismatch | owner-change | mode-change | missing | new-suid>
Baseline: <stored hash/meta or "package-shipped value">
Current: <observed hash/meta>
Approved change in window? <yes+ref | no>
Recommendation: <investigate | hand off to incident-response>
```

## Report Real Blockers

- Root-only files (`/etc/shadow`, `/etc/sudoers`) unreadable because heartbeat
  runs non-interactively without sudo — note the gap explicitly; do not report
  "clean" for a file you could not read. (Your baseline.md already flags this.)
- `debsums`/`dpkg --verify` unavailable AND no baseline → you can only run the
  invariant checks; say so.

## Ubuntu-Specific Notes

- `debsums` may not be installed by default: `apt-get install debsums`. Without
  it, `dpkg --verify` is the fallback but covers fewer files.
- `/etc/passwd`, `/etc/group` change on legitimate package installs that add
  system users — cross-check `/var/log/apt/history.log` before alerting.
- Snap and unattended-upgrades rewrite files on their own schedule; large hash
  churn under `/snap/` is expected.

## What This Skill Does NOT Do

Detects and reports drift. Does not restore files (that is operator/`harden`
work — auto-restoring from a stored copy is itself an attack surface). Does not
update the baseline on observed drift — only `baseline-scan` does that, with
operator confirmation.
