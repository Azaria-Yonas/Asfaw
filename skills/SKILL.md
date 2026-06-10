---
name: auth-log-monitor
description: Use when checking authentication events on the host — failed logins, sudo usage, ssh sessions, new account creation. Runs during heartbeat auth rotation and on demand when the operator asks about login activity.
user-invocable: false
---

# Auth Log Monitor

Use this skill when you need to inspect authentication activity on the Ubuntu host. Primary source is `/var/log/auth.log`. On systemd-only hosts where auth.log is absent, fall back to `journalctl -u ssh -u sudo`.

## Operating Loop

1. Check log availability before reading:
   - `test -r /var/log/auth.log && echo READABLE || echo MISSING` — confirms the file exists and you can read it.
   - If MISSING, fall back to `journalctl _COMM=sshd _COMM=sudo --since "..."` instead.
   - If neither is available, stop and report the host has no usable auth source. Do not pretend the check succeeded.

2. Find your delta window:
   - Read `memory/heartbeat-state.json` for `lastChecks.auth_log` (unix timestamp).
   - If missing, default to the last 30 minutes.
   - Read only log lines since that timestamp. Do not re-scan the whole file every heartbeat — it is wasteful and produces duplicate alerts.

3. Pull the slice:
   ```bash
   awk -v since="$(date -d @$LAST_CHECK '+%b %d %H:%M:%S')" \
       '$0 >= since' /var/log/auth.log
   ```
   Or, more reliably with journalctl:
   ```bash
   journalctl _COMM=sshd _COMM=sudo --since "@$LAST_CHECK" --no-pager
   ```

4. Apply detection rules (in order, stop at first match per session):
   - **Failed sudo** — `grep "sudo.*authentication failure"` — count per uid in window. Threshold: >3 in 5 min = alert.
   - **SSH from new IP** — `grep "Accepted.*from"` extract source IP, compare against known-good list in TOOLS.md → unknown = alert (informational).
   - **SSH brute force** — `grep "Failed password"` count per source IP. Threshold: >10 in 10 min = alert (critical).
   - **New user account** — `grep "new user"` or `grep "useradd"` → any match = alert (critical).
   - **Password change** — `grep "password changed"` → any match = alert (informational).
   - **Root shell opened** — `grep "session opened.*user root"` outside the expected admin hours window from USER.md → alert.

5. Update state and report:
   - Write the timestamp of the newest line you processed to `memory/heartbeat-state.json` under `lastChecks.auth_log`.
   - Append findings (verified facts only) to `memory/YYYY-MM-DD.md`.
   - If no rule fired, respond `HEARTBEAT_OK` and exit.
   - If a rule fired, send a structured alert to the operator (see "Alert Format" below) and stop. Do not take action.

## Alert Format

```
[AUTH ALERT - {severity}]
What: <one line, what was observed>
Source: /var/log/auth.log lines {N-M}
Evidence: <3 lines max, quoted>
When: <timestamp range>
Recommendation: <suggested next step>
```

Severity is `informational`, `warning`, or `critical` based on rule thresholds above.

## Log Rotation Recovery

`/var/log/auth.log` rotates (typically daily, with `.1`, `.2.gz`, etc.). If your last-check timestamp is older than the current file's earliest entry:

1. Note the gap in your alert ("auth.log rotated between checks, scanned auth.log.1 to fill the gap").
2. Scan `/var/log/auth.log.1` (and `.2.gz` via `zcat` if needed) for entries in the gap window.
3. Combine results with the current file before applying detection rules.
4. Do not skip the rotated portion silently — that creates a blind spot an attacker could exploit by timing activity around rotation.

## Report Real Blockers

Stop and tell the operator if:

- Auth log is missing AND journalctl returns nothing (host has no auth records — itself suspicious).
- File exists but is empty AND the host has been up for >1 hour (someone may have wiped it).
- File mtime is older than the last entry inside it (timestamps tampered).
- You see a rule fire but cannot read the surrounding lines for context.

Do not investigate further on your own past these blockers. Report and wait.

## Ubuntu-Specific Notes

- On Ubuntu 22.04+, sudo events also go to `/var/log/auth.log` by default but some hardened configs route them to a separate file via rsyslog rules. If you see no sudo events but `id` shows sudo is in use, check `/etc/rsyslog.d/` for redirection.
- `journald` may have a different retention window than the on-disk file. Prefer the on-disk file as the source of truth, use journalctl only as a fallback.
- `fail2ban` may already be acting on brute-force sources. Check `/var/log/fail2ban.log` before recommending a manual block — do not double-block.

## What This Skill Does NOT Do

This skill observes and alerts. It does not block IPs, kill sessions, or modify firewall rules. If response action is needed, hand off to `incident-response`. That separation is deliberate — observation must never have the power to act, because an injection through log content could otherwise weaponize it.
