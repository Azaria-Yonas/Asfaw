---
name: log-tamper-detector
description: Use to detect anti-forensic activity — truncated/cleared logs, wtmp/lastlog/journal manipulation, timestamp inconsistencies, and disabled logging. Runs on demand and as a cross-check whenever other checks look suspiciously clean. A clean log on a busy host can itself be the finding.
user-invocable: true
---

# Log Tamper Detector

Use this skill to check whether the host's own records can be trusted. Every
other observation skill reads logs; if an attacker has cleared or edited them,
those skills report a false "all clear." This skill audits the *integrity of the
evidence layer itself*.

The governing intuition: **on an active host, logs grow. Logs that are empty,
truncated, or frozen are anomalies, not reassurance.**

## Operating Loop

### Emptiness / truncation on an active host
```bash
uptime    # how long has the host been up? long uptime + empty logs = suspicious
for f in /var/log/auth.log /var/log/syslog /var/log/kern.log; do
  test -e "$f" && printf '%s size=%s mtime=%s\n' "$f" \
    "$(stat -c %s "$f")" "$(stat -c %y "$f")"; done
# A 0-byte auth.log on a host up for days, or one that stops mid-day, is a flag.
```

### Timestamp / continuity inconsistencies
```bash
# File mtime older than the newest entry inside it (timestamps rewritten)
newest=$(tail -1 /var/log/auth.log 2>/dev/null)
ls -la --time-style=full-iso /var/log/auth.log
# Gaps: hours with zero entries during known-active periods
awk '{print $1, $2, $3}' /var/log/auth.log 2>/dev/null | uniq -c | tail
# Out-of-order timestamps within a file (insertion/editing tell)
```

### Login-record manipulation
```bash
last -20                      # reads wtmp
lastb -20 2>/dev/null         # reads btmp (failed logins)
lastlog | head                # per-user last login
who -a
# wtmp/btmp existence + size; attackers truncate these to hide sessions
ls -la /var/log/wtmp /var/log/btmp /var/log/lastlog 2>/dev/null
# 'last' showing a reboot or gap that doesn't match uptime = wtmp edited
```

### Journal integrity (systemd)
```bash
journalctl --verify 2>&1 | tail        # FAIL = corrupted/tampered journal
journalctl --disk-usage
# Has the journal been vacuumed recently (logs deliberately purged)?
journalctl --list-boots | tail
# Rsyslog / journald actually running and writing?
systemctl is-active rsyslog systemd-journald
```

### Logging-disabled tells
```bash
# Was logging stopped or reconfigured to /dev/null?
grep -RsE '/dev/null|stop|~' /etc/rsyslog.conf /etc/rsyslog.d/ 2>/dev/null
# auditd present but disabled?
command -v auditctl >/dev/null && auditctl -s 2>/dev/null | grep -E 'enabled|pid'
# History disabled (attacker covering their own shell)
for r in /home/*/.bashrc /root/.bashrc; do
  grep -lE 'HISTFILE=/dev/null|HISTSIZE=0|set \+o history|unset HISTFILE' "$r" \
    2>/dev/null; done
# Recently emptied history on an account that clearly did work
for h in /home/*/.bash_history /root/.bash_history; do
  test -e "$h" && [ ! -s "$h" ] && echo "EMPTY history: $h"; done
```

### Cross-check against other evidence
A truncated auth.log is more damning if `process-inspector` shows sshd sessions
or `network-observer` shows established SSH connections that auth.log doesn't
explain. Correlate: activity visible elsewhere but absent from the log that
should record it = strong tampering evidence.

## Triage

- **Critical** — `journalctl --verify` fails; wtmp/btmp truncated to 0 on an
  active host; auth.log frozen while SSH sessions are demonstrably active;
  logging service stopped without an approved change.
- **High** — history redirected to /dev/null in a shell rc; recent unexplained
  journal vacuum; timestamp out-of-order runs.
- **Informational** — normal log rotation (correlate with logrotate timing
  before alerting; rotation is not tampering).

## Alert Format

```
[LOG TAMPER ALERT - {severity}]
Target: <auth.log | wtmp | btmp | journal | rsyslog-config | history>
Anomaly: <empty-on-active-host | truncated | mtime<newest-entry | verify-fail | logging-disabled | gap>
Corroboration: <other evidence the log fails to explain>
Why suspicious: <one sentence>
Recommendation: <preserve current logs now | investigate | incident-response>
```

When tampering is suspected, **preserve what remains immediately** — copy the
current logs to `memory/` via `evidence-condenser` before they're further altered.

## Report Real Blockers

- Root needed to read btmp and some journal scopes — note coverage gaps.
- Distinguish rotation from deletion: a missing `auth.log` with a fresh
  `auth.log.1` is rotation; a missing `auth.log` with no rotated successor is
  deletion. Check before alerting.

## Ubuntu-Specific Notes

- Default logrotate rotates auth.log/syslog daily — a size drop at the rotation
  hour is normal. Know the schedule (`/etc/logrotate.d/rsyslog`).
- Some minimal/cloud Ubuntu images are journald-only with no `/var/log/auth.log`;
  on those, journal verify + `last` are your primary integrity signals, not the
  on-disk file's absence.
- `systemd-journald` can be volatile (RAM-only) by config — confirm storage mode
  in `/etc/systemd/journald.conf` before reading too much into a small journal.

## What This Skill Does NOT Do

Audits evidence integrity; does not rebuild or "fix" logs (you cannot restore
deleted evidence, and faking it is worse than its absence). Does not restart
logging services on its own — that is `incident-response`/operator. Preserving
surviving evidence is in scope; fabricating missing evidence never is.
