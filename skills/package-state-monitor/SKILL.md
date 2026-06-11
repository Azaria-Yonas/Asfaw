---
name: package-state-monitor
description: Use to detect unexpected package installs, removals, downgrades, or held packages on the host. Runs during heartbeat package-state rotation and on demand. Cross-references apt history so legitimate updates don't alert.
user-invocable: false
---

# Package State Monitor

Use this skill to catch software changes an attacker makes to establish
capability or persistence: installing `netcat`/`socat`/compilers on a hardened
box, downgrading a package to a vulnerable version, or removing a security
agent. This is the heartbeat "package state" rotation check.

## Operating Loop

1. Snapshot current package set:
   ```bash
   dpkg -l | awk '/^ii/ {print $2"="$3}' | sort > /tmp/pkg-now.txt
   ```
2. Diff against the baseline (`memory/package-baseline.txt`):
   ```bash
   # Installed or upgraded since baseline
   comm -13 memory/package-baseline.txt /tmp/pkg-now.txt
   # Removed since baseline
   comm -23 memory/package-baseline.txt /tmp/pkg-now.txt
   ```
   If no baseline exists yet, record the current set as a provisional reference
   (mark it provisional — it is NOT operator-confirmed) and skip alerting this
   round.
3. Attribute every change to apt history before alerting:
   ```bash
   grep -E "Install|Upgrade|Remove|Downgrade" /var/log/apt/history.log \
     /var/log/apt/history.log.1 2>/dev/null
   zgrep -hE "Install|Upgrade|Remove|Downgrade" /var/log/apt/history.log.*.gz 2>/dev/null
   ```
   - A change that maps to a logged apt transaction by the operator or
     `unattended-upgrades` = legitimate, log only.
   - A change with **no corresponding apt history entry** = critical. Packages
     don't install themselves; a binary appearing outside apt's record suggests
     manual `dpkg -i`, a compromised mirror, or direct file placement.

## Detection Rules

- **Suspicious-capability install** — packages that expand attacker reach on a
  server that shouldn't need them: `netcat*`, `socat`, `ncat`, `nmap`, `tcpdump`,
  `gcc`/`g++`/`clang`, `python3-dev`, `ruby`, `php-cli`, `tor`, `proxychains`,
  `masscan`. Cross-check against USER.md "Services intended to be running" —
  a build toolchain on a web server is a finding; on a dev box it's normal.
- **Downgrade** — version went backwards. Attackers downgrade to reach a known
  CVE. Always alert; hand the package+version to `vulnerability-scanner`.
- **Security-agent removal** — `auditd`, `apparmor`, `fail2ban`, `ufw`,
  `unattended-upgrades`, `clamav`, any EDR package disappearing = critical.
- **Held packages** — `apt-mark showhold`. A security package pinned to an old
  version is a quiet way to block patching.
- **Foreign-origin packages** — `apt-cache policy <pkg>` showing an unexpected
  repository for a core package.

## Alert Format

```
[PACKAGE ALERT - {severity}]
Change: <install | remove | downgrade | hold | foreign-origin>
Package: <name> <old_ver> -> <new_ver>
Attributed to apt history? <yes+timestamp | NO — unattributed>
Why suspicious: <one sentence>
Recommendation: <observe | scan version for CVEs | hand off to incident-response>
```

## Report Real Blockers

- `/var/log/apt/history.log` empty or missing on a host with installed packages
  → either fresh log rotation or tampering; note it and check `.1`/`.gz`.
- `dpkg` database lock held (apt running) → wait and retry; don't snapshot a
  mid-transaction state.

## Ubuntu-Specific Notes

- `unattended-upgrades` installs security patches on its own; its actions appear
  in `/var/log/unattended-upgrades/` and apt history. Treat as legitimate but
  hand new versions to `vulnerability-scanner` to confirm they actually closed
  the CVE rather than introduced a regression.
- Snap packages are outside dpkg. Track them separately:
  `snap list` and `snap changes`.
- `apt list --upgradable` shows pending patches — surface the count during this
  check so the operator sees patch debt accumulating.

## What This Skill Does NOT Do

Observes package state. Does not install, remove, or patch anything — that is
`harden`/`incident-response` with operator confirmation. Does not auto-update the
baseline; new legitimate packages get confirmed via `baseline-scan`.
