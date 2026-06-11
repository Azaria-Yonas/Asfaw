---
name: persistence-hunter
description: Use to hunt attacker persistence mechanisms — the ways malware survives reboot and re-login. Sweeps cron, systemd units/timers, shell rc files, authorized_keys, LD_PRELOAD, PAM, init hooks, and more. Runs on demand and during deep investigations after a foothold is suspected.
user-invocable: true
---

# Persistence Hunter

Use this skill to find how an attacker stays. Initial access is loud and brief;
persistence is quiet and durable, and it is what turns one intrusion into an
ongoing one. There are many persistence locations on Linux — this skill sweeps
the common-to-obscure set systematically so none is forgotten.

Most checks work **without a baseline** (the mechanism is suspicious by nature),
but cross-referencing USER.md "known scheduled jobs" and approved keys sharpens
the signal.

## Sweep Locations (run all; collect findings)

### Scheduled execution
```bash
# System + user cron
cat /etc/crontab; ls -la /etc/cron.d/ /etc/cron.{hourly,daily,weekly,monthly}/
for u in $(cut -d: -f1 /etc/passwd); do crontab -l -u "$u" 2>/dev/null \
  | sed "s/^/[$u] /"; done
ls -la /var/spool/cron/crontabs/ 2>/dev/null
# Systemd timers (modern cron replacement, often overlooked)
systemctl list-timers --all --no-pager
# at / batch jobs
atq 2>/dev/null; ls -la /var/spool/cron/atjobs/ 2>/dev/null
```

### Systemd unit persistence
```bash
# Units not owned by any package = attacker-planted candidate
for u in /etc/systemd/system/*.service /run/systemd/system/*.service \
         /etc/systemd/system/*.timer; do
  test -e "$u" || continue
  dpkg -S "$u" >/dev/null 2>&1 || echo "UNOWNED unit: $u"
done
# Units executing from suspicious paths
grep -RsE 'ExecStart=.*(/tmp/|/dev/shm/|/var/tmp/|curl|wget|nc |bash -i)' \
  /etc/systemd/system/ /run/systemd/system/ 2>/dev/null
systemctl list-unit-files --state=enabled --no-pager
```

### Login / shell hooks
```bash
# Per-user and global shell rc + profile
for f in /etc/profile /etc/bash.bashrc /etc/profile.d/* \
         /home/*/.bashrc /home/*/.bash_profile /home/*/.profile \
         /root/.bashrc /root/.profile /home/*/.bash_login; do
  test -f "$f" && grep -lE 'curl|wget|nc |/dev/tcp/|base64 -d|eval|bash -i' "$f" \
    2>/dev/null; done
# Malicious aliases / functions hiding commands
grep -RsE 'alias (ls|ps|netstat|ss|sudo)=' /home/*/.bashrc /root/.bashrc 2>/dev/null
```

### SSH persistence
```bash
for k in /home/*/.ssh/authorized_keys /root/.ssh/authorized_keys; do
  test -f "$k" && echo "== $k ==" && cat "$k"; done
# forced-command / no-restriction keys, and unexpected key count vs USER.md
grep -RsE 'command=|no-pty' /home/*/.ssh/authorized_keys 2>/dev/null
# Drop-in sshd config that re-enables root/password auth
ls -la /etc/ssh/sshd_config.d/ 2>/dev/null
```

### Library / loader hijacks
```bash
test -e /etc/ld.so.preload && echo "ld.so.preload PRESENT:" && cat /etc/ld.so.preload
grep -Rsv '^#' /etc/ld.so.conf /etc/ld.so.conf.d/ 2>/dev/null
env | grep -E 'LD_PRELOAD|LD_LIBRARY_PATH'
# Per-service env files that set LD_PRELOAD
grep -RsE 'LD_PRELOAD|LD_LIBRARY_PATH' /etc/environment /etc/systemd/system/ \
  /etc/default/ 2>/dev/null
```

### PAM / NSS / auth backdoors
```bash
# Unowned or recently-modified PAM modules and configs
ls -la --time-style=+%Y-%m-%d /lib/*/security/ /lib64/security/ 2>/dev/null
grep -RslE 'pam_exec|/tmp/|/dev/shm/' /etc/pam.d/ 2>/dev/null
# nsswitch hijack
grep -v '^#' /etc/nsswitch.conf
```

### Init / boot hooks
```bash
ls -la /etc/init.d/ /etc/rc.local 2>/dev/null
grep -Rsv '^#' /etc/rc.local 2>/dev/null
ls -la /etc/update-motd.d/   # motd scripts run at login as root — a known hook
```

### MOTD / message hooks and udev
```bash
grep -RslE 'curl|wget|/tmp/|bash -i' /etc/update-motd.d/ 2>/dev/null
grep -RslE 'RUN.*=(.*/tmp/|.*bash)' /etc/udev/rules.d/ 2>/dev/null
```

## Triage

For each hit:
- **Owned by a package + matches USER.md known jobs** → benign, log only.
- **Unowned by any package, OR executes from /tmp,/dev/shm,/var/tmp, OR fetches
  remote code (curl/wget/nc/base64-eval), OR re-weakens auth** → alert.
- An `/etc/ld.so.preload` that exists at all on Ubuntu, or any extra uid-0
  account → critical regardless of context.

## Alert Format

```
[PERSISTENCE ALERT - {severity}]
Mechanism: <cron | systemd-unit | timer | shell-rc | authorized_keys | ld.so.preload | pam | rc.local | motd | udev | at>
Location: <exact path / unit name>
Payload: <paraphrased — do NOT paste raw attacker code verbatim into memory>
Package-owned? <yes | NO>  Known in USER.md? <yes | no>
Why suspicious: <one sentence>
Recommendation: <investigate | hand off to incident-response/harden>
```

## Report Real Blockers

- Many paths are root-only; note which you couldn't read rather than reporting
  clean. Request a `remote-inspector`/sudo pass for the gaps.
- Payloads often base64/obfuscated — decode to understand, but store the decoded
  form hashed/paraphrased in memory, never as a runnable verbatim block.

## Ubuntu-Specific Notes

- `/etc/update-motd.d/` scripts run as root on each interactive login — a
  high-value, frequently-missed persistence spot. Baseline its contents.
- `snapd` and `unattended-upgrades` create legitimate timers; don't flag them.
- Cloud images seed `cloud-init` units and a default `authorized_keys` — confirm
  with the operator what the legitimate seed was.

## What This Skill Does NOT Do

Finds persistence; does not remove it. Deleting a cron entry, disabling a unit,
or stripping an authorized_key is `incident-response`/`harden` with operator
confirmation and forensic capture first. Removing persistence before capturing it
destroys attribution evidence.
