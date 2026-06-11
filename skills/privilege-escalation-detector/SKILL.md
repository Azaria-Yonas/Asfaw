---
name: privilege-escalation-detector
description: Use to find local privilege-escalation vectors and in-progress escalation — dangerous SUID/SGID binaries, risky sudo rules, Linux capabilities, writable PATH/units, and recent privilege changes. Runs on demand and during foothold investigations. Pairs with vulnerability-scanner (kernel privesc CVEs) and harden (fixes).
user-invocable: true
---

# Privilege Escalation Detector

Use this skill to answer "if an attacker has a normal-user foothold here, how do
they become root — and is there a sign they already did?" It enumerates the
local privesc surface the same way an attacker's `linpeas`-style sweep would, but
for defense.

Works baseline-free (most vectors are dangerous by their nature); USER.md's
legitimate-user list and an expected-SUID set sharpen it.

## Operating Loop

### SUID / SGID binaries
```bash
find / -xdev \( -perm -4000 -o -perm -2000 \) -type f 2>/dev/null \
  | xargs -r ls -la 2>/dev/null
```
- Compare against the known-safe distro set (passwd, sudo, su, mount, ping,
  chsh, chfn, newgrp, gpasswd, pkexec, etc.).
- **Alert on:** SUID on shells/interpreters (`bash`, `dash`, `python`, `perl`,
  `find`, `vim`, `nmap`, `env`, `awk`) — these are GTFOBins-style instant root;
  SUID binaries in `/tmp`, `/home`, `/dev/shm`, `/var/tmp`; SUID binaries not
  owned by any package (`dpkg -S` fails); any SUID binary newer than the rest of
  its directory (recently planted).

### Sudo configuration
```bash
# Effective rules for the current/each user (best run via remote-inspector as the user)
sudo -l 2>/dev/null
grep -RsvE '^\s*#|^\s*$' /etc/sudoers /etc/sudoers.d/ 2>/dev/null
```
- **Alert on:** `NOPASSWD` for non-admin users; `ALL=(ALL) ALL` granted broadly;
  sudo rights to GTFOBins binaries (`vim`, `less`, `find`, `awk`, `python`,
  `tar`, `nmap`, `env`, `man`) — each is a one-liner to root; `!authenticate`;
  env-preserving rules (`env_keep += LD_PRELOAD`) that enable library injection.

### Linux capabilities
```bash
getcap -r / 2>/dev/null
```
- **Alert on:** `cap_setuid`, `cap_sys_admin`, `cap_dac_override`,
  `cap_dac_read_search` on non-standard binaries; capabilities on interpreters
  (`python`, `perl`, `ruby`) — equivalent to SUID root.

### Writable-path hijacks
```bash
# World-writable dirs that appear in root's PATH or in service PATHs
echo "$PATH" | tr ':' '\n' | while read -r d; do
  test -d "$d" && find "$d" -maxdepth 0 -perm -0002 2>/dev/null \
    && echo "WORLD-WRITABLE PATH dir: $d"; done
# Writable systemd unit files / their ExecStart targets (privilege via service)
find /etc/systemd/system /lib/systemd/system -perm -0002 -type f 2>/dev/null
# Writable cron targets, writable files owned by root that scripts source
find / -xdev -perm -0002 -type f -user root 2>/dev/null | head -50
```

### Kernel / known-exploit surface
```bash
uname -r        # hand to vulnerability-scanner for kernel privesc CVEs
test -r /etc/os-release && . /etc/os-release && echo "$PRETTY_NAME"
command -v pkexec >/dev/null && pkexec --version   # PwnKit-class history
```

### Signs escalation already happened
```bash
awk -F: '$3==0 {print}' /etc/passwd          # extra uid-0 accounts
grep -E ':\$' /etc/passwd                      # password hash in passwd (legacy/odd)
getent group sudo root adm                     # unexpected members
last | grep -i root                            # root logins outside admin window
# Setuid processes currently running where euid != uid
ps -eo pid,uid,euid,user,cmd --no-headers | awk '$2!=$3'
```

## Triage by Exploitability

- **Critical** — a vector usable by an existing local user right now (NOPASSWD to
  a GTFOBins binary; SUID shell; cap_setuid on python) OR direct evidence of
  prior escalation (extra uid-0, unexpected sudo-group member).
- **High** — vector requiring a condition an attacker can likely meet (writable
  root-PATH dir, writable unit file).
- **Medium** — vulnerable kernel/pkexec version present but no local foothold
  evidence.

## Alert Format

```
[PRIVESC ALERT - {severity}]
Vector: <suid | sudo-rule | capability | writable-path | writable-unit | kernel | already-escalated>
Detail: <binary/rule/path + why it grants root>
Usable by: <which user/condition>
Evidence of use: <yes — what | no — latent vector only>
Recommendation: <harden to remove vector | incident-response if active>
```

## Report Real Blockers

- `sudo -l` is per-user and may need `remote-inspector` to run as the target
  user; note coverage gaps.
- `getcap -r /` needs read access; run as root for completeness.

## Ubuntu-Specific Notes

- Standard Ubuntu SUID set is well-known — keep an expected list in TOOLS.md so
  this skill flags only *additions*. `pkexec`, `mount.nfs`, `fusermount3` are
  normal; `pkexec` history (CVE-2021-4034 PwnKit) means version matters.
- `sudo` group membership grants full root — audit it tightly; the lab note in
  MEMORY.md says azaria is in sudo on ubuntu2, which is expected for that host.
- AppArmor can neutralize some SUID abuse; note if a flagged binary is confined.

## What This Skill Does NOT Do

Enumerates and flags escalation surface; does not exploit it and does not fix it.
Removing a SUID bit, tightening sudoers, or dropping a capability is `harden`
(proactive) or `incident-response` (active), operator-confirmed. Demonstrating a
vector by actually escalating is out of scope — this is defensive enumeration.
