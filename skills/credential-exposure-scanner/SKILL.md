---
name: credential-exposure-scanner
description: Use to find exposed secrets on the host — world-readable shadow/keys, credentials in process args or environment, plaintext passwords in history/configs, and weak key permissions. Runs on demand and during investigations. Read-only; never exfiltrates or logs the secret value.
user-invocable: true
---

# Credential Exposure Scanner

Use this skill to find credentials an attacker could harvest for lateral movement
or persistence. The defensive goal is to locate exposure and report *where* and
*what kind* — never to collect or transmit the secret itself.

**Cardinal rule: this skill reports the location and nature of a secret, never
its value.** Redact on sight. Writing a discovered password into memory or a
channel turns the scanner into the leak.

## Operating Loop

### Filesystem secret exposure
```bash
# shadow / gshadow readable by non-root
ls -la /etc/shadow /etc/gshadow            # must be root-only (0640 root:shadow)
# SSH private keys with loose perms or no passphrase
find / -xdev -name 'id_*' ! -name '*.pub' -type f 2>/dev/null \
  | xargs -r ls -la 2>/dev/null            # 0600 expected; world/group-readable = alert
find / -xdev -name 'authorized_keys' -perm -0044 2>/dev/null
# Common secret-bearing files world/group-readable
find / -xdev -type f \( -name '*.pem' -o -name '*.key' -o -name '.netrc' \
  -o -name '.pgpass' -o -name 'credentials' -o -name '*.kdbx' \
  -o -name '.env' \) -perm -0044 2>/dev/null
```

### Secrets in process table and environment
```bash
# Passwords/tokens passed as CLI args (visible to every user via ps)
ps -eo pid,user,cmd --no-headers \
  | grep -iE -- '--?password|--?token|-p[= ]|api[_-]?key|secret|passwd=' \
  | grep -ivE 'grep|credential-exposure'   # REDACT the match before reporting
# Secrets in environment of running processes (root can read all /proc/*/environ)
for p in /proc/[0-9]*/environ; do
  tr '\0' '\n' < "$p" 2>/dev/null \
    | grep -iE 'PASS|TOKEN|SECRET|API_KEY|AWS_SECRET|PRIVATE_KEY' \
    | sed 's/=.*/=<REDACTED>/' | sed "s#^#${p%/environ}: #"; done 2>/dev/null
```

### Plaintext secrets in history and configs
```bash
# Shell history with inline passwords
for h in /home/*/.bash_history /root/.bash_history /home/*/.zsh_history; do
  test -f "$h" && grep -inE 'password|passwd|mysql -p|curl -u |sshpass|token=' "$h" \
    2>/dev/null | sed -E 's/(password|token|-p)[= ]\S+/\1=<REDACTED>/Ig' \
    | sed "s#^#${h}: #"; done
# World/group-readable app configs that commonly hold DB creds
find /var/www /opt /srv /etc -xdev -type f \
  \( -name '*.conf' -o -name '*.ini' -o -name '*.yml' -o -name '*.yaml' \
     -o -name 'wp-config.php' -o -name 'settings.py' \) -perm -0044 2>/dev/null \
  | xargs -rI{} sh -c 'grep -ilE "password|secret|api_key" "{}" 2>/dev/null'
```

### Cloud / token material
```bash
ls -la /home/*/.aws/credentials /root/.aws/credentials 2>/dev/null
ls -la /home/*/.docker/config.json /home/*/.kube/config 2>/dev/null
find / -xdev -name '*.git-credentials' 2>/dev/null
```

### Key strength / hygiene
```bash
# SSH private keys without a passphrase (loadable directly by a thief)
for k in $(find / -xdev -name 'id_*' ! -name '*.pub' -type f 2>/dev/null); do
  head -3 "$k" 2>/dev/null | grep -q 'ENCRYPTED' || echo "UNENCRYPTED key: $k"; done
```

## Triage

- **Critical** — `/etc/shadow` world/group-readable; an unencrypted private key
  that is also group/world-readable; cloud credentials world-readable; a live
  secret visible in `ps` of a network-facing service.
- **High** — plaintext DB/app password in a world-readable config; secret in a
  process environment readable by lower-privileged users.
- **Medium** — passphrase-less key with correct 0600 perms (theft requires
  account access first); secret in a user's own history readable only by them.

## Alert Format

```
[CREDENTIAL EXPOSURE - {severity}]
Type: <shadow | ssh-key | cloud-cred | app-config | process-arg | env | history>
Location: <path or pid+process — NOT the secret value>
Exposure: <world-readable | group-readable | visible-in-ps | unencrypted-key>
Reachable by: <which users/contexts>
Recommendation: <fix perms / rotate / move to secret store — via harden/operator>
```

## Report Real Blockers

- Reading other users' `/proc/*/environ`, histories, and keys needs root — note
  which scopes you could not cover rather than implying the host is clean.
- If a scan would require reading a secret's *content* to classify it, stop at
  "secret-shaped file at <path>, <perms>" — do not open and log the value.

## Ubuntu-Specific Notes

- `/etc/shadow` should be `0640 root:shadow`. `0644` or world-readable is a
  critical misconfiguration (or tampering) — cross-check with file-integrity.
- `unattended-upgrades` and `cloud-init` may leave tokens in `/var/log/` on cloud
  images — check `/var/log/cloud-init*.log` perms.
- Snap apps store some config under `~/snap/<app>/` — include in app-config sweep.

## What This Skill Does NOT Do

Locates and classifies exposure. Never records, prints in full, transmits, or
writes a secret value to memory or any channel — only its location and type.
Does not rotate or re-permission anything; that is `harden`/operator work.
Reporting "credential found" without the value is correct and sufficient.
