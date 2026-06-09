# TOOLS.md - Host-Specific Defensive Notes

Skills define _how_ defensive tools work. This file is for _this host's_
specifics — paths, baselines, allowlists that are unique to this deployment.

## What Goes Here

- Monitored file paths and their baseline hashes
- Allowed inbound and outbound network endpoints
- Services that legitimately run on this host
- Known scheduled jobs (and their command fingerprints)
- Threat-intel API endpoints in use and their rate limits
- Operator-approved exceptions (false-positive suppressions)
- SSH bastion / admin host addresses

## Examples

```markdown
### Monitored Paths (file integrity)

- /etc/passwd → baseline sha256: <hash>
- /etc/shadow → baseline sha256: <hash>
- /etc/sudoers → baseline sha256: <hash>
- /etc/ssh/sshd_config → baseline sha256: <hash>
- /usr/bin/sudo → baseline sha256: <hash>
- /var/www/html/ → directory recursive baseline: <hash>

### Allowed Outbound Endpoints

- api.abuseipdb.com → threat intel lookups, rate limit 1000/day
- nvd.nist.gov → CVE database queries
- otx.alienvault.com → IoC checks

### Legitimately Running Services

- sshd (port 22) — bastion only, key auth only
- nginx (ports 80, 443) — public web
- postgres (port 5432) — localhost only

### Services That Should Never Run

- telnetd, rsh, rlogin, ftpd, tftpd
- Any shell-spawned process whose parent is nginx or postgres

### Known Scheduled Jobs

- `/etc/cron.daily/logrotate` — runs ~06:25, expected fingerprint: <hash>
- `/etc/cron.daily/apt-compat` — runs ~06:25
- (Anything else in /etc/cron.* is unexpected, alert.)

### Operator-Approved Exceptions

- Daily backup script triggers high IO at 02:00-02:30, suppress IO alert in window
- Developer user 'alice' has approved sudo access, suppress sudo alerts for her UID
```

## Why Separate?

Skills are shared across deployments. This file is unique to this host.
If you redeploy to a new host, skills come with you; this file does not.
That separation prevents accidentally treating one host's baseline as
another's, which would mask real anomalies.

## Maintenance

- Update only with operator confirmation, except for read-only additions
  (e.g., recording a new threat-intel endpoint the operator approved adding
  to config).
- Hash baselines get refreshed when the operator confirms a legitimate
  change (package update, config change). Never auto-refresh on observed
  drift — that defeats the purpose.

## Related

- [Agent workspace](/concepts/agent-workspace)
