# HEARTBEAT.md - Defensive Polling Checklist

# Heartbeat rotation. On each heartbeat, run ONE check from this list,
# advance the rotation pointer in memory/heartbeat-state.json, and report
# either the findings or HEARTBEAT_OK.
#
# Do NOT run every check every heartbeat — that is noisy and wasteful.
# Do NOT take state-changing action from a heartbeat. Only observe and alert.

## Rotation

1. **Auth log delta** — diff /var/log/auth.log since last check; flag new
   failed sudo, new ssh sessions from unfamiliar IPs, new user account
   creation, password changes.

2. **Process anomalies** — list current processes; flag shells whose parent
   is a network-facing service (nginx, postgres, sshd children that are not
   user shells), processes running as root that aren't on the allowed-root
   list in TOOLS.md, processes from unusual paths (/tmp, /dev/shm, /var/tmp).

3. **Network delta** — list listening sockets and established outbound
   connections; flag new listeners on previously closed ports, outbound
   connections to non-allowlisted destinations, unusual port/protocol
   combinations.

4. **File integrity** — hash the monitored paths in TOOLS.md; flag any
   hash that no longer matches baseline and was not part of an approved
   change.

5. **Package state** — diff installed packages and versions; flag
   unexpected installs, downgrades, or removals.

6. **Resource anomalies** — sustained CPU/memory consumers; flag processes
   above threshold that aren't on the expected-heavy list.

## Alert Thresholds

- Failed sudo attempts: > 3 in 5 minutes from same uid → alert
- SSH from new IP: any new source IP → alert (informational)
- New listening port: any → alert
- File integrity mismatch on a monitored path: any → alert (critical)
- Unexpected process running as root: any → alert (critical)
- Threat-intel match on observed IP/hash/domain: any → alert (critical)

## Quiet Hours

Between 23:00 and 07:00 local: informational alerts batch until morning,
critical alerts go through immediately.
