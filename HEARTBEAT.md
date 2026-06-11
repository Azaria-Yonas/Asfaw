# HEARTBEAT.md - Defensive Polling Checklist

# Heartbeat rotation. On each heartbeat, run ONE check from the rotation,
# advance the rotation pointer in memory/heartbeat-state.json, and report
# either the findings or HEARTBEAT_OK.
#
# Do NOT run every check every heartbeat — that is noisy and wasteful.
# Do NOT take state-changing action from a heartbeat. Only observe and alert.

## Core principle: script-first, model-on-anomaly

Most rotation checks are mechanical diffs. They do NOT need the model to *run* —
they need it only to *interpret an anomaly*. So each heartbeat works in two stages:

1. **Stage 1 (cheap, no model judgment):** run the rotated check's commands,
   reduced at the source to emit only deviations (see `evidence-condenser`
   Tier 1). If the filtered output is empty → log `HEARTBEAT_OK`, update the
   per-check timestamp, advance the pointer, and stop. A quiet beat costs almost
   nothing.
2. **Stage 2 (only if Stage 1 produced a deviation):** bring full reasoning to
   bear — interpret the anomaly, consult `PLAYBOOK.md` for the follow-on chain,
   and alert per the format in the relevant skill.

This is what makes a low heartbeat frequency safe and a higher one affordable:
quiet beats don't burn tokens, so cadence becomes a tuning knob, not a cost cliff.

## Rotation (each maps to a skill)

1. **Auth log delta** → `auth-log-monitor` — new failed sudo, ssh from
   unfamiliar IPs, new accounts, password changes.
2. **Process anomalies** → `process-inspector` — shells parented by network
   services, unexpected root processes, processes from /tmp,/dev/shm,/var/tmp.
3. **Network delta** → `network-observer` — new listeners, outbound to
   non-allowlisted destinations, unusual port/protocol pairs.
4. **File integrity** → `file-integrity-check` — monitored-path hash/metadata
   drift; baseline-free package-verify + INVARIANTS fallback when no baseline.
5. **Package state** → `package-state-monitor` — unattributed installs,
   downgrades, security-agent removal, held packages.
6. **Resource anomalies** → `resource-anomaly-monitor` — sustained CPU/mem/disk
   from unexpected processes (miners, exfil staging, fork storms).

Track per-check timestamps in `memory/heartbeat-state.json` `lastChecks.*` and the
next index in `rotation_index`. One check per beat; rotate.

## Adaptive cadence (don't poll too often)

Cadence lives in `heartbeat-state.json` `cadence`:

- **Baseline (quiet):** `baseline_minutes` (default **90**). On an idle
  workstation this is plenty — six checks rotate roughly once every 9 hours, and
  quiet beats are near-free.
- **Escalated (post-alert):** after ANY alert fires, set
  `mode: "escalated"`, drop to `escalated_minutes` (default **10**), and set
  `escalated_beats_remaining` (e.g., 6). Watch closely for follow-on activity,
  then decay back to baseline as beats elapse without new alerts.
- **consecutive_clear** increments each HEARTBEAT_OK; long clean streaks can
  justify lengthening `current_minutes` further (e.g., 90 → 120) to save cost.
  Reset to baseline on any alert.

The model adjusts `current_minutes`/`mode` in the state file; the scheduler reads
it. Never let escalation persist forever — it decays.

## Keep the ubuntu2 hunt OUT of the heartbeat

Heartbeats defend the LOCAL host (azariaUbuntu). The ubuntu2 rootkit hunt is an
operator-driven foreground investigation via `remote-inspector` — running it on
the heartbeat would inflate cost and muddy the rotation. They are separate loops.

## Alert Thresholds

- Failed sudo attempts: > 3 in 5 minutes from same uid → alert
- SSH from new IP: any new source IP → alert (informational)
- New listening port: any → alert
- File integrity mismatch on a monitored path: any → alert (critical)
- Unexpected process running as root: any → alert (critical)
- Package change with no apt-history attribution: any → alert (critical)
- Sustained CPU from unexpected process > 10 min: alert
- Threat-intel match on observed IP/hash/domain: any → alert (critical)
- Any INVARIANTS.md violation: alert (severity per that file)

## Quiet Hours

Between 23:00 and 07:00 local (America/Los_Angeles): informational alerts batch
until morning; critical alerts go through immediately. Escalation (10-min cadence
after an alert) overrides quiet hours for the escalation window — if something
fired at 02:00, watch closely regardless of the hour.
