---
name: resource-anomaly-monitor
description: Use to detect sustained CPU, memory, disk, or I/O anomalies that indicate cryptominers, fork bombs, exfiltration, or runaway attacker tooling. Runs during heartbeat resource rotation and on demand. Correlates heavy consumers with process identity rather than alerting on load alone.
user-invocable: false
---

# Resource Anomaly Monitor

Use this skill to catch the resource-visible class of compromise: a cryptominer
pinning CPU, a memory-resident implant, disk filling from staged exfil data, or
sustained network I/O from a C2 beacon. The signal is not "load is high" — busy
hosts are normal — it is "an *unexpected* process is sustaining heavy use."

This is the heartbeat "resource anomaly" rotation check.

## Operating Loop

1. Capture top consumers with identity attached:
   ```bash
   ps -eo pid,ppid,user,%cpu,%mem,etimes,cmd --sort=-%cpu --no-headers | head -15
   ps -eo pid,ppid,user,%cpu,%mem,etimes,cmd --sort=-%mem --no-headers | head -15
   ```
   `etimes` (elapsed seconds) matters: a process at 99% CPU for 3 seconds is a
   compile; at 99% for 40 minutes it is a miner.
2. Capture disk and inode pressure:
   ```bash
   df -h; df -i
   # Largest recently-grown dirs in staging-prone locations
   du -sh /tmp/* /dev/shm/* /var/tmp/* 2>/dev/null | sort -rh | head
   ```
3. Capture per-process I/O if available:
   ```bash
   command -v iotop >/dev/null && sudo iotop -b -n1 -o 2>/dev/null | head -15
   ```

## Detection Rules

- **Sustained high CPU from an unexpected process** — `%cpu` over threshold AND
  `etimes` over ~600s AND the process is not on USER.md's expected-heavy list.
  Weight higher if the binary lives in `/tmp`, `/dev/shm`, `/var/tmp`, a home
  dir, or has a random-looking name. This is the cryptominer signature.
- **Process masquerade under load** — a heavy consumer named like a kernel
  thread (`[kworker...]`) but with a real `/proc/PID/exe` (kernel threads have
  none). Miners commonly disguise as `kworker`/`kswapd`.
- **Memory-resident with no disk backing** — `readlink /proc/PID/exe` points to
  `(deleted)`. A running binary deleted from disk is a strong implant tell;
  hand off to `process-inspector` for the deep dive.
- **Disk filling in staging dirs** — `/tmp`, `/dev/shm`, `/var/tmp`, or a web
  upload dir growing fast = possible exfil staging; correlate with
  `exfiltration-detector`.
- **Inode exhaustion** — `df -i` near full while `df -h` is not — many tiny
  files, a sign of a fork/log bomb or mass file creation.
- **Fork storm** — process count spiking far above baseline; check
  `ps -eo ppid --no-headers | sort | uniq -c | sort -rn | head` for a single
  parent spawning hundreds.

## Alert Format

```
[RESOURCE ALERT - {severity}]
Resource: <cpu | mem | disk | inode | io | forks>
Process: <pid> <cmd> (user: <user>, parent: <ppid>)
Sustained: <%usage> for <duration>
Exe path: <readlink /proc/PID/exe — note if (deleted) or /tmp/...>
Why suspicious: <one sentence>
Recommendation: <observe | hand off to process-inspector | hand off to incident-response>
```

## Report Real Blockers

- `iotop` absent and not installable → note that per-process I/O could not be
  measured; fall back to `df` deltas and network counters.
- High load with NO identifiable owning process (load average high, top shows
  nothing) → possible kernel-level activity or hidden process; escalate to
  `kernel-integrity-checker`.

## Ubuntu-Specific Notes

- Legitimate heavy consumers to baseline so they don't alert: `dockerd`/
  container workloads, `gnome-shell`/`Xorg` on a desktop, `unattended-upgrade`
  during patch windows, `updatedb`/`mlocate`, `apt`/`dpkg` during installs,
  backup jobs (your baseline notes a 02:00–02:30 backup window).
- Snap's `snapd` and `tracker-miner` (desktop indexer) spike periodically — both
  are noisy-but-benign; record them in USER.md's expected-heavy list.
- On this Apple-Silicon VM host, brief CPU spikes during VM snapshot/restore are
  host-driven, not guest compromise.

## What This Skill Does NOT Do

Detects and attributes resource anomalies. Does not kill processes or apply
cgroup limits — that is `incident-response` with operator confirmation. A miner
disguised as a critical service means auto-killing on load is a self-inflicted
outage risk; confirm identity, then let the operator decide.
