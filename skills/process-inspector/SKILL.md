---
name: process-inspector
description: Use when inspecting running processes on the host — checking for anomalous parent-child trees, unexpected root processes, shells spawned by network services, processes from suspicious paths. Runs during heartbeat process rotation and on demand during investigations.
user-invocable: false
---

# Process Inspector

Use this skill to enumerate and analyze processes on the Ubuntu host. Most malicious activity eventually surfaces as an unexpected process or an unexpected parent-child relationship, so this is one of the highest-signal observations available.

## Operating Loop

1. Capture current state with stable output:
   ```bash
   ps -eo pid,ppid,uid,user,euid,start_time,cmd --no-headers
   ```
   - PID + PPID lets you reconstruct the process tree.
   - UID and EUID reveal privilege escalation (euid != uid means setuid in play).
   - `start_time` lets you correlate with auth events.
   - `cmd` (not `comm`) shows the full invocation, not just the binary name.

2. Build the parent-child tree mentally or with `pstree -ap` if available. The tree matters more than the flat list.

3. Apply detection rules (run all, collect findings):

   - **Shells spawned by network services** — any process whose `comm` is `bash`, `sh`, `dash`, `zsh`, `ash`, `python`, `python3`, `perl`, `ruby` AND whose parent's `comm` is `nginx`, `apache2`, `postgres`, `mysqld`, `redis-server`, `sshd` (where the sshd child is not a legitimate login session). This is the canonical reverse-shell pattern.

   - **Processes from suspicious paths** — `cmd` starts with `/tmp/`, `/dev/shm/`, `/var/tmp/`, `/run/user/*/`, or any path under a user's home directory but running as root.

   - **Unexpected root processes** — UID 0 processes whose `cmd` is not in the expected-root list in TOOLS.md. Be especially suspicious of root processes with high PIDs (recently started) and short uptimes.

   - **Process masquerading** — `cmd` shows a common name (`[kworker]`, `sshd`, `systemd`) but executable path resolved via `readlink /proc/<pid>/exe` does not match the expected location. Compare:
     ```bash
     readlink /proc/$PID/exe
     ```
     against the package-owned path:
     ```bash
     dpkg -S /usr/sbin/sshd  # or whichever expected location
     ```

   - **Orphaned high-privilege processes** — PPID 1 (re-parented to init) running as root AND not a known daemon. Re-parenting often happens after a parent shell exits, which is fine — but a root process re-parented to init that isn't a system service is worth a look.

   - **Hidden processes** — compare `ls /proc/[0-9]*` PID list against `ps` output. Discrepancies suggest a rootkit hiding processes from `ps`. This is a critical alert.

4. Update state and report:
   - Append findings to `memory/YYYY-MM-DD.md` with the PID, parent PID, user, full cmd, and rule that fired.
   - Update `memory/heartbeat-state.json` `lastChecks.processes` timestamp.
   - If nothing fired, `HEARTBEAT_OK`.
   - If anything fired, alert the operator with the structured format below.

## Alert Format

```
[PROCESS ALERT - {severity}]
What: <rule name and brief description>
PID: <pid> (parent: <ppid> <parent_cmd>)
User: <user> (euid: <euid>)
Started: <start_time>
Cmd: <full command line>
Exe path: <readlink result>
Why suspicious: <one sentence>
Recommendation: <observe further | investigate | hand off to incident-response>
```

## Investigation Deep-Dive

When the operator asks to investigate a specific PID, gather (in order):

```bash
ls -la /proc/$PID/                      # exe, cwd, root, fd
readlink /proc/$PID/exe                 # actual binary path
cat /proc/$PID/cmdline | tr '\0' ' '    # full args, including those hidden from ps
cat /proc/$PID/status                   # uid map, capabilities, threads
ls -la /proc/$PID/fd/                   # open files, sockets, pipes
cat /proc/$PID/environ | tr '\0' '\n'   # environment (may reveal injection vectors)
```

Then check whether the binary on disk is package-owned:
```bash
dpkg -S $(readlink /proc/$PID/exe) 2>/dev/null || echo "NOT PACKAGE-OWNED"
```

A process running a binary that no package owns is a strong indicator of an attacker-dropped tool.

## Stale PID Recovery

Processes are ephemeral. If you snapshot, then go to investigate, the PID may be gone or reused.

1. Always re-check `/proc/$PID/exe` exists before deep-diving.
2. If gone, note it in the alert ("process exited before deep-dive") — short-lived processes are themselves a signal.
3. Do not assume a new process at the same PID is the same process. PIDs wrap.

## Report Real Blockers

Stop and tell the operator if:

- `ps` and `/proc` disagree on which processes exist (rootkit indicator — critical).
- You cannot read `/proc/$PID/exe` for a process you can otherwise see (capability restrictions or stealth — investigate).
- Process count is implausibly low (< 50 on a typical Ubuntu host suggests ps output is being filtered).

## Ubuntu-Specific Notes

- Kernel threads have names in square brackets (`[kworker/0:1]`) and their `/proc/$PID/exe` is empty — that's normal, do not alert on kernel threads.
- `systemd --user` instances run per-user-session, that's normal.
- `snapd` spawns many short-lived helpers — expect noise, baseline accordingly.
- Containers running on the host (Docker, LXC) will appear as processes — their cmds often start with `containerd-shim` or similar. Coordinate with the operator about which containers are expected.

## What This Skill Does NOT Do

Observes and alerts. Does not kill processes, send signals, or modify cgroups. Killing a process based on observation is `incident-response`'s job and requires operator confirmation. An attacker can disguise legitimate processes to look malicious — auto-killing on suspicion creates a denial-of-service vector against the host itself.
