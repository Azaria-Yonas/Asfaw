---
name: network-observer
description: Use when inspecting network state on the host — listening sockets, established connections, unexpected outbound traffic, new ports. Runs during heartbeat network rotation and on demand when investigating possible exfiltration or C2.
user-invocable: false
---

# Network Observer

Use this skill to enumerate network state on the Ubuntu host. The two highest-signal questions are "what is listening that shouldn't be" and "what outbound connection isn't accounted for." Both surface here.

## Operating Loop

1. Capture listening sockets first:
   ```bash
   ss -tulnp
   ```
   - `-t` TCP, `-u` UDP, `-l` listening, `-n` numeric, `-p` process.
   - Needs root for the process column; without root the listener is visible but the owning process is hidden.

2. Capture established connections:
   ```bash
   ss -tnp state established
   ```
   - Excludes listening sockets and time-wait, focuses on active conversations.

3. Apply listener detection rules:

   - **Unexpected port** — any listening port not in the allowed-listeners list in TOOLS.md. Cross-reference the process column to see what opened it.

   - **Listener on 0.0.0.0 that should be localhost** — services like postgres, redis, mysql should typically bind to `127.0.0.1` only. A bind on `0.0.0.0:5432` is a misconfiguration at minimum and a deliberately-exposed backdoor at worst.

   - **Listener with no owning process** — `ss -tulnp` shows the port but the users field is empty. Indicates either a kernel-level socket or a process you don't have permission to see (suspicious).

   - **High port listener owned by an unexpected user** — UID 1000+ binding to a port that isn't expected for that user. Web users binding to ports nobody asked for is a webshell tell.

4. Apply outbound connection rules:

   - **Connection to allowlisted-only domain not on allowlist** — any established outbound to an IP that doesn't resolve to (or originate from) an entry on the allowed-egress list in TOOLS.md.

   - **Connection to known-bad infrastructure** — cross-reference destination IPs against `threat-intel-lookup`. Don't do the lookup inline — collect the IPs, then call the threat-intel skill in batch.

   - **Unusual port destinations** — outbound to high ports (>1024) on uncommon protocols is a C2 indicator, especially if the connecting process is a shell or interpreter rather than a known network client.

   - **DNS to non-configured resolvers** — outbound UDP 53 or TCP 53 to anything other than `/etc/resolv.conf` configured nameservers. Malware often hardcodes its own DNS to bypass local filtering.

5. Update state and report:
   - Append findings to `memory/YYYY-MM-DD.md`.
   - Update `memory/heartbeat-state.json` `lastChecks.network` timestamp.
   - `HEARTBEAT_OK` if nothing fired.
   - Structured alert otherwise.

## Alert Format

```
[NETWORK ALERT - {severity}]
What: <rule name>
Local: <local_ip>:<port>
Remote: <remote_ip>:<port> (resolved: <hostname or "no PTR">)
Process: <pid> <cmd> (user: <user>)
State: <listening | established | time-wait>
Why suspicious: <one sentence>
Recommendation: <observe | enrich with threat-intel | hand off to incident-response>
```

## Baseline Comparison

The first time this skill runs on a host (or after `baseline-scan` is invoked), capture the full listener and established-connection set into `memory/network-baseline.json`. Future runs diff against that baseline:

- **New listener since baseline** → alert (informational at minimum).
- **Listener gone since baseline** → alert (a service stopped — could be legitimate or could be tampering with monitoring).
- **Established connection to a destination not seen in baseline** → log, escalate only if it crosses the rules above.

Never auto-update the baseline on observed drift. The operator must confirm new entries.

## Investigation Deep-Dive

When asked to investigate a specific connection:

```bash
# Find the socket
ss -tnp | grep "<remote_ip>:<port>"

# Get the inode
ss -tne | grep "<remote_ip>:<port>" | awk '{print $NF}'

# Find which process owns the socket
sudo lsof -i :@<remote_ip>:<port>

# Reverse DNS the destination
dig +short -x <remote_ip>

# Check the destination's reputation (hand off to threat-intel-lookup)
```

## Stale Connection Recovery

Network state changes constantly. A connection you snapshotted may be gone by the time you investigate.

1. Re-run `ss` before deep-diving.
2. If the connection is gone, note duration ("connection visible for at most N seconds before close") — very short connections are themselves a signal (data exfil via burst).
3. If the connection persists across multiple checks, that strengthens the alert.

## Report Real Blockers

Stop and tell the operator if:

- `ss` returns empty output on a host with services running (output is being filtered or capabilities revoked).
- `/proc/net/tcp` and `ss` disagree (rootkit hiding sockets — critical).
- DNS resolution is broken and you cannot enrich destination IPs (note in the alert; do not block on it).
- `iptables -L` or `nft list ruleset` shows rules you did not expect — could be legitimate fail2ban activity, could be attacker rules. Report and let the operator interpret.

## Ubuntu-Specific Notes

- `systemd-resolved` listens on `127.0.0.53:53` — that's normal, not an alert.
- `snap` services often bind unusual ports — baseline these specifically so they don't generate noise.
- `cloud-init` on first boot opens transient listeners — baseline only after first boot completes.
- Docker creates `docker0` bridge and per-container interfaces — connections to/from `172.17.0.0/16` are intra-container, not internet egress. Treat them as a separate trust zone.
- UFW (Ubuntu's firewall frontend) status: `ufw status verbose`. If it's inactive on a host that should have it active, that's an alert.

## What This Skill Does NOT Do

Observes and reports. Does not modify firewall rules, drop connections, or block IPs. Network response actions go through `incident-response` with operator confirmation. An injection that causes you to drop connections is a self-DoS — observation must stay separate from action.
