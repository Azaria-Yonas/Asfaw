---
name: baseline-scan
description: Use on demand to capture or refresh host baselines — file hashes, expected services, listening ports, scheduled jobs. Run during initial deployment, after operator-approved system changes, or when investigating possible baseline tampering. The only skill the operator invokes directly.
user-invocable: true
---

# Baseline Scan

Use this skill to populate or refresh the host-specific baselines that every other defensive skill depends on. Without an accurate baseline, the rest of the agent is a chatbot with security tools — capable of describing state, incapable of distinguishing normal from abnormal.

This is the only `user-invocable: true` skill in the defensive set. The operator triggers it; the agent never runs it autonomously.

## When To Run

1. **Initial deployment** — on a freshly-installed, known-clean host before exposing it to traffic. This is the most important run. If the host was already compromised at baseline time, the baseline encodes the compromise.

2. **After approved system changes** — package updates, config changes, new services added. The operator runs `baseline-scan --paths <list>` to refresh only what changed.

3. **Suspected baseline tampering** — if `file-integrity-check` is alerting on TOOLS.md itself, or if the operator suspects the workspace has been modified.

4. **Never on a schedule.** Auto-running baseline scans is exactly the bypass an attacker exploits: cause a malicious change, then have the agent helpfully baseline it as the new normal. This skill runs only when the operator says so.

## Operating Loop

1. Confirm intent with the operator:
   ```
   [BASELINE SCAN]
   Mode: <initial | refresh | targeted>
   Targets: <"all monitored paths" | specific list>
   Current baseline age: <when last full baseline was captured>
   
   This will overwrite the matching entries in TOOLS.md. Existing entries
   not in the target list will be preserved.
   
   Proceed? Reply YES to continue.
   ```

2. Verify operator confirmation (per `incident-response` rules — exact `YES`).

3. Capture each category in turn:

### File Integrity Baselines

For each path in the monitored set:

```bash
# Files
sha256sum "$PATH" | awk '{print $1}'

# Directories (recursive hash)
find "$PATH" -type f -print0 | sort -z | xargs -0 sha256sum | sha256sum | awk '{print $1}'

# Also capture metadata
stat -c "%s %Y %U:%G %a" "$PATH"
```

Output goes to TOOLS.md under "Monitored Paths (file integrity)" in this format:

```markdown
- /etc/passwd → sha256: <hash> | size: <bytes> | mtime: <unix> | owner: root:root | mode: 0644 | captured: <iso8601>
```

### Service Baselines

```bash
# Currently-running services
systemctl list-units --type=service --state=running --no-pager --no-legend \
    | awk '{print $1}'

# Enabled services (will start on boot)
systemctl list-unit-files --type=service --state=enabled --no-pager --no-legend \
    | awk '{print $1}'
```

Output goes to TOOLS.md under "Legitimately Running Services".

### Network Baselines

```bash
# Listening sockets
ss -tulnp | tail -n +2

# Configured firewall rules
sudo iptables-save 2>/dev/null || sudo nft list ruleset 2>/dev/null
```

Output goes to TOOLS.md under "Allowed Inbound Listeners" and `memory/network-baseline.json`.

### Scheduled Job Baselines

```bash
# System crontabs
for f in /etc/crontab /etc/cron.d/* /etc/cron.hourly/* /etc/cron.daily/* /etc/cron.weekly/* /etc/cron.monthly/*; do
    test -f "$f" && echo "$f: $(sha256sum "$f" | awk '{print $1}')"
done

# User crontabs
for u in $(cut -d: -f1 /etc/passwd); do
    sudo crontab -l -u "$u" 2>/dev/null | sha256sum | awk -v user="$u" '{print user": "$1}'
done

# Systemd timers
systemctl list-timers --all --no-pager --no-legend | awk '{print $NF, $1}'
```

Output goes to TOOLS.md under "Known Scheduled Jobs".

### Package State Baseline

```bash
dpkg -l | awk '/^ii/ {print $2"="$3}' | sha256sum
```

The single aggregate hash goes to `memory/package-baseline.json`. Individual package list also written for diff purposes.

### Expected-Root Process List

```bash
# Processes currently running as root with their command paths
ps -eo uid,cmd --no-headers | awk '$1==0 {$1=""; print}' | sort -u
```

Operator reviews this list — it becomes the "expected root processes" reference that `process-inspector` uses.

4. Write all results to TOOLS.md atomically:
   - Read current TOOLS.md.
   - Compute the new content.
   - Write to `TOOLS.md.new`.
   - Operator reviews the diff.
   - On second confirmation, rename `TOOLS.md.new` to `TOOLS.md`.

5. Record the scan in `memory/YYYY-MM-DD.md`:
   ```
   Baseline scan completed at <timestamp>
   Mode: <mode>
   Paths captured: <count>
   Services captured: <count>
   Operator: <admin channel identity>
   Previous baseline age: <duration>
   ```

## Two-Stage Confirmation

Baseline scan is the only skill that requires confirmation twice:

1. Before running — "should I capture?"
2. After running, before writing — "the captured values look like this, should I commit them to TOOLS.md?"

The second confirmation lets the operator catch a baseline that was taken on a compromised system. If the captured "legitimately running services" list contains something the operator doesn't recognize, that's a finding — not something to commit as the new normal.

## Targeted Refresh Mode

When refreshing after an approved change:

```
[BASELINE SCAN - targeted]
Paths: /etc/ssh/sshd_config, /usr/sbin/sshd
Reason: <operator's stated reason — "applied openssh-server upgrade">
```

Targeted mode only touches the named entries. The rest of TOOLS.md is preserved unchanged. This is the common case — full re-baselines are rare and risky.

## Report Real Blockers

Stop and tell the operator if:

- The host is not in a known-clean state ("how do you know this host is clean?" is a fair question for the operator to have a clear answer to).
- Any path on the proposed monitor list is missing — that itself is interesting, do not silently skip it.
- `sha256sum` returns errors on files that should be readable — capability or permission issue worth investigating before baselining.
- TOOLS.md already exists with non-trivial content and the operator is requesting a full re-baseline — confirm this is intentional, since it erases the prior baseline.

## Pre-Baseline Sanity Checks

Before any capture, run these and surface results to the operator:

```bash
# Was the host recently rebooted (timestamps may be off)?
uptime

# Is the clock correct (baseline timestamps depend on it)?
timedatectl status

# Are there pending unattended upgrades that would change things mid-scan?
ls /var/run/reboot-required 2>/dev/null

# Is there a known intrusion indicator on the host?
test -f /etc/ld.so.preload && echo "WARNING: /etc/ld.so.preload exists"
last -10  # recent logins — does anything look wrong?
```

If any of these surface anomalies, do not proceed with baseline. Surface to operator and let them decide.

## Ubuntu-Specific Notes

- Snap packages have their own update mechanism — refreshes happen automatically. Baseline `/snap/` contents but expect higher churn there than in `/usr/`.
- `apt` keeps a history at `/var/log/apt/history.log`. Reading this gives you a list of legitimate package changes since the last baseline — useful for the operator to cross-reference what changed.
- AppArmor profiles in `/etc/apparmor.d/` should always be in the baseline.
- The `ubuntu-advantage` / `landscape-client` tools may apply unattended security updates — coordinate with the operator about whether those should trigger automatic targeted re-baselines for the affected files (the answer is usually yes, but with operator awareness, not silent auto-refresh).

## What This Skill Does NOT Do

Captures known-good state. Does not validate that the state is *actually* good — that's the operator's responsibility before invoking. Does not run on a timer. Does not modify TOOLS.md without two confirmations. Does not delete prior baselines (the previous TOOLS.md is preserved as TOOLS.md.<timestamp>.bak so the operator can compare or revert).
