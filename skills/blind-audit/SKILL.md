---
name: blind-audit
description: Use to assess a host you cannot trust and have no clean baseline for — walking into a possibly-already-compromised system. Detects compromise from universal Linux invariants and cross-source consistency checks rather than baseline diffs. Primary skill for the ubuntu2 blind rootkit hunt.
user-invocable: true
---

# Blind Audit

Use this skill when you must judge a host's integrity with **no trusted
baseline** — the "walk into an already-infected box" scenario. You cannot diff
against known-good, so detection comes from two baseline-free sources:

1. **Universal invariants** — things that are wrong on *any* clean Linux host
   regardless of its configuration (see `INVARIANTS.md`).
2. **Cross-source consistency** — asking the same question two different ways and
   catching the layer that lies. A rootkit can hide a process from `ps` but
   struggles to hide it from `/proc` *and* the scheduler *and* an external view
   simultaneously.

This is the lead skill for the ubuntu2 engagement (see MEMORY.md). Run it over
SSH via `remote-inspector`, treating all guest-reported output as potentially
filtered by whatever you're hunting.

## Trust Model (read every run)

Once a kernel is compromised, every tool's output on that host passes through a
layer the attacker may control. So:
- **Favor cross-checks that are hard to forge from inside the guest** (atomic
  /proc-vs-ps; an *external* port scan from azariaUbuntu vs the guest's own `ss`).
- **Absence of evidence is not evidence of absence** — a capable rootkit scrubs
  `dmesg` and filters `ps`. A clean-looking single tool proves little; agreement
  across independent sources proves more.
- **Earn the hypothesis from evidence before confirming a named family.** Do not
  grep for a specific known module name as your *detection* (that's the cheat
  noted in MEMORY.md). Let generic evidence point you, then confirm.

## Operating Loop (order matters: is-there → what → how)

### Phase 1 — Is something loaded? (cheap, high-signal)

```bash
cat /proc/sys/kernel/tainted          # non-zero = out-of-tree/unsigned/forced module
# decode the bitmask:
for b in $(seq 0 18); do v=$(( ($(cat /proc/sys/kernel/tainted) >> b) & 1 )); \
  [ "$v" = 1 ] && echo "taint bit $b set"; done
dmesg 2>/dev/null | grep -iE 'taint|module verification failed|loading out-of-tree' | tail
```
Taint is generic and strong. A set "out-of-tree module" or "unsigned module"
bit on a host that should run only stock modules is a real lead.

### Phase 2 — What is hidden? (cross-source consistency)

```bash
# Hidden process: PID in /proc but never in ps, across repeated ATOMIC samples.
# Non-atomic sampling races on transient ssh/sudo/grep pipelines -> false positives.
for i in 1 2 3; do
  comm -23 <(ls /proc | grep -E '^[0-9]+$' | sort) \
           <(ps -e --no-headers -o pid | sort -u)
  sleep 1
done | sort | uniq -c    # a PID appearing in ALL samples is a real suspect

# Hidden module: lsmod vs /proc/modules vs sysfs
comm -3 <(lsmod | awk 'NR>1{print $1}' | sort) \
        <(awk '{print $1}' /proc/modules | sort)
ls /sys/module | sort > /tmp/sysmod.txt   # compare against lsmod too

# Hidden listener: guest's own ss vs /proc/net, vs EXTERNAL scan from azariaUbuntu
ss -tulnp | awk 'NR>1{print $5}' | sort -u
awk 'NR>1{print $2}' /proc/net/tcp /proc/net/tcp6 2>/dev/null   # hex addr:port
# then from azariaUbuntu (out-of-band, harder to forge):
#   nmap -sT -p- 192.168.223.132
```
Any discrepancy — PID consistently in /proc but not ps, a module in /proc/modules
but not lsmod, a port open externally but absent from the guest's `ss` — is a
hiding-layer signature.

### Phase 3 — How did it get in / persist? (universal red flags)

Run the full `INVARIANTS.md` sweep:
```bash
test -e /etc/ld.so.preload && echo "ld.so.preload PRESENT" && cat /etc/ld.so.preload
awk -F: '$3==0 && $1!="root"' /etc/passwd          # extra uid-0
find / -xdev -perm -4000 -type f 2>/dev/null        # all SUID (compare to sane set)
find /tmp /dev/shm /var/tmp -type f -executable 2>/dev/null
ls -la /etc/cron* /etc/systemd/system/*.timer 2>/dev/null
grep -RIl 'NOPASSWD' /etc/sudoers /etc/sudoers.d/ 2>/dev/null
```
Hand persistence detail to `persistence-hunter`, privesc detail to
`privilege-escalation-detector`, kernel detail to `kernel-integrity-checker`.

### Phase 4 — When / who? (timeline)

```bash
last -30; lastb -20 2>/dev/null            # logins / failed logins
stat -c '%n %z %y' /etc/passwd /etc/shadow /etc/ld.so.preload 2>/dev/null
# newest files in system dirs (recent drops):
find /usr/bin /usr/sbin /bin /sbin /lib /etc -xdev -type f -mtime -14 2>/dev/null
```

## Output

A structured verdict, not a transcript. Use `evidence-condenser` to keep raw
`/proc` and `dmesg` dumps on disk and only the signal in context.

```
[BLIND AUDIT — <host>]
Integrity verdict: <clean-so-far | suspicious | compromised>
Confidence: <low | medium | high> — based on <N independent sources agreeing>
Leads (evidence-earned, not assumed):
  - Phase1 taint: <bits / dmesg lines>
  - Phase2 hidden: <PID/module/port discrepancy, # of samples agreeing>
  - Phase3 redflags: <ld.so.preload / extra-uid0 / suspicious SUID / persistence>
  - Phase4 timeline: <recent drops, anomalous logins>
Hypothesis: <only if evidence supports it> — next confirmation step: <...>
Forging risk: <which findings come from guest-trusted output and may be filtered>
```

## Report Real Blockers

- `ps`/`/proc` counts implausibly low, or `ss` empty on a host with services →
  output is being filtered; that itself is a critical finding, not a clean result.
- Cannot get an external view to cross-check the guest → say the network finding
  is single-sourced and therefore weaker.
- dmesg empty on a long-uptime host → possibly scrubbed; note it, do not treat as
  exoneration.

## What This Skill Does NOT Do

Detects and characterizes; does not remediate. Removing a module, killing a
hidden PID, or blocking traffic on ubuntu2 is a state-changing action — propose
it, operator confirms per action (engagement red line in MEMORY.md). Does not
read the operator's install command / source tree / shell history to identify the
rootkit — that's the cheat; the hunt is blind by design.
