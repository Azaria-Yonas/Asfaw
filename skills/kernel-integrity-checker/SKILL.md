---
name: kernel-integrity-checker
description: Use to assess kernel-level integrity — loaded modules, taint state, syscall-table/hook tampering, and rootkit indicators. The reusable form of the LKM-rootkit methodology in MEMORY.md. Runs on demand and as a deep-dive when other skills suspect kernel-level hiding.
user-invocable: true
---

# Kernel Integrity Checker

Use this skill when evidence points below userspace — a hidden process that
survives atomic /proc-vs-ps sampling, a port open externally but invisible to the
guest's `ss`, a set kernel taint bit, or `process-inspector`/`network-observer`
reporting source disagreement. This is the family-agnostic LKM-rootkit detection
methodology from MEMORY.md, promoted to a reusable skill.

## What A Kernel Rootkit Does (so you know what to look for)

LKM rootkits typically hook the syscall table or VFS/proc handlers to: hide
processes, hide files/dirs by name prefix, hide network connections, hide their
own module from `lsmod`, and expose a magic control channel (a special signal,
a magic file, or a crafted `/proc` write) to grant root or toggle visibility.
Each behavior leaves a cross-checkable seam.

## Operating Loop

### 1 — Taint and load residue (generic, strong)

```bash
cat /proc/sys/kernel/tainted        # 0 = clean; non-zero = decode bits below
# Key bits: 12 = out-of-tree module, 13 = unsigned module, 0 = proprietary module
dmesg 2>/dev/null | grep -iE 'taint|module|unsigned|out-of-tree|verification failed'
journalctl -k 2>/dev/null | grep -iE 'taint|module' | tail
```
Note: a capable rootkit can clear its own taint contribution and scrub dmesg —
absence is not exoneration, but presence is a solid lead.

### 2 — Module visibility cross-check

```bash
comm -3 <(lsmod | awk 'NR>1{print $1}' | sort) <(awk '{print $1}' /proc/modules | sort)
diff <(lsmod | awk 'NR>1{print $1}' | sort) <(ls /sys/module | sort)
# A module present in /proc/modules or /sys/module but absent from lsmod = hiding.
```

### 3 — Syscall-table / hook integrity

```bash
# Symbols visible? (often restricted; 0x000... means kptr_restrict is hiding them)
grep -E ' sys_call_table| __x64_sys_| ksys_' /proc/kallsyms 2>/dev/null | head
# Look for unexpected symbols owned by a module in the syscall path:
grep -iE 'hook|hide|rootkit|backdoor' /proc/kallsyms 2>/dev/null
# Modules with no sysfs srcversion / suspicious params:
for m in /sys/module/*/; do
  test -e "$m/taint" && t=$(cat "$m/taint" 2>/dev/null) && [ -n "$t" ] && \
    echo "tainted module: $(basename "$m") [$t]"
done
```
If `/proc/kallsyms` is all zeros, `kptr_restrict` is on — read it as root via
`remote-inspector` for the real addresses, or compare handler addresses against
the module address ranges in `/proc/modules`. A syscall handler resolving into a
loaded module's address range (instead of the core kernel) is a hook.

### 4 — Hidden-process confirmation (atomic, repeated)

```bash
for i in $(seq 1 5); do
  comm -23 <(ls /proc | grep -E '^[0-9]+$' | sort) \
           <(ps -e --no-headers -o pid | sort -u); sleep 1
done | sort | uniq -c | awk '$1>=4{print "persistent hidden PID:",$2}'
```
For any persistent hidden PID, try to read it directly — a rootkit that hides
from `ps` (which reads /proc) but not from a direct stat is inconsistent and
exposes itself:
```bash
ls -la /proc/<PID>/exe /proc/<PID>/cmdline 2>/dev/null
```

### 5 — File/dir hiding probe

```bash
# Count mismatch: readdir (ls) vs link count, a classic name-prefix hide tell
for d in /etc /tmp /usr/sbin /lib/modules/$(uname -r); do
  echo "$d: ls=$(ls -1a "$d" 2>/dev/null | wc -l) links=$(stat -c %h "$d" 2>/dev/null)"
done
# Bruteforce-probe a suspected magic prefix only AFTER evidence suggests one.
```

### 6 — Magic control-channel probe (behavior, last)

Only after generic evidence points here. Some rootkits grant root or toggle
visibility on an unusual signal or a write to a magic path. Probe by *behavior*
(does privilege/visibility change?) rather than firing a known family's exact
trigger blind. Document any probe before running it; this is closer to
interaction than observation.

## Output

```
[KERNEL INTEGRITY — <host>]
Verdict: <no kernel-level indicators | suspicious | kernel compromise likely>
Confidence: <low|med|high> (independent sources agreeing: <list>)
Evidence:
  taint: <value/bits>  dmesg: <residue or "scrubbed/empty">
  module hiding: <lsmod vs /proc/modules vs sysfs result>
  syscall hooks: <handlers resolving into module ranges? which>
  hidden PIDs: <persistent across N samples>
  file hiding: <readdir vs linkcount anomalies>
Hardest-to-forge corroboration: <external/atomic checks that agree>
Next confirmation step: <single concrete action>
```

Route bulky `/proc/kallsyms` and `dmesg` to `evidence-condenser`.

## Report Real Blockers

- `/proc/kallsyms` zeroed (`kptr_restrict`) → need root; request via operator /
  `remote-inspector`, don't conclude "no hooks" from zeros.
- Module signing enforced but taint shows unsigned load → contradiction worth a
  critical alert.
- Tools themselves may be trojaned on a compromised guest — prefer azariaUbuntu's
  external view and atomic local cross-checks over any single guest binary.

## What This Skill Does NOT Do

Detects and characterizes kernel-level tampering. Does not `rmmod`, unhook, or
reboot — all state-changing, all operator-confirmed per the engagement red lines.
Does not assume a named rootkit family before evidence earns the hypothesis.
