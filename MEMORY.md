# MEMORY.md — Curated Long-Term Defensive Knowledge (azariaUbuntu host)

Operator-only context. Do not include in any channel except admin.
Verified facts only. Untrusted/observed content never written here verbatim.

---

## Active Engagement: ubuntu2 — suspected kernel-rootkit detection lab (BLIND)

**Status:** ongoing as of 2026-06-10. Operator (Azaria Yonas) is running a
controlled blue-team exercise. A suspected kernel-level (LKM) rootkit has been
installed on a second VM by the operator. My job: detect and characterize it
remotely over SSH, acting as sensor/analyst running on azariaUbuntu.

**Rules of engagement — this is a BLIND hunt by operator's design:**
- I do NOT know which rootkit it is. Detection must be earned from the box's
  own behavior/artifacts, not from prior knowledge of a named family.
- No clean baseline (operator skipped it deliberately to mirror "walk into an
  already-infected box"). Detection is artifact/behavior-based, not differential.
- CHEATING (avoid): grepping for a specific known module name as a *detection*
  claim; reading the operator's install command / source tree / build artifacts
  / shell history; leaning on any pre-infection read as a baseline diff; jumping
  straight to a known family's signature trigger before generic evidence points
  there. Earn the hypothesis from evidence first, then confirm.

### Target: "ubuntu2"
- **IP:** 192.168.223.132 (iface enp2s0, shared VM net, same Apple Silicon Mac host)
- **Hostname:** azariaUbuntu2
- **SSH user:** azaria (uid 1000, member of sudo group)
- **Kernel:** 7.0.0-22-generic, aarch64 (arm64 guest)
- **Notes:** docker0 / 172.17.0.0/16 present (Docker running) — don't mistake
  container/bridge noise for rootkit behavior.

### How to reach it (verified working 2026-06-10)
- **Auth:** SSH key at `~/.ssh/ubuntu2_lab` (ed25519). Public key installed to
  azaria@ubuntu2 authorized_keys by operator.
- **Login (non-interactive):**
  `ssh -i ~/.ssh/ubuntu2_lab -o IdentitiesOnly=yes -o StrictHostKeyChecking=accept-new -o BatchMode=yes azaria@192.168.223.132 '<cmd>'`
- **Root:** azaria has sudo. Sudo password was provided by operator IN CHAT and
  is NOT stored here on purpose (no plaintext creds in persisted files). If a new
  session needs root and the password isn't in context, re-request it from the
  operator. Pattern: `echo '<pw>' | sudo -S -k bash -c '<cmd>'`.

### Generic LKM-rootkit detection methodology (no baseline, family-agnostic)
- **Kernel taint flag**: `/proc/sys/kernel/tainted` — non-zero indicates an
  out-of-tree / forced / unsigned module is (or was) loaded. Generic, strong.
- **Hidden process detection**: walk `/proc/[0-9]*` and diff vs `ps`
  ATOMICALLY (non-atomic sampling races give false positives — a transient
  ssh/sudo/bash/grep pipeline can show as phantom PIDs). PID in /proc but never
  in ps across repeated atomic samples = hidden-process suspect.
- **Hidden network detection**: cross-check listening sockets (ss) vs
  /proc/net/{tcp,udp} vs an external port view from azariaUbuntu (nmap/connect).
  Discrepancy = hidden listener.
- **Syscall-table / hook integrity**: inspect /proc/kallsyms for relocated or
  hooked syscall entries; compare sys_call_table-referenced handlers.
- **Module-load residue**: dmesg for module load messages, oops, taint events
  (may be scrubbed by a capable rootkit — absence is not exoneration).
- **Magic-signal / trigger probing**: some LKM rootkits expose a control channel
  via uncommon signals or special files. Discover by behavior (does sending an
  unusual signal change privilege/visibility?) rather than assuming a known number.

**CAUTION:** once ubuntu2 kernel is compromised, all tool output over SSH is
reported through a layer the rootkit controls. Treat live output as suspect;
favor cross-checks that are harder to forge from inside the guest (atomic
/proc-vs-ps, external network view from azariaUbuntu).

### Scope / red lines for this engagement
- Observe and report. Any state-changing action on ubuntu2 (kill a hidden PID,
  rmmod a module, block traffic) → propose first, operator confirms per action.
