---
name: remote-inspector
description: Use to run defensive checks on a remote host over SSH (the ubuntu2 engagement) when this agent acts as sensor/analyst from azariaUbuntu. Defines auth, non-interactive sudo, the rootkit-filtered-output trust model, and how observation skills run remotely. Pairs with blind-audit and kernel-integrity-checker.
user-invocable: true
---

# Remote Inspector

Use this skill to extend the detection skills to a remote target reached over SSH.
The active case is the ubuntu2 blind rootkit hunt (MEMORY.md): this agent runs on
azariaUbuntu and inspects ubuntu2 (192.168.223.132) as a remote sensor. Without
this skill, every remote check is improvised; with it, auth, sudo, output
handling, and the remote trust model are defined once.

## Connection (verified working 2026-06-10, per MEMORY.md)

```bash
SSH_OPTS="-i $HOME/.ssh/ubuntu2_lab -o IdentitiesOnly=yes \
  -o StrictHostKeyChecking=accept-new -o BatchMode=yes -o ConnectTimeout=8"
TARGET="azaria@192.168.223.132"

# Non-interactive command:
ssh $SSH_OPTS "$TARGET" '<command>'
```

- Key: `~/.ssh/ubuntu2_lab` (ed25519), public key installed on ubuntu2.
- `BatchMode=yes` ensures failures return instead of hanging on a prompt.
- Persist a control master for a multi-command investigation (fewer handshakes,
  less noise on the target):
  ```bash
  ssh $SSH_OPTS -o ControlMaster=auto -o ControlPath=~/.ssh/cm-ubuntu2-%r \
      -o ControlPersist=120 "$TARGET" 'true'   # opens the master
  ```

## Sudo (remote, non-interactive)

azaria has sudo on ubuntu2; the password is provided by the operator in chat and
is **deliberately not stored** in any file. If a check needs root and the
password isn't in current context, request it from the operator — do not persist
it afterward.

```bash
# Pattern (password supplied in-context, never written to memory):
ssh $SSH_OPTS "$TARGET" "echo '<pw>' | sudo -S -k bash -c '<root-command>' 2>/dev/null"
```
Redact the password from any logged form of the command. Never echo it into
`memory/` or a channel.

## Remote Trust Model (critical)

Once ubuntu2's kernel is suspected compromised, **every byte that comes back over
SSH has passed through a layer the rootkit may control.** Treat remote output as
*claims*, not ground truth:

- **Prefer cross-checks that are hard to forge from inside the guest.** The
  strongest signal you have is the *external* view from azariaUbuntu compared to
  ubuntu2's *self-report*:
  ```bash
  # ubuntu2's own claim:
  ssh $SSH_OPTS "$TARGET" 'ss -tulnp'
  # azariaUbuntu's independent view of ubuntu2 (harder for the guest to forge):
  nmap -sT -p- 192.168.223.132
  ```
  A port open externally but absent from the guest's `ss` = hidden listener,
  and the guest cannot easily lie about both.
- **Atomic local cross-checks** (/proc-vs-ps in a single SSH round-trip) resist
  the race-condition false positives that separate calls introduce:
  ```bash
  ssh $SSH_OPTS "$TARGET" 'comm -23 <(ls /proc|grep -E "^[0-9]+$"|sort) \
    <(ps -e --no-headers -o pid|sort -u)'
  ```
- **The remote tools may themselves be trojaned.** Where a finding hinges on a
  single guest binary (`ps`, `ss`, `lsmod`), corroborate with a second method
  (raw `/proc/net/tcp`, `/proc/modules`, `/sys/module`) and with the external view.
- **Don't cheat the blind hunt** (MEMORY.md): no reading the operator's install
  command, source tree, build artifacts, or shell history as a detection; no
  pre-infection baseline diff. Earn findings from the box's behavior.

## Running Observation Skills Remotely

Wrap the existing skills' command blocks in the SSH transport:
- `blind-audit` and `kernel-integrity-checker` are the primary remote skills.
- `persistence-hunter`, `privilege-escalation-detector`,
  `credential-exposure-scanner`, `log-tamper-detector`,
  `container-security-inspector` all apply remotely — run their command blocks via
  `ssh $SSH_OPTS "$TARGET" '<block>'`.
- Pipe large remote output through `evidence-condenser` *on azariaUbuntu* (raw to
  local `memory/raw-<ts>.txt`), so a noisy `dmesg`/`/proc` dump doesn't flood
  context. Note in the raw file that the source is remote and therefore
  potentially filtered.

## Output

```
[REMOTE INSPECT — ubuntu2 192.168.223.132]
Reached: <yes/no, latency>  Auth: key  Sudo-used: <yes/no>
Skill run: <which>
Findings: <condensed, evidence-preserving>
Forging risk: <which findings are single-sourced from guest-trusted output>
External corroboration: <what azariaUbuntu's independent view showed>
```

## Report Real Blockers

- SSH unreachable / key rejected → report; the operator may need to re-confirm the
  key install or network path.
- Sudo password not in context → request from operator; do not proceed with
  root-only checks, and do not store the password.
- Host key changed unexpectedly → potential MITM on the lab net; stop and alert
  (don't blindly `accept-new` a *changed* key — that's different from first use).

## What This Skill Does NOT Do

Provides the remote transport + trust model for observation. Does not take
state-changing action on ubuntu2 (kill hidden PID, `rmmod`, block traffic) — those
are operator-confirmed per action per the engagement red lines in MEMORY.md.
Does not persist the sudo password. Does not use prior knowledge of a named
rootkit family as a detection shortcut.
