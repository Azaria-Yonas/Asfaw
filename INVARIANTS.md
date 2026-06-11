# INVARIANTS.md — Universal Linux Red Flags (no baseline required)

These are things that are wrong on **any** clean Linux host, regardless of its
role, configuration, or what "normal" looks like for it. They need no baseline
diff — the condition itself is the finding. This is what lets the agent defend a
host it has no clean snapshot of (the ubuntu2 case, and any "walk into an
unknown box" scenario).

Use this as the reference set for `blind-audit`, and as a fast triage anywhere.
A hit here is high-signal; treat each as alert-worthy until explained.

## Account / privilege invariants

- **Only `root` has uid 0.** `awk -F: '$3==0{print $1}' /etc/passwd` returns
  exactly `root`. Any other uid-0 account = critical.
- **No password hash directly in `/etc/passwd`** (second field should be `x`).
- **No empty-password accounts** that can log in:
  `awk -F: '($2==""){print $1}' /etc/shadow`.
- **`/etc/shadow` is not world/group-readable** (expected `0640 root:shadow`).
- **`sudo`/`docker` group membership is small and known** — both are effectively
  root on the host.

## Loader / library invariants

- **`/etc/ld.so.preload` should not exist** on a stock Ubuntu host. If present,
  it injects a library into *every* dynamically-linked process — a top-tier
  rootkit/backdoor mechanism. Existence alone = critical.
- **No `LD_PRELOAD`/`LD_LIBRARY_PATH`** set globally in `/etc/environment`,
  systemd unit env, or service defaults pointing at writable/temp paths.

## Filesystem invariants

- **No setuid/setgid binaries in writable/temp dirs** (`/tmp`, `/dev/shm`,
  `/var/tmp`, home dirs). SUID root anywhere a user can write = instant privesc.
- **No setuid on shells or interpreters** (`bash`, `dash`, `python`, `perl`,
  `find`, `vim`, `awk`, `env`) — these are GTFOBins instant-root.
- **No executables running from `/dev/shm`** — RAM-backed, a favorite for
  fileless implants.
- **No running binary deleted from disk** (`/proc/PID/exe -> (deleted)`) for a
  non-trivial process — classic memory-resident implant.

## Kernel invariants

- **`/proc/sys/kernel/tainted` is `0`** on a host expected to run only stock,
  signed modules. Non-zero (esp. out-of-tree/unsigned bits) = lead.
- **`lsmod`, `/proc/modules`, and `/sys/module` agree.** A module visible to one
  but not the others is hiding.
- **`ps` and `/proc` agree on which PIDs exist** (atomic, repeated sampling). A
  PID persistently in `/proc` but never in `ps` = hidden process.
- **`ss` and `/proc/net/tcp` and an external scan agree** on open ports. A port
  reachable from outside but absent from the host's own `ss` = hidden listener.

## Logging / forensics invariants

- **On an active host, logs grow.** A 0-byte or frozen `auth.log`/`wtmp`/`btmp`
  on a host with meaningful uptime = anti-forensics, not cleanliness.
- **`journalctl --verify` passes.** A verify failure = corrupted/tampered journal.
- **Logging services are running** (`rsyslog`, `systemd-journald`). Stopped
  logging without an approved change = blinding.
- **History not redirected to `/dev/null`** in shell rc files.

## Persistence invariants

- **systemd units and timers are package-owned or operator-known.** An
  `/etc/systemd/system/*.service` that no package owns and runs from `/tmp` or
  fetches remote code = planted.
- **cron entries are attributable.** A cron job invoking `curl|bash`,
  `base64 -d|sh`, or `/dev/tcp/` = malicious.
- **`authorized_keys` contents are operator-known.** An unexplained key, or a key
  with `command=`/`no-pty` you didn't expect, = backdoor.
- **`/etc/update-motd.d/`, `/etc/rc.local`, PAM modules, udev rules** contain no
  network-fetch or temp-path execution.

## Network / process invariants

- **No shell whose parent is a network daemon** (`bash`/`python` under `nginx`,
  `apache2`, `postgres`, `mysqld`) — canonical reverse shell.
- **No listener bound `0.0.0.0` for a service that should be loopback-only**
  (postgres, redis, mysql, docker API).
- **No outbound connection from a shell/interpreter to a high port on an
  unfamiliar IP** — C2 beacon shape.
- **Process count is plausible** (a Linux host with <50 processes where `ps` is
  being filtered is itself suspicious).

## How to use this file

1. `blind-audit` runs the full sweep; this is its rule source.
2. Any skill can spot-check the relevant subset.
3. A single invariant hit is enough to open an investigation — consult
   `PLAYBOOK.md` for the follow-on chain.
4. These are necessary-not-sufficient: passing all of them does **not** prove a
   host is clean (a capable rootkit hides its own violations). Agreement across
   independent sources is what raises confidence — see the trust model in
   `blind-audit` and `remote-inspector`.
