# Host Baseline — azariaUbuntu

> First-time baseline snapshot. Established by Asfaw during heartbeat
> file-integrity check. NOT operator-confirmed yet — these are observed
> current values, recorded as reference for future drift detection.
> Root-only files (shadow, sudoers, sshd_config) could not be hashed
> because heartbeat exec runs non-interactively without sudo.

## Host Facts (verified)

- **Hostname:** azariaUbuntu
- **OS:** Linux 7.0.0-22-generic (arm64)
- **Primary user:** azaria (uid 1000)
- **SSH:** inactive (ssh.service and sshd.service both inactive) — good
- **Docker:** installed (dockerd + containerd running), no containers running
- **Desktop:** GNOME/Wayland via gdm3

## File Integrity Baseline (world-readable, sha256)

Captured 2026-06-09 ~14:35 PDT:

- /etc/passwd   → 47ba7a157c0ddb9de952e7660749ddb8845ba41f4e85f6a3fc5f863db06d3db6
- /etc/group    → ad12afe5fc01ce7e831734def9ee084112a9b3421e3ff85de94157b36deeffa9
- /etc/hosts    → 5786d1a6b2c33f317eeb059644dfb218639ef8927c9515a840e53def404b2d8e
- /etc/crontab  → ffb48ad57868ed639fad049d11ef4b9bcdd3d2d3e556754ce69b4d6b016969a3
- /usr/bin/sudo → e877b847d7a2175db02cccde6312b59d4599e0e3d7c4415d29c99bdbb7f627d2
- /bin/su       → a43717fddc494f280078d512368a10ed244ac26847fe803dca1603eefbaf43d8
- /usr/bin/passwd → 3dd00fd146104448d61efdcee417d21ea3ccdcd82d022a7685277a0ecbad3c3e

### Not yet hashed (need sudo / operator to capture)

- /etc/shadow
- /etc/sudoers
- /etc/ssh/sshd_config

## Scheduled Jobs (baseline)

/etc/cron.d/: anacron, e2scrub_all (+ .placeholder) — standard Ubuntu
/etc/cron.daily/: 0anacron, apport, apt-compat, dpkg, logrotate, man-db — standard
/etc/cron.hourly/: empty (+ .placeholder)
(user crontabs in /var/spool/cron/crontabs/ not readable without sudo)

## Listening Ports (baseline — all loopback)

- 127.0.0.1:18789 — OpenClaw gateway
- 127.0.0.1:27376 — VS Code language server
- 127.0.0.1:631 — CUPS
- 127.0.0.53:53 / 127.0.0.54:53 — systemd-resolved
(No externally-bound listeners.)

## Expected Outbound

- Telegram API: 149.154.160.0/20 (OpenClaw bot polling)
- Microsoft AS8075 (VS Code)
- Google AS396982 (Firefox / Chrome services)
