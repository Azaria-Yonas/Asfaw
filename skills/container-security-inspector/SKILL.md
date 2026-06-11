---
name: container-security-inspector
description: Use to inspect Docker/container security on the host — privileged containers, exposed Docker socket, host mounts, capabilities, and breakout indicators. Runs on demand and during heartbeat when container activity changes. Both this host and ubuntu2 run Docker, so this is in-scope, not optional.
user-invocable: true
---

# Container Security Inspector

Use this skill to assess container-related risk. Docker is running on both your
hosts (baseline.md and MEMORY.md confirm `dockerd`/`containerd`), which means the
container layer is real attack surface: a misconfigured container is one of the
cleanest paths from "code execution in a container" to "root on the host."

The container layer is also a blind spot for the other skills — a process inside
a container, or the Docker socket itself, looks different from host-native
activity.

## Operating Loop

### Daemon and inventory
```bash
systemctl is-active docker containerd
docker ps -a --format '{{.ID}} {{.Image}} {{.Names}} {{.Status}} {{.Ports}}' 2>/dev/null
docker images --format '{{.Repository}}:{{.Tag}} {{.ID}} {{.Size}}' 2>/dev/null
# Unexpected containers vs USER.md expected set; baseline.md says none should run
```
baseline.md records "no containers running" as normal for this host — so *any*
running container here is a delta worth confirming with the operator.

### Dangerous run configurations (the breakout enablers)
```bash
for c in $(docker ps -q 2>/dev/null); do
  echo "== $(docker inspect -f '{{.Name}}' "$c") =="
  docker inspect "$c" --format '
   Privileged: {{.HostConfig.Privileged}}
   PidMode:    {{.HostConfig.PidMode}}
   NetworkMode:{{.HostConfig.NetworkMode}}
   CapAdd:     {{.HostConfig.CapAdd}}
   SecurityOpt:{{.HostConfig.SecurityOpt}}
   Mounts:     {{range .Mounts}}{{.Source}}->{{.Destination}}({{.RW}}) {{end}}'
done
```
- **Critical breakout configs:**
  - `Privileged: true` — near-equivalent to host root.
  - Mount of `/var/run/docker.sock` into a container — container can drive the
    daemon and spawn a privileged host-level container. Full host compromise path.
  - Host mount of `/`, `/etc`, `/root`, or `/proc` writable into a container.
  - `CapAdd` including `SYS_ADMIN`, `SYS_PTRACE`, `SYS_MODULE`, `DAC_READ_SEARCH`.
  - `PidMode: host` or `NetworkMode: host` — shares host namespaces.
  - `SecurityOpt: [seccomp=unconfined]` or `apparmor=unconfined`.

### Docker socket exposure on the host
```bash
ls -la /var/run/docker.sock          # group 'docker' = root-equivalent membership
getent group docker                  # who is in it? sudo-equivalent, audit tightly
# Socket exposed over TCP (very dangerous if so)
ss -tulnp | grep -E ':2375|:2376'
grep -RsE '\-H tcp://|hosts.*tcp' /etc/docker/daemon.json \
  /lib/systemd/system/docker.service 2>/dev/null
```

### Image trust
```bash
# Images from unexpected registries / unsigned / running as root inside
docker inspect $(docker ps -q 2>/dev/null) \
  --format '{{.Config.Image}} user={{.Config.User}}' 2>/dev/null
# A container whose Config.User is empty/0 runs as root inside — worse if also
# privileged or socket-mounted.
```

### In-container anomalies (if you can exec safely, read-only)
```bash
# From the host, check what container processes map to on the host
for c in $(docker ps -q 2>/dev/null); do
  docker top "$c" 2>/dev/null; done
# Containers spawning shells / reaching the network unexpectedly correlate with
# process-inspector (containerd-shim parent) and network-observer.
```

## Triage

- **Critical** — any running container with the Docker socket mounted, or
  `Privileged: true`, or a writable host-root mount; the Docker TCP socket
  listening without TLS; a non-docker, non-root user in the `docker` group on a
  multi-user host.
- **High** — dangerous added capabilities, host PID/network namespace, unconfined
  seccomp/apparmor.
- **Informational** — an unexpected-but-benign container (confirm with operator),
  images from an unrecognized registry.

## Alert Format

```
[CONTAINER ALERT - {severity}]
Container: <name/id> image=<image> user=<inside-user>
Issue: <privileged | docker-sock-mount | host-root-mount | dangerous-cap | host-namespace | tcp-socket | docker-group>
Host impact: <one sentence — why this reaches host root>
Recommendation: <confirm legitimacy with operator | reconfigure via harden | incident-response>
```

## Report Real Blockers

- `docker` CLI needs daemon socket access (root or docker group). If denied, note
  you could enumerate containers but not inspect configs.
- Rootless Docker / Podman changes the model (less host risk by design) — detect
  which is in use before applying these rules.

## Ubuntu-Specific Notes

- Membership in the `docker` group is effectively passwordless root on the host
  (you can `docker run -v /:/host`). Treat the group like sudoers — audit it in
  `privilege-escalation-detector` too.
- `containerd-shim`/`runc` processes are normal parents for container PIDs; don't
  let `process-inspector` flag them as anomalous once containers are expected.
- The `172.17.0.0/16` docker0 bridge traffic is intra-container (per baseline.md
  and MEMORY.md) — a separate trust zone, not internet egress.

## What This Skill Does NOT Do

Inspects and flags container risk. Does not stop, reconfigure, or remove
containers — that is `incident-response`/`harden` with operator confirmation.
Does not exec arbitrary commands inside containers beyond read-only inspection;
interacting with a possibly-malicious container is itself risky.
