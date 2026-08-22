# probe — ShadowKube Behavioral Probe (Phase 2)

The probe collects three syscall categories on every prod-cluster node:

| Category   | eBPF backend (bpftrace)         | auditd backend (fallback) |
|------------|---------------------------------|---------------------------|
| exec       | `tracepoint:syscalls:sys_enter_execve{,at}` | syscall 59 (execve)       |
| file       | `tracepoint:syscalls:sys_enter_openat`     | syscall 257 (openat)      |
| net        | `kprobe:tcp_connect`            | syscall 42 (connect)      |

Events are enriched with Table 1 pod metadata (Name, Namespace, Labels,
Annotations, ControlledBy) via a cgroup-id -> pod-UID cache, then shipped as
NDJSON over HTTP to the detector (Phase 3). Until the detector exists, set
`PROBE_DRY_RUN=true` to print events to stdout for verification.

## Backend selection

At startup the probe checks `/sys/kernel/btf/vmlinux`. If present and
`bpftrace` is on PATH, the eBPF backend runs; otherwise the auditd backend
runs. The choice is reported in the pod log on startup.

`PROBE_MODE=ebpf` forces eBPF (fails fast if unavailable).
`PROBE_MODE=auditd` forces auditd.
`PROBE_MODE=auto` (default) prefers eBPF.

## Build

```bash
cd probe
docker build -t weather-app-probe:lab .
k3d image import weather-app-probe:lab -c prod-cluster
```

## Deploy

```bash
kubectl --context k3d-prod-cluster apply -f probe/deploy/
kubectl --context k3d-prod-cluster -n shadowkube-probe get pods -w
```

Expect one probe pod per prod-cluster node (server + agent).

## Verify (Phase 2 — no detector yet)

1. Tail the probe logs:
   ```bash
   kubectl --context k3d-prod-cluster -n shadowkube-probe logs -f <probe-pod>
   ```
   You should see `probe: starting node=... mode=auto dryRun=true detector=` followed by
   `probe: backend=ebpf` (or `auditd`) once the backend attaches.

2. Generate a benign event:
   ```bash
   curl "http://localhost:30080/weather?city=London"
   ```

3. Confirm events stream to stdout (dry-run mode). Expected lines look like:
   ```json
   {"ts":"2025-08-22T...","type":"exec","node":"k3d-prod-cluster-server-0","pid":42,"pod":{"name":"frontend","namespace":"dev-namespace","labels":{"group":"weather-app","app":"frontend","tier":"frontend"},"controlledBy":[{"kind":"ReplicaSet","name":"frontend-..."}]},"payload":{"cmd":"ping"}}
   {"ts":"2025-08-22T...","type":"net","node":"k3d-prod-cluster-server-0","pid":42,"pod":{...},"payload":{"dstIp":"10.42.x.x","dstPort":8000}}
   ```

4. Verify the enricher attached pod metadata correctly:
   - Events from `frontend` should carry `labels.group=weather-app`.
   - Events from `legacy-debug-privileged` should carry `labels.group=legacy-debug`.

5. Run an attack-style payload and confirm it shows up in the stream:
   ```bash
   curl "http://localhost:30080/weather?city=London;id"
   ```
   Look for an `exec` event with `cmd` ending in `id` (or whatever the shell
   concatenated). The detector in Phase 3 is what flags this — the probe just
   needs to observe it.

## Switching to live mode

When Phase 3 ships the detector, edit `probe/deploy/01-config.yaml`:

```yaml
PROBE_DRY_RUN: "false"
DETECTOR_URL: "http://<detector-host>:8080/events"
```

(Inside a k3d cluster, `<detector-host>` is typically the host machine; on
Codespaces `host.docker.internal:8080` works from a node container that has
been configured with `--add-host=host.docker.internal:host-gateway`.)

Then `kubectl --context k3d-prod-cluster -n shadowkube-probe rollout restart ds shadowkube-probe`.

## Layout

```
probe/
├── cmd/probe/main.go         pipeline orchestration, mode selection
├── internal/
│   ├── event/event.go        shared Event schema (probe <-> detector)
│   ├── backend/
│   │   ├── backend.go        Backend interface
│   │   ├── ebpf.go           bpftrace-based backend
│   │   └── auditd.go         auditd-fallback backend
│   ├── enrich/enricher.go    cgroup -> pod metadata enrichment
│   ├── transport/http.go     NDJSON HTTP transport (with --dry-run)
│   └── config/config.go      env-driven configuration
├── bpftrace/                 bpftrace scripts (execve, openat, connect)
├── auditd/rules.d/           audit rules for fallback mode
├── deploy/                   k8s manifests (DaemonSet + RBAC + ConfigMap)
├── Dockerfile                multi-stage golang -> debian+bpftrace+auditd
└── go.mod
```
