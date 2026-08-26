# actuator — ShadowKube response engine

The actuator is the ShadowKube component that receives alarms from the
detector, decides whether to do an in-situ honeypot conversion (preferred)
or directly eliminate the compromised pod (fallback), and runs the chosen
flow end-to-end. It also owns the edge-level Traffic Proxy blacklist and
schedules teardown after the case-study window.

This is **Phase 4** of the lab.

## Responsibilities

1. **Strategy Selection** — when the detector's alarm fires, choose between
   *ConvertInSitu* (3-phase conversion) and *DirectEliminate* (delete pod +
   blacklist IPs). The feasibility gates are:
   - Compromised pod has no writeable `hostPath` volume
   - Cluster node count > `THRESHOLD_NODES`
   - Replica pods of the compromised workload exist on other nodes

   All three must be true for `ConvertInSitu`; otherwise `DirectEliminate`.

2. **3-Phase Honeypot Conversion** (per ShadowKube §3.3):
   - **Phase 1 — Network Reconfiguration (~2.2s)**: iptables DNAT on the
     compromised node redirects outbound cluster calls (e.g. `keystore:9000`,
     `backend:8000`) to the shadow cluster's IP, rewriting both
     destination host AND port because k3d's port mapping makes the
     shadow frontend `30081` vs prod's `30080`.
   - **Phase 2 — Pods Sanitation (~5.0s)**: delete every pod on the target
     node EXCEPT the compromised one. The API server reschedules them on
     other nodes (where replicas of their workloads exist, per the
     strategy gate).
   - **Phase 3 — Sensitive Info Alteration (~1.4s)**: replace SA tokens on
     the target node + pod with shadow-cluster equivalents and document
     the would-be monitor install. In the lab, Phase 1 already neutered
     the pod's effective cluster access, so Phase 3 is largely defense
     in depth (marker file + log).

3. **Traffic Proxy** — maintains a blacklist of source IPs. New external
   connections from blacklisted source IPs are routed to the shadow
   cluster. In lab mode the proxy is a *passive decision logger* — it
   records the routing decision via `/decide/{src}` rather than standing
   up an actual TCP proxy in front of the Codespace ingress.

4. **Teardown** — after `TEARDOWN_AFTER` (default 20 min), the actuator:
   - Flips the proxy into full-capture mode for the affected IPs
   - Removes Phase 1 iptables rules
   - Resets the affected group's detector baseline via
     `POST $DETECTOR_URL/baseline/<group>/reset`
   - Marks the conversion record torn down

## Layout

```
actuator/
├── go.mod
├── Dockerfile
├── README.md
├── cmd/
│   └── actuator/main.go         HTTP server, alarm intake, strategy, teardown
├── internal/
│   ├── config/config.go         env-driven Config
│   ├── strategy/strategy.go     Decision + Select()
│   ├── conversion/
│   │   ├── conversion.go        orchestrate 3 phases + timings
│   │   ├── iptables.go          Phase 1 DNAT + isolation rules
│   │   ├── sanitize.go          Phase 2 pod deletion
│   │   ├── secrets.go           Phase 3 SA token + monitor marker
│   │   └── kube.go              k8s API helpers
│   ├── proxy/proxy.go           source-IP blacklist + decision log
│   ├── teardown/teardown.go     scheduled teardown after TeardownAfter
│   └── state/state.go           in-memory + on-disk conversion records
└── deploy/
    ├── 00-rbac.yaml             SA + ClusterRole + ClusterRoleBinding
    ├── 01-config.yaml           ConfigMap (threshold, teardown, shadow IP)
    └── 02-deployment.yaml       Deployment + Service (hostNetwork, privileged)
```

## Configuration

All knobs are env-driven; the ConfigMap in `deploy/01-config.yaml` maps
straight to env vars. The deployment mounts it via `envFrom`.

| Var | Default | Meaning |
|---|---|---|
| `ACTUATOR_ADDR` | `:8081` | HTTP listen address |
| `NODE_NAME` | downward API | informational; the actuator is cluster-wide |
| `SHADOW_CLUSTER_IP` | *required when ACT_ON_ALARM=true* | shadow cluster server IP on `shadowkube-net` |
| `SHADOW_SERVICE_PORT` | `30081` | shadow frontend NodePort |
| `THRESHOLD_NODES` | `1` | min cluster node count for in-situ conversion |
| `TEARDOWN_AFTER` | `20m` | time before scheduled teardown |
| `ACT_ON_ALARM` | `false` | false = dry-run, log only |
| `ACTUATOR_STATE_DIR` | `/var/lib/shadowkube/actuator` | persistence dir |
| `DETECTOR_URL` | — | detector base URL for teardown-time baseline reset |

## Build

```bash
cd actuator
CGO_ENABLED=0 go build ./...
CGO_ENABLED=0 go vet ./...
CGO_ENABLED=0 go build -o /tmp/actuator ./cmd/actuator
```

The binary uses only `client-go` and stdlib (no cilium/ebpf / libbpf).

## Docker image

```bash
docker build -t shadowkube-actuator:lab .
```

Multi-stage: golang:1.22-bookworm → debian:bookworm-slim + iptables.

## Deploy (lab)

After `k3d image import shadowkube-actuator:lab -c prod-cluster`:

```bash
kubectl --context k3d-prod-cluster apply -f actuator/deploy/
```

After applying, fill in `SHADOW_CLUSTER_IP`:

```bash
SHADOW_IP=$(docker inspect -f '{{range .NetworkSettings.Networks}}{{.IPAddress}}{{end}}' \
  k3d-shadow-cluster-server-0 | head -1)
kubectl --context k3d-prod-cluster -n shadowkube-system patch cm shadowkube-actuator-config \
  --type merge -p "{\"data\":{\"SHADOW_CLUSTER_IP\":\"$SHADOW_IP\"}}"
kubectl --context k3d-prod-cluster -n shadowkube-system rollout restart deploy/shadowkube-actuator
```

When you're ready for live action, flip `ACT_ON_ALARM: "true"` in the
ConfigMap and restart.

## HTTP API

| Method | Path | Purpose |
|---|---|---|
| `GET` | `/healthz` | liveness/readiness |
| `POST` | `/alarms` | detector webhook; runs strategy + dispatches |
| `GET` | `/status` | active conversions + history + blacklist snapshot |
| `POST` | `/teardown/{podUID}?immediate=1` | manual teardown for a pod |
| `GET` | `/blacklist` | current traffic-proxy blacklist |
| `POST` | `/blacklist/{ip}?ttl=…&reason=…` | operator-driven blacklist add |
| `GET` | `/decide/{src}` | passive proxy decision log |

### Example: trigger an alarm

```bash
curl -X POST http://localhost:8081/alarms \
  -H 'Content-Type: application/json' \
  -d '{
    "group": "labels:group=weather-app",
    "node":  "k3d-prod-cluster-server-0",
    "pod":   "weather-app-frontend-6f8b9c7d5-x2k4p",
    "podIp": "10.42.0.17",
    "sourceIp": "203.0.113.42"
  }'
```

Response:

```json
{
  "decision": "convert_in_situ",
  "reason":   "all feasibility checks passed: no hostPath, sufficient nodes, replicas elsewhere",
  "record":   { "pod": "...", "timings": { "phase1": "2.13s", "phase2": "5.07s", "phase3": "1.34s", "total": "8.55s" }, ... }
}
```

### Example: query state

```bash
curl http://localhost:8081/status | jq
```

Returns active conversions, full history, blacklist, and the loaded config.

## Smoke test

```bash
# Start actuator in dry-run (no SHADOW_CLUSTER_IP needed).
ACT_ON_ALARM=false ACTUATOR_STATE_DIR=/tmp/actuator-state /tmp/actuator &
sleep 1

# Health check.
curl -sf http://localhost:8081/healthz

# Fire a fake alarm (will fail PodByUID but the strategy decision is logged).
curl -X POST http://localhost:8081/alarms \
  -H 'Content-Type: application/json' \
  -d '{"group":"labels:group=weather-app","node":"node0","pod":"fake-uid","podIp":"10.0.0.1"}'

# Inspect state.
curl -s http://localhost:8081/status | jq

# Stop.
pkill -f /tmp/actuator
```

Expected:

- `/healthz` returns `{"status":"ok"}`.
- The alarm request returns `decision=convert_in_situ` (dry-run path)
  with a populated `record` carrying per-phase timings.
- `/status` shows the conversion in `conversions[]` with `torndown=false`.

## Limitations & notes

- **Phase 1 iptables** uses `hostNetwork:true` + `NET_ADMIN` so the rules
  apply cluster-wide from the single Deployment. A more locked-down prod
  deployment would use a per-node DaemonSet.
- **Phase 3 SA token replacement** is a marker file in the lab — Phase 1's
  iptables redirection already cuts the pod's effective cluster access.
- **Traffic Proxy** is passive: it logs `/decide/{src}` results rather than
  standing up a TCP proxy at the Codespace ingress. The decision logic and
  blacklist persistence are real and feed Phase 5's Table 6 evaluation.
- **k3d port rewrite** — shadow frontend is `30081`, prod is `30080`. The
  DNAT rule rewrites both destination IP AND port (documented in
  `conversion/iptables.go`).
- **No live testing yet** — verified via `go build`, `go vet`, and a dry-run
  smoke test of the orchestrator. End-to-end comes when the Codespace
  exists; flip `ACT_ON_ALARM=true` after wiring the detector's
  `ACTUATOR_URL` to this service.
