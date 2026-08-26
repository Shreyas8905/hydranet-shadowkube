# detector — ShadowKube Detector (Phase 3)

The detector consumes probe events (NDJSON), applies Algorithm 1 (LCS
baseline extraction) and Algorithm 2 (Levenshtein online detection), and
fires an alarm when a group's windowed cumulative suspicion `D` exceeds
the threshold `L`.

```
probe ---> POST /events (NDJSON)
              │
              ▼
        ┌─────────────────────────────┐
        │ detector (Go HTTP server)   │
        │                             │
        │  per-group:                 │
        │    - file baseline          │
        │    - exec baseline (per bin)│
        │    - net peer set           │
        │    - ring-buffered D window  │
        │                             │
        │  when D > L  ─────►  alarm  │
        │                       │     │
        │                       ▼     │
        │            log + webhook to │
        │            ACTUATOR_URL     │
        └─────────────────────────────┘
```

## Endpoints

| Method | Path | Purpose |
|---|---|---|
| POST | `/events` | ingest NDJSON (one `event.Event` per line) |
| GET | `/baselines` | list groups with persisted baselines |
| POST | `/baseline/{group}/freeze` | switch a group to scoring-only |
| POST | `/baseline/{group}/reset` | clear a group's in-memory state and on-disk file |
| GET | `/healthz` | health check |

Group keys in URLs are URL-safe; the resolver accepts both the
canonical form (`labels:group=weather-app`) and the on-disk safe form
(`labels_group_weather-app`).

## Configuration (env vars, set by `deploy/00-config.yaml`)

| Var | Default | Meaning |
|---|---|---|
| `DETECTOR_ADDR` | `:8080` | listen address |
| `DETECTOR_BASELINE_DIR` | `/var/lib/shadowkube/baselines` | persisted baselines |
| `DETECTOR_LOG_PATH` | `/var/log/shadowkube/events.ndjson` | NDJSON log of every received event (used by `baselinectl extract`) |
| `DETECTOR_TI` | `60s` | window length for cumulative `D` |
| `DETECTOR_L` | `3.0` | alarm threshold (`D > L`) |
| `DETECTOR_PENALTY_UNGROUP` | `0.5` | constant `x` per ungroupable event |
| `DETECTOR_PENALTY_NETBAD` | `1.0` | constant `c` for net events to unexpected destinations |
| `DETECTOR_ALGO1_ONLINE` | `true` | if `true`, baselines keep learning from new events |
| `ACTUATOR_URL` | (empty) | webhook URL the detector POSTs alarm JSON to (Phase 4) |

## Build

```bash
cd detector
docker build -t shadowkube-detector:lab .
# Load into prod-cluster so the Deployment can reference it:
k3d image import shadowkube-detector:lab -c prod-cluster
```

## Deploy

```bash
kubectl --context k3d-prod-cluster apply -f detector/deploy/
kubectl --context k3d-prod-cluster -n shadowkube-system get pods -w
# Port-forward for verification:
kubectl --context k3d-prod-cluster -n shadowkube-system port-forward svc/shadowkube-detector 8080:8080 &
```

## Verify

### 1. Health + ingest

```bash
curl http://localhost:8080/healthz
# → ok

curl -X POST -H 'Content-Type: application/x-ndjson' \
  --data-binary '{"ts":"2026-08-23T00:00:00Z","type":"exec","node":"n1","pod":{"uid":"u","name":"frontend","namespace":"dev-namespace","labels":{"group":"weather-app"}},"payload":{"cmd":"ping"}}' \
  http://localhost:8080/events
# → {"alarms":0,"received":1}
```

### 2. Trigger an alarm

Default `L=3.0`, `c=1.0` (net penalty), `x=0.5` (ungroupable). Send 4
net events from a `weather-app` pod to destinations not in the baseline
peer set:

```bash
for i in 1 2 3 4; do
  curl -s -X POST -H 'Content-Type: application/x-ndjson' \
    --data-binary "$(printf '{"ts":"2026-08-23T00:02:0%dZ","type":"net","node":"n1","pod":{"uid":"u","name":"frontend","namespace":"dev-namespace","labels":{"group":"weather-app"}},"payload":{"dstIp":"203.0.113.%d","dstPort":4444}}' $i $i)" \
    http://localhost:8080/events
done
# The 4th response will be {"alarms":1,...}; check the pod logs to see
# the structured alarm JSON line.
kubectl --context k3d-prod-cluster -n shadowkube-system logs -f deploy/shadowkube-detector
```

### 3. Offline baseline seeding

While the detector is running in `PROBE_DRY_RUN=true` mode (probe
prints to stdout), capture that output to a file and use it as input to
`baselinectl extract`:

```bash
# After the probe has been dry-running for a few minutes:
kubectl --context k3d-prod-cluster -n shadowkube-probe logs <probe-pod> > /tmp/events.ndjson

# (In a follow-up release the probe will log directly to a shared
#  /var/log/shadowkube/events.ndjson; for now we capture from stdout.)

# Copy the captured NDJSON into the detector pod, then run:
kubectl --context k3d-prod-cluster -n shadowkube-system exec deploy/shadowkube-detector -- \
  baselinectl extract --from /var/log/shadowkube/events.ndjson

# Inspect:
kubectl --context k3d-prod-cluster -n shadowkube-system exec deploy/shadowkube-detector -- \
  baselinectl status
```

Once baselines exist, restart the detector so it cold-loads them.

### 4. Freeze a group after an alarm

```bash
# Stop online learning for the suspicious group so attacker behavior
# doesn't poison the baseline (recommended once an alarm fires):
curl -X POST http://localhost:8080/baseline/labels:group=weather-app/freeze
```

### 5. Reset a group after the actuator finishes teardown

```bash
# Phase 4 will signal this once the attacker has been observed long enough.
curl -X POST http://localhost:8080/baseline/labels:group=weather-app/reset
```

## Layout

```
detector/
├── cmd/
│   ├── detector/main.go       HTTP server (ingest, baselines, freeze, reset)
│   └── baselinectl/main.go    offline baseline extraction / status
├── internal/
│   ├── algo1/lcs.go           Algorithm 1: LCS-based baseline extraction
│   ├── algo2/
│   │   ├── levenshtein.go     Wagner-Fischer edit distance (normalized)
│   │   └── scorer.go          Algorithm 2: per-event d, windowed D, alarm
│   ├── baseline/
│   │   ├── baseline.go        Baseline interface + Config
│   │   ├── file.go            per-group file path baseline
│   │   ├── exec.go            per-binary argv baseline + package-local Levenshtein
│   │   ├── net.go             per-group allowed peer set
│   │   └── store.go           disk persistence (atomic .json writes)
│   ├── config/config.go       env-driven configuration
│   ├── group/group.go         GroupKey resolution + per-group state index
│   └── window/window.go       time-windowed ring buffer (Ti)
├── Dockerfile                  multi-stage golang:1.22 -> debian:bookworm-slim
└── deploy/
    ├── 00-config.yaml         ConfigMap (Ti, L, x, c, actuator URL, ...)
    └── 01-deployment.yaml     Deployment + ClusterIP Service
```