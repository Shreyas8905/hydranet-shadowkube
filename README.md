# ShadowKube Reimplementation

ShadowKube is a laboratory reimplementation of *ShadowKube: enhancing Kubernetes security with behavioral monitoring and honeypot integration* by Chen et al. The paper combines runtime behavior monitoring, anomaly detection, and a shadow-cluster honeypot to contain compromised Kubernetes workloads without immediately destroying the attacker's activity space.

This repository turns that design into a reproducible Codespaces lab. A production-like k3d cluster runs a deliberately vulnerable weather application and representative Kubernetes misconfigurations. A second k3d cluster mirrors the application with decoy credentials. Go services observe production behavior, establish per-workload baselines, detect deviations, and coordinate honeypot conversion or direct elimination.

The project is intended for private, isolated research and education. It is not a production security product and must not be deployed on an internet-facing or shared Kubernetes cluster.

## What This Project Demonstrates

The implementation covers the paper's complete system flow:

1. Normal application behavior is collected from production nodes.
2. Events are enriched with Kubernetes pod metadata and sent as NDJSON.
3. The detector groups events and learns behavioral baselines.
4. Levenshtein and network-deviation scoring accumulate suspicion in a time window.
5. An alarm is sent to the actuator when the configured threshold is crossed.
6. The actuator selects in-situ conversion when cluster availability allows it, otherwise it eliminates the compromised pod.
7. Conversion redirects traffic toward the shadow cluster, sanitizes sibling pods, and replaces sensitive access information.
8. Phase 5 scripts reproduce two paper-inspired attack narratives and measure conversion timings against Table 6.

## Current Status

| Phase | Scope | Status |
|---|---|---|
| 1 | Dual-cluster topology, vulnerable weather app, decoys, and misconfigurations | Complete |
| 2 | Go behavioral probe with bpftrace and auditd fallback | Complete |
| 3 | LCS baseline, Levenshtein scoring, windows, persistence, and alarm webhook | Complete |
| 4 | Strategy selection, honeypot conversion, proxy blacklist, and teardown | Complete |
| 5 | Case-study simulator and Table 6 timing benchmark | Complete |

All five Go modules currently pass `go build`, `go vet`, and `go test`. There are no automated test files yet, so `go test` currently verifies compilation; live behavior still requires the Codespace and Kubernetes tools.

## System Architecture

```text
                         +-------------------+
                         |  Shadow cluster   |
                         |  decoy services   |
                         |  bait credentials |
                         +---------^---------+
                                   |
                          redirected traffic
                                   |
+-------------+    +--------+    +--------+    +----------+
| Weather app | -> | Probe  | -> |Detector| -> | Actuator |
| prod cluster|    |DaemonSet|   |NDJSON  |    | response |
+-------------+    +--------+    +--------+    +----------+
       ^                              |              |
       |                              +---- alarm ---+
       |                                             |
       +------------- normal / attack traffic -------+
```

### Production cluster

The production cluster contains the real lab workload and `sk-lab-...` credentials. Its services expose a weather endpoint and intentionally include security weaknesses needed to exercise the detector and actuator.

### Shadow cluster

The shadow cluster uses matching service names and labels so redirected requests continue to look normal to an attacker. It contains `sk-BAIT-...` credentials and intentionally mirrored insecure behavior for observation.

### Probe

The probe runs as a privileged DaemonSet on production nodes. It collects:

- `exec`: command execution from `execve`/`execveat`
- `file`: file access from `openat`
- `net`: TCP connections from `connect`

When kernel BTF and bpftrace are available, the eBPF backend is preferred. The auditd backend is available as a fallback. Each event is enriched with pod name, namespace, labels, annotations, and owner references before transport.

### Detector

The detector receives one JSON event per line through `POST /events`. Group resolution follows the paper's metadata model:

1. `labels[group]`, represented as `labels:group=<value>`
2. `<namespace>/<name>` when the group label is absent
3. `ungroupable` when pod identity cannot be resolved

Algorithm 1 builds file and command feature baselines using LCS. Network baselines retain expected peer destinations. Algorithm 2 calculates event deviation using normalized Levenshtein distance for file and command events, and fixed penalties for unexpected network or ungroupable events. Scores are accumulated in a time window of length `Ti`; an alarm is raised when `D > L`.

The detector persists baselines under `/var/lib/shadowkube/baselines/` and logs received events as NDJSON under `/var/log/shadowkube/events.ndjson`.

### Actuator

The actuator receives detector alarms at `POST /alarms`. It first checks the strategy gates:

- the target pod has no writeable hostPath dependency;
- the cluster has more than the configured minimum node count; and
- replicas for the affected workload exist on other nodes.

If all gates pass, the actuator runs three conversion phases:

1. **Network reconfiguration:** install DNAT and isolation rules for the compromised node and redirect cluster service traffic to the shadow side.
2. **Pods sanitation:** remove sibling pods from the compromised node so they can be recreated elsewhere by Kubernetes.
3. **Sensitive information alteration:** replace or invalidate production access information and record the monitor-installation step.

If conversion is infeasible, the actuator chooses direct pod elimination and blacklists relevant source or pod addresses. Conversion records are persisted under the configured actuator state directory. A teardown scheduler can later remove redirect rules, reset the detector group, and finalize the record.

## Repository Layout

```text
.
├── .devcontainer/
│   ├── devcontainer.json       Codespaces resources and container settings
│   └── postcreate.sh           Installs tools and creates both k3d clusters
├── k8s-manifests/
│   ├── prod/                   Production app, secrets, RBAC, and misconfigs
│   └── shadow/                 Mirrored decoy workload and bait secrets
├── pkg/
│   └── event/event.go          Shared probe-to-detector event contract
├── probe/                      Phase 2 node monitoring component
├── detector/                   Phase 3 scoring and baseline component
├── actuator/                   Phase 4 response and conversion component
├── attack-sim/                 Phase 5 deterministic evaluation runner
├── docs/BUILD_NOTES.md         Image and initial cluster build notes
├── RunBenchmark.md             Complete deployment and benchmark procedure
└── shadowkube.pdf              Reference paper supplied with the project
```

Every Go component is its own module. The probe, detector, and actuator import the shared event module through local `replace` directives. Do not duplicate the event schema in another component.

## Paper-to-Code Mapping

| Paper section or artifact | Implementation |
|---|---|
| Fig. 6 weather application | `k8s-manifests/prod/app-src/` |
| Table 1 pod metadata | `pkg/event/event.go` |
| Table 2 insecure configurations | `k8s-manifests/prod/00-namespace-rbac.yaml`, `03-misconfig-pods.yaml` |
| Probe collection | `probe/internal/backend/`, `probe/bpftrace/` |
| Algorithm 1 LCS baseline | `detector/internal/algo1/`, `detector/internal/baseline/` |
| Algorithm 2 scoring | `detector/internal/algo2/`, `detector/internal/window/` |
| Group resolution | `detector/internal/group/` |
| Strategy selection | `actuator/internal/strategy/` |
| Three conversion phases | `actuator/internal/conversion/` |
| Traffic proxy and teardown | `actuator/internal/proxy/`, `actuator/internal/teardown/` |
| Case Studies 1 and 2 | `attack-sim/cmd/attack-sim/main.go` |
| Table 6 benchmark | `attack-sim benchmark` |

## Prerequisites

The supported environment is a GitHub Codespace based on the repository's devcontainer. Allocate at least 4 CPUs and 16 GB RAM. The environment needs:

- Docker
- k3d
- kubectl
- Go 1.22 or newer
- curl and jq

The devcontainer setup creates `prod-cluster`, `shadow-cluster`, and the shared Docker network `shadowkube-net`. It also checks whether the host kernel exposes `/sys/kernel/btf/vmlinux`, which determines whether the probe can use its preferred backend.

## Build Validation

Run the checks from the repository root. The separate module directories are intentional:

```bash
for module in pkg probe detector actuator attack-sim; do
  (cd "$module" && \
    CGO_ENABLED=0 go build ./... && \
    CGO_ENABLED=0 go vet ./... && \
    CGO_ENABLED=0 go test ./...)
done
```

Build standalone binaries when local smoke tests are needed:

```bash
(cd probe && CGO_ENABLED=0 go build -o /tmp/shadowkube-probe ./cmd/probe)
(cd detector && CGO_ENABLED=0 go build -o /tmp/shadowkube-detector ./cmd/detector)
(cd detector && CGO_ENABLED=0 go build -o /tmp/shadowkube-baselinectl ./cmd/baselinectl)
(cd actuator && CGO_ENABLED=0 go build -o /tmp/shadowkube-actuator ./cmd/actuator)
(cd attack-sim && CGO_ENABLED=0 go build -o /tmp/attack-sim ./cmd/attack-sim)
```

## Quick Start

The complete, copyable workflow is in [RunBenchmark.md](RunBenchmark.md). The high-level sequence is:

1. Open the repository in its Codespace/devcontainer and wait for cluster creation to finish.
2. Build the weather-app, probe, detector, and actuator images.
3. Import the images into the appropriate k3d clusters.
4. Apply production and shadow manifests.
5. Apply detector, actuator, and probe deployments.
6. Port-forward detector and actuator services for local verification.
7. Generate benign weather traffic and verify the production/shadow key difference.
8. Run the Phase 5 case studies and benchmark.

The initial actuator deployment should remain in dry-run mode while validating the pipeline. In that mode it records decisions and phase timings without executing live iptables or Kubernetes deletion operations.

## Phase 5 Commands

Build the simulator:

```bash
cd attack-sim
CGO_ENABLED=0 go build -o /tmp/attack-sim ./cmd/attack-sim
cd ..
```

Run the two deterministic scenarios after detector and actuator endpoints are available:

```bash
DETECTOR_URL=http://127.0.0.1:8080/events \
ACTUATOR_URL=http://127.0.0.1:8081/alarms \
/tmp/attack-sim case-study-1

DETECTOR_URL=http://127.0.0.1:8080/events \
ACTUATOR_URL=http://127.0.0.1:8081/alarms \
/tmp/attack-sim case-study-2
```

Case Study 1 models Docker API access and Kinsing-style follow-on activity. Case Study 2 models weather-service command injection followed by suspicious shell and file activity. The runner uses synthetic events and does not download or execute malware.

Run the ten-iteration Table 6 timing evaluation:

```bash
ACTUATOR_URL=http://127.0.0.1:8081/alarms \
BENCHMARK_RUNS=10 \
/tmp/attack-sim benchmark
```

The command writes `benchmark-results.json` and `benchmark-results.md`. Reference values from the paper are:

| Stage | Paper value |
|---|---:|
| Network reconfiguration | 2.168 s |
| Pods sanitation | 5.005 s |
| Sensitive information alteration | 1.409 s |
| Complete transformation | 9.612 s |

Local dry-run timings are not expected to match the paper because the lab does not perform actual iptables changes, pod deletion, or credential replacement. They are useful for checking the actuator contract and measuring the implementation path. See [RunBenchmark.md](RunBenchmark.md) for live-mode requirements and cleanup.

## HTTP Endpoints

### Detector

| Method | Endpoint | Purpose |
|---|---|---|
| POST | `/events` | Ingest NDJSON events |
| GET | `/baselines` | List persisted groups |
| POST | `/baseline/{group}/freeze` | Stop online learning for a group |
| POST | `/baseline/{group}/reset` | Clear a group after containment |
| GET | `/healthz` | Health check |

### Actuator

| Method | Endpoint | Purpose |
|---|---|---|
| POST | `/alarms` | Receive detector alarms |
| GET | `/status` | View conversions and configuration |
| POST | `/teardown/{pod}?immediate=1` | Manually finish a conversion |
| GET | `/blacklist` | View proxy blacklist entries |
| POST | `/blacklist/{ip}` | Add a source address to the blacklist |
| GET | `/decide/{src}` | Inspect passive proxy routing decision |
| GET | `/healthz` | Health check |

## Important Configuration

Configuration is environment-driven and is represented in the component ConfigMaps. The most important detector settings are `DETECTOR_TI`, `DETECTOR_L`, `DETECTOR_PENALTY_UNGROUP`, `DETECTOR_PENALTY_NETBAD`, and `ACTUATOR_URL`. The probe uses `PROBE_MODE`, `PROBE_DRY_RUN`, and `DETECTOR_URL`. The actuator uses `ACT_ON_ALARM`, `SHADOW_CLUSTER_IP`, `THRESHOLD_NODES`, `TEARDOWN_AFTER`, and `DETECTOR_URL`.

Keep `ACT_ON_ALARM=false` until the dry-run flow is understood. Enabling live action allows the actuator to modify host networking and delete pods, so it must only be done in the isolated lab.

## Design Constraints and Lab Simplifications

- Go is used for the Phase 2-5 components.
- bpftrace scripts are used instead of cilium/ebpf, libbpf, or CO-RE Go libraries.
- The shared event schema lives only in `pkg/event`.
- Detector persistence is file-based and restart-safe, not a production data store.
- The actuator deployment uses host networking for the lab. A production design would need a carefully controlled per-node implementation.
- The traffic proxy currently exposes passive decision logging rather than a full TCP ingress proxy.
- Sensitive-information alteration records a marker in the lab instead of copying real shadow credentials into a running compromised process.
- Codespaces provides a shared kernel, unlike the paper's physically separate virtual machines. This affects the fidelity of node isolation and eBPF observations.
- Phase 5 scenarios are synthetic and safe by design. They validate event, detector, and actuator integration, not the exploitability of every CVE in the paper.

## Safety

This repository intentionally includes command injection, privileged pods, hostPath access, over-permissioned RBAC, bait credentials, and other insecure settings. Use a private Codespace or isolated host. Never forward the lab ports publicly, never use real credentials, and destroy the clusters after an experiment:

```bash
k3d cluster delete prod-cluster
k3d cluster delete shadow-cluster
```

## Further Documentation

- [RunBenchmark.md](RunBenchmark.md): complete setup, deployment, case-study, benchmark, live-test, and cleanup procedure.
- [docs/BUILD_NOTES.md](docs/BUILD_NOTES.md): image loading and initial cluster build notes.
- [probe/README.md](probe/README.md): probe backends and deployment.
- [detector/README.md](detector/README.md): baseline and scoring workflow.
- [actuator/README.md](actuator/README.md): response engine and conversion details.
- [attack-sim/README.md](attack-sim/README.md): Phase 5 command reference.
