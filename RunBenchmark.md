# Run the ShadowKube System and Phase 5 Benchmark

This guide runs the complete lab pipeline described in the ShadowKube paper:
production and shadow k3d clusters, weather application, probe, detector,
actuator, case studies, and the Table 6 timing benchmark.

The lab intentionally contains insecure Kubernetes resources. Run it only in
a private Codespace or isolated machine. Do not expose the forwarded ports to
the public internet.

## 1. Environment

Use a GitHub Codespace with at least 4 CPUs and 16 GB RAM. Open the repository
in its devcontainer and wait for `.devcontainer/postcreate.sh` to create:

- `prod-cluster`
- `shadow-cluster`
- the shared Docker network `shadowkube-net`

Required tools inside the environment are Docker, k3d, kubectl, Go 1.22+, curl,
and jq. Verify them with:

```bash
docker version
k3d version
kubectl version --client
go version
```

## 2. Build and load images

Build the application image and load it into both clusters:

```bash
cd k8s-manifests/prod/app-src
docker build -t weather-app:lab .
k3d image import weather-app:lab -c prod-cluster
k3d image import weather-app:lab -c shadow-cluster
cd ../../..
```

Build the probe, detector, and actuator images:

```bash
docker build -t shadowkube-probe:lab probe
docker build -t shadowkube-detector:lab detector
docker build -t shadowkube-actuator:lab actuator
k3d image import shadowkube-probe:lab -c prod-cluster
k3d image import shadowkube-detector:lab -c prod-cluster
k3d image import shadowkube-actuator:lab -c prod-cluster
```

## 3. Deploy the production and shadow clusters

Apply the production resources:

```bash
kubectl --context k3d-prod-cluster apply -f k8s-manifests/prod/
```

Apply the matching shadow decoys:

```bash
kubectl --context k3d-shadow-cluster apply -f k8s-manifests/shadow/
```

Check that workloads become ready:

```bash
kubectl --context k3d-prod-cluster -n dev-namespace get pods -o wide
kubectl --context k3d-shadow-cluster -n dev-namespace get pods -o wide
```

Verify the two application endpoints. Production should use an `sk-lab-` key;
the shadow response should use an `sk-BAIT-` key:

```bash
curl -s 'http://localhost:30080/weather?city=London' | jq
curl -s 'http://localhost:30081/weather?city=London' | jq
```

## 4. Deploy detector and actuator

Apply their RBAC, configuration, Deployments, and Services:

```bash
kubectl --context k3d-prod-cluster apply -f detector/deploy/
kubectl --context k3d-prod-cluster apply -f actuator/deploy/
```

Find the shadow cluster server IP on the shared Docker network and place it in
the actuator ConfigMap:

```bash
SHADOW_IP=$(docker inspect -f '{{range .NetworkSettings.Networks}}{{.IPAddress}}{{end}}' \
  k3d-shadow-cluster-server-0 | head -1)
kubectl --context k3d-prod-cluster -n shadowkube-system patch cm shadowkube-actuator-config \
  --type merge -p "{\"data\":{\"SHADOW_CLUSTER_IP\":\"$SHADOW_IP\"}}"
```

For the first validation, keep `ACT_ON_ALARM=false`. This exercises the full
HTTP path without changing host iptables or deleting pods. Port-forward both
services:

```bash
kubectl --context k3d-prod-cluster -n shadowkube-system \
  port-forward svc/shadowkube-detector 8080:8080 &
kubectl --context k3d-prod-cluster -n shadowkube-system \
  port-forward svc/shadowkube-actuator 8081:8081 &
```

Check health:

```bash
curl -sf http://localhost:8080/healthz
curl -sf http://localhost:8081/healthz
```

## 5. Enable the probe and seed normal behavior

The probe is deployed as a privileged DaemonSet on production nodes:

```bash
kubectl --context k3d-prod-cluster apply -f probe/deploy/
kubectl --context k3d-prod-cluster -n shadowkube-probe get pods -o wide
```

For live detector ingestion, patch the probe ConfigMap values to:

```yaml
PROBE_DRY_RUN: "false"
DETECTOR_URL: "http://shadowkube-detector.shadowkube-system.svc.cluster.local:8080/events"
```

Then restart it:

```bash
kubectl --context k3d-prod-cluster -n shadowkube-probe rollout restart ds/shadowkube-probe
```

Generate normal traffic for at least several minutes:

```bash
for i in $(seq 1 20); do curl -sf 'http://localhost:30080/weather?city=London' >/dev/null; done
```

For a controlled local run, the Phase 5 simulator creates a fresh group and
its own benign baseline events, so manual baseline seeding is optional.

## 6. Run the paper-inspired case studies

Build the simulator:

```bash
cd attack-sim
CGO_ENABLED=0 go build -o /tmp/attack-sim ./cmd/attack-sim
cd ..
```

Run Case Study 1, based on the paper's exposed Docker API and Kinsing-style
activity. The simulator sends synthetic events only:

```bash
DETECTOR_URL=http://localhost:8080/events \
ACTUATOR_URL=http://localhost:8081/alarms \
/tmp/attack-sim case-study-1
```

Run Case Study 2, based on the weather-app command injection and follow-on
reverse-shell behavior:

```bash
DETECTOR_URL=http://localhost:8080/events \
ACTUATOR_URL=http://localhost:8081/alarms \
/tmp/attack-sim case-study-2
```

Inspect detector and actuator results:

```bash
kubectl --context k3d-prod-cluster -n shadowkube-system logs deploy/shadowkube-detector --tail=30
curl -s http://localhost:8081/status | jq
curl -s http://localhost:8081/blacklist | jq
```

The simulator calls the actuator directly after the detector confirms an
alarm. This makes the local scenario deterministic. To test detector webhook
fan-out instead, set `ACTUATOR_URL` in `detector/deploy/00-config.yaml`, restart
the detector, and run a scenario without the simulator's direct actuator
endpoint pointing at the same live actuator.

## 7. Run the Table 6 benchmark

Keep the actuator in dry-run mode for a repeatable and non-destructive
benchmark. Run ten conversions, matching the paper:

```bash
BENCHMARK_RUNS=10 \
ACTUATOR_URL=http://localhost:8081/alarms \
BENCHMARK_OUTPUT=benchmark-results.json \
BENCHMARK_MARKDOWN=benchmark-results.md \
/tmp/attack-sim benchmark
```

The command records each actuator response in JSON and writes a Markdown table
comparing measured values with the paper's reference values:

| Stage | Paper reference |
|---|---:|
| Network reconfiguration | 2.168 s |
| Pods sanitation | 5.005 s |
| Sensitive information alteration | 1.409 s |
| Complete transformation | 9.612 s |

The paper's network value is the sum of its two network operations, `0.912 +
1.256` seconds. Local values are expected to differ because dry-run mode does
not execute iptables, Kubernetes pod deletion, or credential replacement.

## 8. Optional live actuator test

Only perform this in the isolated lab after reviewing the actuator settings.
Set `ACT_ON_ALARM=true` in the actuator ConfigMap and restart it:

```bash
kubectl --context k3d-prod-cluster -n shadowkube-system patch cm shadowkube-actuator-config \
  --type merge -p '{"data":{"ACT_ON_ALARM":"true"}}'
kubectl --context k3d-prod-cluster -n shadowkube-system \
  rollout restart deploy/shadowkube-actuator
```

The live path requires the actuator ServiceAccount permissions, a valid shadow
cluster IP, and a real pod UID/node in the alarm. Do not use the synthetic
Phase 5 benchmark for this mode. Confirm the response in `/status`, then use
the manual teardown endpoint when finished:

```bash
curl -X POST 'http://localhost:8081/teardown/<pod-uid>?immediate=1'
```

## 9. Cleanup

Delete the two clusters when the experiment is complete:

```bash
k3d cluster delete prod-cluster
k3d cluster delete shadow-cluster
```

The benchmark artifacts are local files and can be removed independently:

```bash
rm -f benchmark-results.json benchmark-results.md
```
