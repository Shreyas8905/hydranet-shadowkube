#!/usr/bin/env bash
set -euo pipefail

# --- Colorized Logger Helpers ---
log_info()  { echo -e "\033[1;34m[INFO]\033[0m $*"; }
log_succ()  { echo -e "\033[1;32m[SUCCESS]\033[0m $*"; }
log_warn()  { echo -e "\033[1;33m[WARN]\033[0m $*"; }
log_error() { echo -e "\033[1;31m[ERROR]\033[0m $*" >&2; }

# Track port-forward PIDs for cleanup on script exit
PF_PIDS=()
cleanup() {
    log_info "Cleaning up background processes..."
    for pid in "${PF_PIDS[@]}"; do
        if kill -0 "$pid" 2>/dev/null; then
            kill "$pid" 2>/dev/null || true
        fi
    done
}
trap cleanup EXIT

# ------------------------------------------------------------------------------
# 1. Environment Verification
# ------------------------------------------------------------------------------
log_info "1. Verifying environment and tool prerequisites..."
docker version >/dev/null || { log_error "Docker is not running"; exit 1; }
k3d version >/dev/null
kubectl version --client >/dev/null
go version >/dev/null
log_succ "Environment check passed."

# ------------------------------------------------------------------------------
# 2. Build and Load Docker Images
# ------------------------------------------------------------------------------
log_info "2. Building and importing Docker images..."

log_info "Building weather-app image..."
(
    cd k8s-manifests/prod/app-src
    docker build -t weather-app:lab .
)
k3d image import weather-app:lab -c prod-cluster
k3d image import weather-app:lab -c shadow-cluster

log_info "Building probe, detector, and actuator images..."
docker build -t shadowkube-probe:lab -f probe/Dockerfile .
docker build -t shadowkube-detector:lab -f detector/Dockerfile .
docker build -t shadowkube-actuator:lab -f actuator/Dockerfile .

k3d image import shadowkube-probe:lab -c prod-cluster 
k3d image import shadowkube-detector:lab -c prod-cluster 
k3d image import shadowkube-actuator:lab -c prod-cluster 
log_succ "Images built and loaded successfully."

# ------------------------------------------------------------------------------
# 3. Deploy Production and Shadow Decoys
# ------------------------------------------------------------------------------
log_info "3. Deploying Production and Shadow cluster manifests..."
kubectl --context k3d-prod-cluster apply -f k8s-manifests/prod/
kubectl --context k3d-shadow-cluster apply -f k8s-manifests/shadow/

log_info "Waiting for workloads to become ready..."

# Production Cluster Deployments
kubectl rollout status deployment/keystore -n dev-namespace --context k3d-prod-cluster --timeout=90s
kubectl rollout status deployment/backend -n dev-namespace --context k3d-prod-cluster --timeout=90s
kubectl rollout status deployment/frontend -n dev-namespace --context k3d-prod-cluster --timeout=90s

# Shadow Cluster Deployments
kubectl rollout status deployment/keystore -n dev-namespace --context k3d-shadow-cluster --timeout=90s
kubectl rollout status deployment/backend -n dev-namespace --context k3d-shadow-cluster --timeout=90s
kubectl rollout status deployment/frontend -n dev-namespace --context k3d-shadow-cluster --timeout=90s

log_info "Verifying application endpoints..."
curl -s 'http://localhost:30080/weather?city=London' | jq .
curl -s 'http://localhost:30081/weather?city=London' | jq .
log_succ "Base application workloads are healthy."


# # ------------------------------------------------------------------------------
# # 4. Deploy Detector and Actuator services
# # ------------------------------------------------------------------------------
# log_info "4. Deploying Detector and Actuator services..."

# # Ensure shadowkube-system namespace exists on target cluster
# kubectl create namespace shadowkube-system --context k3d-prod-cluster --dry-run=client -o yaml | kubectl apply --context k3d-prod-cluster -f -

# # Wait for namespace creation to complete in API server
# kubectl get ns shadowkube-system --context k3d-prod-cluster

# # Apply ConfigMaps and Deployments
# kubectl apply --context k3d-prod-cluster -f detector/deploy/00-config.yaml
# kubectl apply --context k3d-prod-cluster -f detector/deploy/
# kubectl apply --context k3d-prod-cluster -f actuator/deploy/

# # --- FIX 1: Wait for detector and actuator workloads to be ready ---
# log_info "Waiting for ShadowKube workloads to become ready..."
# kubectl rollout status deployment/shadowkube-detector -n shadowkube-system --context k3d-prod-cluster --timeout=90s
# kubectl rollout status deployment/shadowkube-actuator -n shadowkube-system --context k3d-prod-cluster --timeout=90s

# # --- FIX 2: Start background port-forwards and track their PIDs ---
# log_info "Starting port-forward tunnels for Detector (8080) and Actuator (8081)..."
# # Forward local 8080 -> detector 8080
# kubectl --context k3d-prod-cluster -n shadowkube-system port-forward --address 127.0.0.1 svc/shadowkube-detector 8080:8080 >/dev/null 2>&1 &
# PF_PIDS+=($!)

# # Forward local 8081 -> actuator 8081
# kubectl --context k3d-prod-cluster -n shadowkube-system port-forward --address 127.0.0.1 svc/shadowkube-actuator 8081:8081 >/dev/null 2>&1 &
# PF_PIDS+=($!)

# # Wait for local ports to accept traffic
# log_info "Waiting for port-forward tunnels to accept connections..."
# for i in {1..15}; do
#     if curl -sf http://localhost:8080/healthz >/dev/null && curl -sf http://localhost:8081/healthz >/dev/null; then
#         break
#     fi
#     sleep 1
# done

# curl -sf http://localhost:8080/healthz
# curl -sf http://localhost:8081/healthz
# log_succ "Detector and Actuator endpoints are live and healthy."

# ------------------------------------------------------------------------------
# 4. Deploy Detector and Actuator services
# ------------------------------------------------------------------------------
log_info "4. Deploying Detector and Actuator services..."

# Ensure shadowkube-system namespace exists on target cluster
kubectl create namespace shadowkube-system --context k3d-prod-cluster --dry-run=client -o yaml | kubectl apply --context k3d-prod-cluster -f -

# Apply ConfigMaps, RBAC, and Deployments
kubectl apply --context k3d-prod-cluster -f detector/deploy/00-config.yaml
kubectl apply --context k3d-prod-cluster -f detector/deploy/
kubectl apply --context k3d-prod-cluster -f actuator/deploy/

# Dynamically patch the real node IP (without duplicating :30081)
RAW_IP=$(docker inspect -f '{{range .NetworkSettings.Networks}}{{.IPAddress}}{{end}}' k3d-shadow-cluster-server-0 2>/dev/null || echo "127.0.0.1")
# Strip any existing port if present, then append :30081 cleanly
SHADOW_HOST=$(echo "$RAW_IP" | cut -d':' -f1)
kubectl --context k3d-prod-cluster -n shadowkube-system patch cm shadowkube-actuator-config \
  --type merge -p "{\"data\":{\"SHADOW_CLUSTER\":\"${SHADOW_HOST}:30081\"}}" || true

# Force restart to load updated ConfigMap & fresh pod instance
kubectl --context k3d-prod-cluster -n shadowkube-system rollout restart deploy/shadowkube-actuator

log_info "Waiting for ShadowKube workloads to become ready..."
kubectl rollout status deployment/shadowkube-detector -n shadowkube-system --context k3d-prod-cluster --timeout=90s
kubectl rollout status deployment/shadowkube-actuator -n shadowkube-system --context k3d-prod-cluster --timeout=90s

# Kill stale background port-forwards
fuser -k 8080/tcp 2>/dev/null || true
fuser -k 8081/tcp 2>/dev/null || true

log_info "Starting port-forward tunnels for Detector (8080) and Actuator (8081)..."
kubectl --context k3d-prod-cluster -n shadowkube-system port-forward --address 127.0.0.1 svc/shadowkube-detector 8080:8080 >/dev/null 2>&1 &
PF_PIDS+=($!)

kubectl --context k3d-prod-cluster -n shadowkube-system port-forward --address 127.0.0.1 svc/shadowkube-actuator 8081:8081 >/dev/null 2>&1 &
PF_PIDS+=($!)

# Wait for local ports to accept traffic
log_info "Waiting for port-forward tunnels to accept connections..."
for i in {1..15}; do
    if curl -sf http://localhost:8080/healthz >/dev/null && curl -sf http://localhost:8081/healthz >/dev/null; then
        break
    fi
    sleep 1
done

curl -sf http://localhost:8080/healthz
curl -sf http://localhost:8081/healthz
log_succ "Detector and Actuator endpoints are live and healthy."

# ------------------------------------------------------------------------------
# 5. Deploy and Patch Probe, Generate Baseline Traffic
# ------------------------------------------------------------------------------
log_info "5. Deploying probe and configuring ingestion pipeline..."
kubectl --context k3d-prod-cluster apply -f probe/deploy/

log_info "Patching probe ConfigMap for live detector ingestion..."
kubectl --context k3d-prod-cluster -n shadowkube-probe patch cm shadowkube-probe-config \
  --type merge -p '{"data":{"PROBE_DRY_RUN":"false","DETECTOR_URL":"http://shadowkube-detector.shadowkube-system.svc.cluster.local:8080/events"}}'

kubectl --context k3d-prod-cluster -n shadowkube-probe rollout restart ds/shadowkube-probe
kubectl --context k3d-prod-cluster -n shadowkube-probe rollout status ds/shadowkube-probe --timeout=90s
kubectl --context k3d-prod-cluster -n shadowkube-probe get pods -o wide

log_info "Generating initial baseline traffic..."
for i in $(seq 1 20); do
    curl -sf 'http://localhost:30080/weather?city=London' >/dev/null
done
log_succ "Probe online and baseline traffic generated."

# ------------------------------------------------------------------------------
# 6. Build Simulator and Run Case Studies
# ------------------------------------------------------------------------------
log_info "6. Building attack simulator..."
(
    cd attack-sim
    CGO_ENABLED=0 go build -o /tmp/attack-sim ./cmd/attack-sim
)

log_info "Executing Case Study 1 (Exposed Docker API / Kinsing profile)..."
DETECTOR_URL=http://localhost:8080/events \
ACTUATOR_URL=http://localhost:8081/alarms \
/tmp/attack-sim case-study-1

log_info "Executing Case Study 2 (Command Injection / Reverse Shell profile)..."
DETECTOR_URL=http://localhost:8080/events \
ACTUATOR_URL=http://localhost:8081/alarms \
/tmp/attack-sim case-study-2

log_info "Inspecting results..."
kubectl --context k3d-prod-cluster -n shadowkube-system logs deploy/shadowkube-detector --tail=30
curl -s http://localhost:8081/status | jq .
curl -s http://localhost:8081/blacklist | jq .
log_succ "Case studies complete."

# ------------------------------------------------------------------------------
# 7. Run Phase 5 / Table 6 Benchmark
# ------------------------------------------------------------------------------
log_info "7. Executing Phase 5 / Table 6 timing benchmark (10 iterations)..."
BENCHMARK_RUNS=10 \
ACTUATOR_URL=http://localhost:8081/alarms \
BENCHMARK_OUTPUT=benchmark-results.json \
BENCHMARK_MARKDOWN=benchmark-results.md \
/tmp/attack-sim benchmark

log_succ "Benchmark generated: benchmark-results.json and benchmark-results.md"
if [ -f benchmark-results.md ]; then
    cat benchmark-results.md
fi

# ------------------------------------------------------------------------------
# 8. Teardown and Cleanup
# ------------------------------------------------------------------------------
log_warn "8. Tearing down k3d clusters and cleaning temporary files..."
k3d cluster delete prod-cluster
k3d cluster delete shadow-cluster
rm -f benchmark-results.json benchmark-results.md

log_succ "ShadowKube lab execution and benchmark run finished successfully."