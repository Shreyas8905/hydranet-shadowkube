#!/usr/bin/env bash
# .devcontainer/postcreate.sh
# Runs automatically once when the Codespace is created.
set -euo pipefail

echo "== Waiting for Docker daemon (docker-in-docker) =="
until docker info >/dev/null 2>&1; do sleep 1; done

echo "== Installing k3d =="
curl -s https://raw.githubusercontent.com/k3d-io/k3d/main/install.sh | bash

echo "== Installing bpftrace + BCC tools (for Phase 2 probe) =="
sudo apt-get update -y
sudo apt-get install -y bpftrace linux-tools-common jq

echo "== Checking eBPF/BTF availability in this Codespace =="
if [ -f /sys/kernel/btf/vmlinux ]; then
  echo "  ✅ /sys/kernel/btf/vmlinux present -- CO-RE eBPF (bpftrace) should work."
  EBPF_OK=true
else
  echo "  ⚠️  /sys/kernel/btf/vmlinux NOT found -- this Codespace's host kernel"
  echo "     doesn't expose BTF to the container. bpftrace probes in Phase 2"
  echo "     will likely fail to attach. Fallback plan: use auditd + Docker"
  echo "     events polling for file/exec/network visibility instead of raw"
  echo "     eBPF. This will be finalized when we build Phase 2."
  EBPF_OK=false
fi
echo "$EBPF_OK" > /tmp/ebpf_supported.flag

echo "== Creating shared Docker network for both clusters =="
docker network create shadowkube-net 2>/dev/null || echo "  (network already exists)"

echo "== Creating prod-cluster (k3d) =="
k3d cluster create prod-cluster \
  --network shadowkube-net \
  --servers 1 --agents 1 \
  -p "30080:30080@server:0" \
  --k3s-arg "--kube-apiserver-arg=anonymous-auth=true@server:0" \
  --k3s-arg "--kubelet-arg=anonymous-auth=true@server:0" \
  --k3s-arg "--kubelet-arg=authorization-mode=AlwaysAllow@server:0" \
  --wait

echo "== Creating shadow-cluster (k3d) =="
k3d cluster create shadow-cluster \
  --network shadowkube-net \
  --servers 1 --agents 1 \
  -p "30081:30081@server:0" \
  --wait

echo "== Clusters ready. Contexts: =="
kubectl config get-contexts | grep k3d

echo ""
echo "== Verifying inter-cluster reachability over shadowkube-net =="
PROD_SERVER=$(docker ps --filter "label=k3d.cluster=prod-cluster" --filter "label=k3d.role=server" --format '{{.Names}}' | head -1)
SHADOW_SERVER=$(docker ps --filter "label=k3d.cluster=shadow-cluster" --filter "label=k3d.role=server" --format '{{.Names}}' | head -1)
echo "  prod server container:   $PROD_SERVER"
echo "  shadow server container: $SHADOW_SERVER"
docker exec "$SHADOW_SERVER" ping -c1 -W2 "$PROD_SERVER" >/dev/null 2>&1 \
  && echo "  ✅ shadow-cluster can reach prod-cluster by container name" \
  || echo "  ⚠️  ping failed -- will use docker network inspect to resolve IPs instead in Phase 4"

echo ""
echo "== Done. Next: build & load the weather-app image (see docs/BUILD_NOTES.md) =="
