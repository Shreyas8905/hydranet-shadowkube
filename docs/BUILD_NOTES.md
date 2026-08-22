# Building & loading the weather-app image (Codespaces / k3d)

Run this once the Codespace has finished `postcreate.sh` (both k3d clusters
already exist at that point).

```bash
cd k8s-manifests/prod/app-src
docker build -t weather-app:lab .

# k3d has a built-in image import (no registry needed), simpler than the
# raw `k3s ctr images import` trick from the VM-based approach:
k3d image import weather-app:lab -c prod-cluster
k3d image import weather-app:lab -c shadow-cluster
```

Verify an image landed in each cluster:
```bash
kubectl --context k3d-prod-cluster get nodes
docker exec k3d-prod-cluster-server-0 crictl images | grep weather-app
```

Then apply manifests, targeting each cluster's context explicitly (both
contexts exist simultaneously in this single Codespace, unlike the VM setup
where each cluster lived on its own machine with its own kubeconfig):

**Prod cluster:**
```bash
cd ~/shadowkube-repro/k8s-manifests/prod
kubectl --context k3d-prod-cluster apply -f 00-namespace-rbac.yaml
kubectl --context k3d-prod-cluster apply -f 01-secret.yaml
kubectl --context k3d-prod-cluster apply -f 02-weather-app.yaml
kubectl --context k3d-prod-cluster apply -f 03-misconfig-pods.yaml
kubectl --context k3d-prod-cluster -n dev-namespace get pods -w
```

**Shadow cluster:**
```bash
cd ~/shadowkube-repro/k8s-manifests/shadow
kubectl --context k3d-shadow-cluster apply -f 00-shadow-decoys.yaml
kubectl --context k3d-shadow-cluster -n dev-namespace get pods -w
```

## Smoke test

Codespaces auto-forwards ports 30080 (prod) and 30081 (shadow) — check the
**Ports** tab in VS Code/the Codespaces UI for the public/forwarded URL, or
just curl from inside the Codespace terminal:

```bash
curl "http://localhost:30080/weather?city=London"   # prod
curl "http://localhost:30081/weather?city=London"   # shadow decoy
```

Both should return JSON with `temp_c`, `condition`, and a masked `used_key`
(the prod one will show a key starting `sk-lab-`, the shadow one `sk-BAIT-`
— useful for confirming which cluster answered once redirection is involved
in later phases).

This confirms Phase 1 (topology + vulnerable app + misconfigs + shadow
decoys) is working end to end before we layer on the probe (Phase 2),
detector/actuator (Phase 3-4), and the attack simulation (Phase 5).

## eBPF/BTF note

`postcreate.sh` checks for `/sys/kernel/btf/vmlinux` and writes the result to
`/tmp/ebpf_supported.flag`. Check it before we start Phase 2:
```bash
cat /tmp/ebpf_supported.flag
```
If `false`, we'll build the probe on auditd + Docker/containerd event
polling instead of raw eBPF — still real data, just a different collection
mechanism than the paper's kernel-level hooks.
