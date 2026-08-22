# ShadowKube Reproduction Lab

A faithful, hands-on reproduction of *ShadowKube: enhancing Kubernetes
security with behavioral monitoring and honeypot integration* (Chen et al.,
Cybersecurity 2025), built to run entirely in a **GitHub Codespace**
(4-core/16GB), using two k3d (k3s-in-Docker) clusters to simulate the
paper's production/shadow cluster split.

## Status: Phase 1 complete (topology + vulnerable app + misconfigs)

| Phase | What it covers | Status |
|---|---|---|
| 1 | Devcontainer, k3d prod/shadow clusters, vulnerable weather-app, Table 2 misconfigs, shadow decoys | ✅ this drop |
| 2 | eBPF (bpftrace) or auditd-fallback probe -> event agent shipping to detector | next |
| 3 | Detector: Algorithm 1 (LCS baseline) + Algorithm 2 (Levenshtein online detection) | next |
| 4 | Actuator: strategy selection + 3-phase honeypot conversion (redirect + sanitize + rotate secrets) | next |
| 5 | Attack simulation (Case Study 1 & 2 style) + Table 6-style timing evaluation | next |

## Directory layout

```
.devcontainer/        devcontainer.json + postcreate.sh (installs k3d, creates both clusters)
k8s-manifests/prod/    Vulnerable weather-app source + k8s manifests + Table 2 misconfigs
k8s-manifests/shadow/  Shadow-cluster decoy manifests (identical names, bait secrets)
probe/                 (Phase 2) eBPF/bpftrace or auditd-fallback behavior probe
detector/               (Phase 3) Algorithm 1 & 2 implementation
actuator/               (Phase 4) Strategy selection + honeypot transformation
attack-sim/             (Phase 5) Exploit scripts reproducing the paper's case studies
docs/                   Build notes, architecture notes
```

## Quickstart (Phase 1)

1. Push this repo to a GitHub repository (or open it in an existing one).
2. On the repo page: **Code → Codespaces → Create codespace on main**.
   Codespaces reads `.devcontainer/devcontainer.json` automatically, spins up
   a 4-core/16GB machine, installs Docker-in-Docker + kubectl + Python, and
   runs `postcreate.sh`, which:
   - installs k3d and bpftrace
   - checks eBPF/BTF support in this Codespace's kernel (writes result to
     `/tmp/ebpf_supported.flag` — check this before Phase 2)
   - creates `prod-cluster` and `shadow-cluster` (separate k3d clusters on a
     shared Docker network `shadowkube-net`, ports 30080/30081 forwarded)
   - verifies the two clusters can reach each other by container name
3. Build and load the app image into both clusters, then apply manifests —
   see `docs/BUILD_NOTES.md` for exact commands.
4. Smoke-test:
   ```bash
   curl "http://localhost:30080/weather?city=London"   # prod
   curl "http://localhost:30081/weather?city=London"   # shadow decoy
   ```

Once both return JSON and `kubectl --context k3d-prod-cluster -n dev-namespace get pods` /
the `k3d-shadow-cluster` equivalent look healthy, we're ready for Phase 2.

## Why this topology (and what changed from the VM-based design)

We originally scoped this for two Hyper-V VMs, which gives each "node" its
own kernel — the most faithful match to the paper's physically-separate
machines. Moving to Codespaces trades that for:

- **No local disk/RAM/Hyper-V juggling** — everything runs on GitHub's
  infrastructure, sized explicitly via `hostRequirements` in devcontainer.json.
- **Shared kernel** across both clusters (Codespaces doesn't support nested
  VMs), so eBPF probes and any container-escape-adjacent behavior see the
  Codespace's one kernel rather than two truly separate ones. Network
  isolation between clusters is Docker-network-level, not VM-level.
- **Identical service names/labels** on the shadow side is preserved exactly
  as before — that mechanism doesn't depend on VM vs. container isolation.

This is a reasonable trade for a "run through the actual mechanics and
validate detection logic" goal. If you later want the fuller kernel-level
isolation, the original VM-based scripts are straightforward to resurrect
from this same k8s-manifests/ content — only the topology layer changes.

## Safety note

The vulnerable app and misconfigs in this repo are intentionally exploitable
(command injection, privileged pods, exposed Docker socket, anonymous kubelet
access, cluster-admin RBAC). Keep this to a private repo/Codespace — do not
make the forwarded ports public, and don't reuse any of this code/config
outside the lab.
