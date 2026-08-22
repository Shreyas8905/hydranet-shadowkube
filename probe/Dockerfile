# Multi-stage build for the ShadowKube probe.
#
# Stage 1: build the Go binary statically (no glibc dependency).
# Stage 2: bake bpftrace + auditd into a slim runtime image alongside the
#          binary and the bpftrace scripts.

FROM golang:1.22 AS build
WORKDIR /src
COPY go.mod go.sum* ./
RUN go mod download || true
COPY . .
RUN CGO_ENABLED=0 GOOS=linux go build -ldflags='-s -w' -o /out/probe ./cmd/probe

FROM debian:bookworm-slim
RUN apt-get update && apt-get install -y --no-install-recommends \
        ca-certificates \
        bpftrace \
        auditd \
        linux-headers-amd64 \
        && rm -rf /var/lib/apt/lists/*

# bpftrace scripts baked into the image at a known path; cmd/probe uses this.
COPY --from=build /out/probe /usr/local/bin/probe
COPY bpftrace/ /opt/shadowkube/bpftrace/
COPY auditd/rules.d/ /etc/audit/rules.d/

# Default: run in auto mode, dry-run (Phase 2 verification path).
# The ConfigMap (deploy/01-config.yaml) overrides these in-cluster.
ENV PROBE_MODE=auto \
    PROBE_DRY_RUN=true \
    DETECTOR_URL=""

ENTRYPOINT ["/usr/local/bin/probe"]
