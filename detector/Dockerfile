# # Multi-stage build for the ShadowKube detector (Phase 3).
# #
# # Stage 1: build the detector + baselinectl binaries statically.
# # Stage 2: slim runtime image with ca-certificates (for the webhook call
# #          to the actuator, if HTTPS) and the two binaries.

# FROM golang:1.22 AS build
# WORKDIR /src
# COPY detector/go.mod detector/go.sum* ./
# RUN go mod download || true
# COPY detector/ .
# RUN CGO_ENABLED=0 GOOS=linux go build -ldflags='-s -w' -o /out/detector    ./cmd/detector
# RUN CGO_ENABLED=0 GOOS=linux go build -ldflags='-s -w' -o /out/baselinectl ./cmd/baselinectl

# FROM debian:bookworm-slim
# RUN apt-get update && apt-get install -y --no-install-recommends ca-certificates \
#     && rm -rf /var/lib/apt/lists/*

# # Detectors only need network access (to receive /events and POST alarms
# # to the actuator) plus read/write access to the baseline directory.
# COPY --from=build /out/detector    /usr/local/bin/detector
# COPY --from=build /out/baselinectl /usr/local/bin/baselinectl

# # Create the directories the runtime expects; in the cluster the volumes
# # from deploy/01-deployment.yaml mount over these.
# RUN mkdir -p /var/lib/shadowkube/baselines /var/log/shadowkube

# ENV DETECTOR_ADDR=":8080" \
#     DETECTOR_BASELINE_DIR="/var/lib/shadowkube/baselines" \
#     DETECTOR_LOG_PATH="/var/log/shadowkube/events.ndjson"

# EXPOSE 8080
# ENTRYPOINT ["/usr/local/bin/detector"]

# Multi-stage build for the ShadowKube detector (Phase 3).
#
# Stage 1: build the detector + baselinectl binaries statically.
# Stage 2: slim runtime image with ca-certificates (for the webhook call
#          to the actuator, if HTTPS) and the two binaries.

FROM golang:1.22 AS build
WORKDIR /src

# Copy module files and local dependency pkg/ relative to repo root
COPY detector/go.mod detector/go.sum* ./detector/
COPY pkg/ ./pkg/

# Download dependencies inside the detector module directory
WORKDIR /src/detector
RUN go mod download || true

# Copy full repo context and build binaries from inside the module directory
WORKDIR /src
COPY . .

WORKDIR /src/detector
RUN CGO_ENABLED=0 GOOS=linux go build -ldflags='-s -w' -o /out/detector    ./cmd/detector
RUN CGO_ENABLED=0 GOOS=linux go build -ldflags='-s -w' -o /out/baselinectl ./cmd/baselinectl

FROM debian:bookworm-slim
RUN apt-get update && apt-get install -y --no-install-recommends ca-certificates \
    && rm -rf /var/lib/apt/lists/*

# Detectors only need network access (to receive /events and POST alarms
# to the actuator) plus read/write access to the baseline directory.
COPY --from=build /out/detector    /usr/local/bin/detector
COPY --from=build /out/baselinectl /usr/local/bin/baselinectl

# Create the directories the runtime expects; in the cluster the volumes
# from deploy/01-deployment.yaml mount over these.
RUN mkdir -p /var/lib/shadowkube/baselines /var/log/shadowkube

ENV DETECTOR_ADDR=":8080" \
    DETECTOR_BASELINE_DIR="/var/lib/shadowkube/baselines" \
    DETECTOR_LOG_PATH="/var/log/shadowkube/events.ndjson"

EXPOSE 8080
ENTRYPOINT ["/usr/local/bin/detector"]