# # syntax=docker/dockerfile:1.6

# # Build stage: static Go binary.
# FROM golang:1.22-bookworm AS build
# WORKDIR /src

# # Cache the module graph first.
# COPY go.mod go.sum* ./
# COPY ../pkg /pkg
# RUN go mod download

# COPY . .
# ARG VERSION=lab
# RUN CGO_ENABLED=0 GOOS=linux GOARCH=amd64 \
#     go build -trimpath -ldflags="-s -w -X main.version=${VERSION}" \
#     -o /out/actuator ./cmd/actuator

# # Runtime stage: iptables for Phase 1 / teardown.
# FROM debian:bookworm-slim
# RUN apt-get update && apt-get install -y --no-install-recommends \
#         iptables \
#         ca-certificates \
#         curl \
#     && rm -rf /var/lib/apt/lists/*

# RUN useradd -r -u 10001 -g root actuator
# RUN mkdir -p /var/lib/shadowkube/actuator /var/log/shadowkube \
#     && chown -R actuator:root /var/lib/shadowkube /var/log/shadowkube

# COPY --from=build /out/actuator /usr/local/bin/actuator

# USER actuator
# EXPOSE 8081
# ENTRYPOINT ["/usr/local/bin/actuator"]

# syntax=docker/dockerfile:1.6

# Build stage: static Go binary.
FROM golang:1.22-bookworm AS build
WORKDIR /src

# Copy module files and local dependency pkg/ relative to repo root
COPY actuator/go.mod actuator/go.sum* ./actuator/
COPY pkg/ ./pkg/

# Cache the module graph first
WORKDIR /src/actuator
RUN go mod download

# Copy full repo context and build binary from inside the module directory
WORKDIR /src
COPY . .

WORKDIR /src/actuator
ARG VERSION=lab
RUN CGO_ENABLED=0 GOOS=linux GOARCH=amd64 \
    go build -trimpath -ldflags="-s -w -X main.version=${VERSION}" \
    -o /out/actuator ./cmd/actuator

# Runtime stage: iptables for Phase 1 / teardown.
FROM debian:bookworm-slim
RUN apt-get update && apt-get install -y --no-install-recommends \
        iptables \
        ca-certificates \
        curl \
    && rm -rf /var/lib/apt/lists/*

RUN useradd -r -u 10001 -g root actuator
RUN mkdir -p /var/lib/shadowkube/actuator /var/log/shadowkube \
    && chown -R actuator:root /var/lib/shadowkube /var/log/shadowkube

COPY --from=build /out/actuator /usr/local/bin/actuator

USER actuator
EXPOSE 8081
ENTRYPOINT ["/usr/local/bin/actuator"]
