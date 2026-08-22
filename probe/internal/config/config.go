// Package config loads runtime configuration from environment variables.
//
// The probe runs as a DaemonSet; configuration is injected via a ConfigMap
// mounted as env vars (see probe/deploy/01-config.yaml).
package config

import (
	"fmt"
	"os"
	"strings"
	"time"
)

// Mode selects which event-collection backend to use.
type Mode string

const (
	ModeAuto   Mode = "auto"   // try ebpf, fall back to auditd
	ModeEbpf   Mode = "ebpf"   // force bpftrace, fail if unavailable
	ModeAuditd Mode = "auditd" // force auditd
)

// Config is the resolved runtime configuration for the probe binary.
type Config struct {
	// Mode is the backend selection.
	Mode Mode
	// DryRun prints enriched events to stdout instead of POSTing to the detector.
	// Used during Phase 2 verification before the detector exists.
	DryRun bool
	// DetectorURL is the NDJSON ingest endpoint, e.g. http://host:8080/events.
	DetectorURL string
	// NodeName is the node the probe is running on (downward API).
	NodeName string
	// PodName is the probe's own pod name (used in logs only).
	PodName string
	// KubeconfigPath is optional; if empty, in-cluster config is used.
	KubeconfigPath string
	// BatchSize is the maximum number of events per HTTP POST.
	BatchSize int
	// FlushInterval is the maximum time to wait before flushing a partial batch.
	FlushInterval time.Duration
	// EnrichRefreshInterval is how often the pod-metadata cache is rebuilt.
	EnrichRefreshInterval time.Duration
}

// FromEnv builds a Config from environment variables. Returns an error if a
// required value is missing or malformed.
func FromEnv() (*Config, error) {
	mode := Mode(strings.ToLower(strings.TrimSpace(envOr("PROBE_MODE", "auto"))))
	switch mode {
	case ModeAuto, ModeEbpf, ModeAuditd:
		// ok
	default:
		return nil, fmt.Errorf("invalid PROBE_MODE %q (auto|ebpf|auditd)", mode)
	}

	dryRun := strings.EqualFold(envOr("PROBE_DRY_RUN", "false"), "true")

	detectorURL := os.Getenv("DETECTOR_URL")
	if !dryRun && detectorURL == "" {
		return nil, fmt.Errorf("DETECTOR_URL is required unless PROBE_DRY_RUN=true")
	}

	node := os.Getenv("NODE_NAME")
	if node == "" {
		// Fall back to hostname; useful for local docker runs.
		if h, err := os.Hostname(); err == nil {
			node = h
		}
	}

	return &Config{
		Mode:                  mode,
		DryRun:                dryRun,
		DetectorURL:           detectorURL,
		NodeName:              node,
		PodName:               os.Getenv("POD_NAME"),
		KubeconfigPath:        os.Getenv("KUBECONFIG"),
		BatchSize:             50,
		FlushInterval:         time.Second,
		EnrichRefreshInterval: 30 * time.Second,
	}, nil
}

func envOr(key, def string) string {
	if v := os.Getenv(key); v != "" {
		return v
	}
	return def
}
