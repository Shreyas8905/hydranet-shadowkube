// Package config loads runtime configuration for the actuator.
//
// All knobs are env-driven so the ConfigMap in deploy/01-config.yaml maps
// straight to env vars (see actuator/deploy/02-deployment.yaml).
package config

import (
	"errors"
	"fmt"
	"os"
	"strconv"
	"time"
)

// Config is the resolved runtime configuration for the actuator binary.
type Config struct {
	// Addr is the HTTP listen address, e.g. ":8081".
	Addr string
	// NodeName is the actuator's own node (downward API; informational).
	NodeName string
	// ShadowClusterIP is the IP of the shadow-cluster server on the shared
	// shadowkube-net Docker network. iptables DNAT targets this for the
	// compromised pod's redirected cluster calls.
	ShadowClusterIP string
	// ShadowServicePort is the port the shadow cluster's frontend NodePort
	// listens on (30081 vs prod's 30080 because k3d shares localhost).
	ShadowServicePort uint16
	// ThresholdNodes is the minimum cluster node count for in-situ
	// conversion. Below this, DirectEliminate is chosen.
	ThresholdNodes int
	// TeardownAfter is the duration to wait before tearing down a
	// conversion (paper's Case Studies used ~20 min).
	TeardownAfter time.Duration
	// ActOnAlarm, when false, logs decisions and skips real iptables /
	// kubectl calls. Useful for verification before the live pipeline.
	ActOnAlarm bool
	// StateDir is where persistent conversion records are written.
	StateDir string
	// DetectorURL is the detector's /baseline/{group}/reset endpoint base
	// (without the trailing group/action). Used by teardown to clear
	// the affected group.
	DetectorURL string
}

// FromEnv builds a Config from environment variables.
func FromEnv() (*Config, error) {
	c := &Config{
		Addr:              envOr("ACTUATOR_ADDR", ":8081"),
		NodeName:          os.Getenv("NODE_NAME"),
		ShadowClusterIP:   os.Getenv("SHADOW_CLUSTER_IP"),
		ThresholdNodes:    2,
		TeardownAfter:     20 * time.Minute,
		ActOnAlarm:        true,
		ShadowServicePort: 30081,
		StateDir:          envOr("ACTUATOR_STATE_DIR", "/var/lib/shadowkube/actuator"),
		DetectorURL:       os.Getenv("DETECTOR_URL"),
	}

	if v := os.Getenv("SHADOW_SERVICE_PORT"); v != "" {
		p, err := strconv.ParseUint(v, 10, 16)
		if err != nil {
			return nil, fmt.Errorf("SHADOW_SERVICE_PORT: %w", err)
		}
		c.ShadowServicePort = uint16(p)
	}
	if v := os.Getenv("THRESHOLD_NODES"); v != "" {
		n, err := strconv.Atoi(v)
		if err != nil {
			return nil, fmt.Errorf("THRESHOLD_NODES: %w", err)
		}
		c.ThresholdNodes = n
	}
	if v := os.Getenv("TEARDOWN_AFTER"); v != "" {
		d, err := time.ParseDuration(v)
		if err != nil {
			return nil, fmt.Errorf("TEARDOWN_AFTER: %w", err)
		}
		c.TeardownAfter = d
	}
	if v := os.Getenv("ACT_ON_ALARM"); v != "" {
		b, err := strconv.ParseBool(v)
		if err != nil {
			return nil, fmt.Errorf("ACT_ON_ALARM: %w", err)
		}
		c.ActOnAlarm = b
	}

	if c.ShadowClusterIP == "" && c.ActOnAlarm {
		return nil, errors.New("SHADOW_CLUSTER_IP must be set when ACT_ON_ALARM=true")
	}
	return c, nil
}

func envOr(key, def string) string {
	if v := os.Getenv(key); v != "" {
		return v
	}
	return def
}