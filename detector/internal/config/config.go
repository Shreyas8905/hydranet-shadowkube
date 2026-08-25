// Package config loads runtime configuration for the detector.
//
// All knobs are env-driven so the deploy/00-config.yaml ConfigMap can map
// them straight to env vars (see detector/deploy/01-deployment.yaml).
package config

import (
	"errors"
	"fmt"
	"os"
	"strconv"
	"time"
)

// Config is the resolved runtime configuration for the detector binary.
type Config struct {
	// Addr is the HTTP listen address, e.g. ":8080".
	Addr string
	// BaselineDir is where per-group baselines are persisted as JSON.
	BaselineDir string
	// LogPath is the NDJSON file that the detector appends every received
	// event to; baselinectl extract reads from this same file.
	LogPath string
	// Ti is the window length over which cumulative suspicion D is computed.
	Ti time.Duration
	// L is the alarm threshold: when D > L the detector fires.
	L float64
	// PenaltyUngroup is the constant x added when the event is ungroupable.
	PenaltyUngroup float64
	// PenaltyNetBad is the constant c added when a net event's destination
	// is outside the group's expected peer set.
	PenaltyNetBad float64
	// ActuatorURL is the webhook the detector POSTs to on alarm
	// (e.g. http://actuator:8081/alarm). Empty disables.
	ActuatorURL string
	// Algorithm1Online, if true, the scorer continues to learn baselines
	// during detection. If false, only the explicitly-loaded baselines
	// (built via baselinectl extract) are used for scoring.
	Algorithm1Online bool
}

// FromEnv builds a Config from environment variables. Returns an error if a
// required value is missing or malformed.
func FromEnv() (*Config, error) {
	c := &Config{
		Addr:             envOr("DETECTOR_ADDR", ":8080"),
		BaselineDir:      envOr("DETECTOR_BASELINE_DIR", "/var/lib/shadowkube/baselines"),
		LogPath:          envOr("DETECTOR_LOG_PATH", "/var/log/shadowkube/events.ndjson"),
		Ti:               60 * time.Second,
		L:                3.0,
		PenaltyUngroup:   0.5,
		PenaltyNetBad:    1.0,
		ActuatorURL:      os.Getenv("ACTUATOR_URL"),
		Algorithm1Online: true,
	}

	if v := os.Getenv("DETECTOR_TI"); v != "" {
		d, err := time.ParseDuration(v)
		if err != nil {
			return nil, fmt.Errorf("DETECTOR_TI: %w", err)
		}
		c.Ti = d
	}
	if v := os.Getenv("DETECTOR_L"); v != "" {
		f, err := strconv.ParseFloat(v, 64)
		if err != nil {
			return nil, fmt.Errorf("DETECTOR_L: %w", err)
		}
		c.L = f
	}
	if v := os.Getenv("DETECTOR_PENALTY_UNGROUP"); v != "" {
		f, err := strconv.ParseFloat(v, 64)
		if err != nil {
			return nil, fmt.Errorf("DETECTOR_PENALTY_UNGROUP: %w", err)
		}
		c.PenaltyUngroup = f
	}
	if v := os.Getenv("DETECTOR_PENALTY_NETBAD"); v != "" {
		f, err := strconv.ParseFloat(v, 64)
		if err != nil {
			return nil, fmt.Errorf("DETECTOR_PENALTY_NETBAD: %w", err)
		}
		c.PenaltyNetBad = f
	}
	if v := os.Getenv("DETECTOR_ALGO1_ONLINE"); v != "" {
		b, err := strconv.ParseBool(v)
		if err != nil {
			return nil, fmt.Errorf("DETECTOR_ALGO1_ONLINE: %w", err)
		}
		c.Algorithm1Online = b
	}
	if c.L <= 0 {
		return nil, errors.New("DETECTOR_L must be > 0")
	}
	if c.Ti <= 0 {
		return nil, errors.New("DETECTOR_TI must be > 0")
	}
	return c, nil
}

func envOr(key, def string) string {
	if v := os.Getenv(key); v != "" {
		return v
	}
	return def
}
