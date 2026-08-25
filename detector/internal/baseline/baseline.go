// Package baseline defines the per-group, per-event-type baselines used by
// Algorithm 2 to compute per-event suspicion d.
//
// Three implementations are provided:
//
//   FileBaseline  — stores a learned set of normal file paths (sequences) and
//                   scores a new path as min-Levenshtein over its prefix
//                   token set against learned paths.
//   ExecBaseline  — keyed by binary name; each binary has its own set of
//                   observed argv strings (the binary's "behavioral array").
//                   Scoring: min Levenshtein(cmd, learned_argv_i).
//   NetBaseline   — per-group set of allowed (dstIP, port) pairs. Score is 0
//                   if the new event's dest matches; otherwise cfg.PenaltyNetBad.
//
// All three implement the Baseline interface and round-trip through the
// Store (JSON on disk) for restart durability.
package baseline

import "github.com/shadowkube-repro/pkg/event"

// Baseline is one group's per-event-type behavioral baseline.
type Baseline interface {
	// Observe learns from an event. Called on every event for the group
	// when online learning is enabled (Algorithm 1 online mode).
	Observe(ev event.Event)

	// Score returns the per-event suspicion d for an incoming event. The
	// caller (scorer) accumulates d into the group's windowed D.
	Score(ev event.Event) float64

	// Snapshot returns a JSON-serializable state.
	Snapshot() any

	// Load restores state from a previously-saved Snapshot.
	Load(any) error
}

// Config holds the penalty constants used by baselines when computing d.
type Config struct {
	// PenaltyNetBad is the constant c added when a net event's dest is
	// outside the group's allowed set.
	PenaltyNetBad float64
}
