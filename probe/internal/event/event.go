// Package event defines the wire format for probe -> detector events.
//
// This struct is intentionally minimal. Algorithm 1 (LCS baseline) and
// Algorithm 2 (online Levenshtein) consume the same shape from the detector
// in Phase 3, so any change here is a cross-component contract change.
package event

import "time"

// Type categorizes the syscall that produced the event.
type Type string

const (
	TypeExec Type = "exec" // command execution (execve/execveat)
	TypeFile Type = "file" // file access (openat/open)
	TypeNet  Type = "net"  // network connection (connect)
)

// Event is one enriched behavioral observation, ready to be scored by the
// detector. CgroupID/PID are kept as raw trace fields so the detector can
// apply additional grouping logic if needed; Pod carries the Table 1 metadata
// (Name, Namespace, Labels, Annotations, ControlledBy) the paper groups by.
type Event struct {
	TS      time.Time `json:"ts"`
	Type    Type      `json:"type"`
	Node    string    `json:"node"`  // node name (downward API)
	CgroupID uint64   `json:"cgroupId,omitempty"` // raw, kept for debugging
	PID     int       `json:"pid,omitempty"`
	Pod     PodMeta   `json:"pod"`
	Payload Payload   `json:"payload"`
}

// PodMeta mirrors Table 1 (Name, Namespace, Labels, Annotations, ControlledBy).
type PodMeta struct {
	UID          string            `json:"uid"`
	Name         string            `json:"name"`
	Namespace    string            `json:"namespace"`
	Labels       map[string]string `json:"labels,omitempty"`
	Annotations  map[string]string `json:"annotations,omitempty"`
	ControlledBy []OwnerRef        `json:"controlledBy,omitempty"`
}

// OwnerRef mirrors k8s ObjectMeta.OwnerReferences (subset).
type OwnerRef struct {
	Kind string `json:"kind"`
	Name string `json:"name"`
}

// Payload is a tagged union over Type. Only the fields relevant to the event
// type are populated; the detector dispatches on Type before reading.
type Payload struct {
	// exec
	Cmd string `json:"cmd,omitempty"`
	// file
	Path   string `json:"path,omitempty"`
	FileOp string `json:"fileOp,omitempty"` // "read" | "write" | "open"
	// net
	DstIP   string `json:"dstIp,omitempty"`
	DstPort uint16 `json:"dstPort,omitempty"`
}
