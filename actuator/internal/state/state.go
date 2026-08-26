// Package state tracks active and historical conversions / eliminations.
//
// Records are kept in memory and persisted to <StateDir>/conversions.json
// so the actuator can be restarted without losing visibility into the
// currently-shifted pods.
package state

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"sync"
	"time"

	"github.com/shadowkube-repro/pkg/event"
)

// Decision is what the strategy selector chose.
type Decision string

const (
	DecisionConvertInSitu   Decision = "convert_in_situ"
	DecisionDirectEliminate Decision = "direct_eliminate"
)

// PhaseTimings records per-phase duration for an in-situ conversion.
type PhaseTimings struct {
	Phase1 time.Duration `json:"phase1,omitempty"` // network reconfiguration
	Phase2 time.Duration `json:"phase2,omitempty"` // pods sanitation
	Phase3 time.Duration `json:"phase3,omitempty"` // sensitive info alteration
	Total  time.Duration `json:"total,omitempty"`
}

// Record is one alarm-driven action.
type Record struct {
	Alarm       time.Time         `json:"alarmAt"`
	StartedAt   time.Time         `json:"startedAt"`
	TeardownAt  time.Time         `json:"teardownAt,omitempty"`
	Torndown    bool              `json:"torndown"`
	Group       string            `json:"group"`
	Node        string            `json:"node"`
	Pod         string            `json:"pod"`
	PodIP       string            `json:"podIp"`
	Decision    Decision          `json:"decision"`
	Reason      string            `json:"reason,omitempty"` // why this decision
	Timings     PhaseTimings      `json:"timings,omitempty"`
	SourceEvent *event.Event      `json:"sourceEvent,omitempty"`
}

// State is the in-memory + on-disk store of records, keyed by pod UID.
type State struct {
	mu       sync.RWMutex
	dir      string
	byPod    map[string]*Record
}

// New creates a State rooted at dir (created if missing).
func New(dir string) (*State, error) {
	if err := os.MkdirAll(dir, 0o755); err != nil {
		return nil, fmt.Errorf("create state dir: %w", err)
	}
	s := &State{dir: dir, byPod: make(map[string]*Record)}
	if err := s.load(); err != nil {
		return nil, err
	}
	return s, nil
}

// Add inserts or replaces the record for the given pod.
func (s *State) Add(r *Record) error {
	if r.Pod == "" {
		return fmt.Errorf("record: empty pod UID")
	}
	s.mu.Lock()
	s.byPod[r.Pod] = r
	s.mu.Unlock()
	return s.save()
}

// Get returns the record for the pod UID, if any.
func (s *State) Get(podUID string) (*Record, bool) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	r, ok := s.byPod[podUID]
	return r, ok
}

// MarkTorndown marks the record as torn down at t.
func (s *State) MarkTorndown(podUID string, t time.Time) error {
	s.mu.Lock()
	r, ok := s.byPod[podUID]
	if !ok {
		s.mu.Unlock()
		return fmt.Errorf("no record for pod %s", podUID)
	}
	r.Torndown = true
	r.TeardownAt = t
	s.mu.Unlock()
	return s.save()
}

// Snapshot returns all records, sorted by StartedAt ascending.
func (s *State) Snapshot() []Record {
	s.mu.RLock()
	defer s.mu.RUnlock()
	out := make([]Record, 0, len(s.byPod))
	for _, r := range s.byPod {
		out = append(out, *r)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].StartedAt.Before(out[j].StartedAt) })
	return out
}

// Active returns records that have not been torn down yet.
func (s *State) Active() []Record {
	all := s.Snapshot()
	out := all[:0]
	for _, r := range all {
		if !r.Torndown {
			out = append(out, r)
		}
	}
	return out
}

func (s *State) save() error {
	s.mu.RLock()
	out := make([]Record, 0, len(s.byPod))
	for _, r := range s.byPod {
		out = append(out, *r)
	}
	s.mu.RUnlock()
	data, err := json.MarshalIndent(out, "", "  ")
	if err != nil {
		return err
	}
	path := filepath.Join(s.dir, "conversions.json")
	tmp := path + ".tmp"
	if err := os.WriteFile(tmp, data, 0o644); err != nil {
		return err
	}
	return os.Rename(tmp, path)
}

func (s *State) load() error {
	path := filepath.Join(s.dir, "conversions.json")
	data, err := os.ReadFile(path)
	if err != nil {
		if os.IsNotExist(err) {
			return nil
		}
		return err
	}
	var arr []Record
	if err := json.Unmarshal(data, &arr); err != nil {
		return fmt.Errorf("decode %s: %w", path, err)
	}
	s.mu.Lock()
	for i := range arr {
		s.byPod[arr[i].Pod] = &arr[i]
	}
	s.mu.Unlock()
	return nil
}