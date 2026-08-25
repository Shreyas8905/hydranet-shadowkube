// Package group resolves a probe event to a GroupKey and owns per-group state.
//
// Resolution priority (paper §3.2):
//   1. labels["group"] — primary key, e.g. "labels:group=weather-app"
//   2. "<namespace>/<name>" — fallback when no group label
//   3. "ungroupable" — Pod is empty (cgroup didn't resolve to a known pod)
//
// Each group has its own groupState holding the Baseline + Window.
// GroupState is created lazily on first event for that key.
package group

import (
	"sync"

	"github.com/shadowkube-repro/pkg/event"
)

// Key is the identifier used for grouping. Format depends on Resolution:
//   "labels:group=<value>"
//   "ns/<namespace>/<name>"
//   "ungroupable"
type Key string

const Ungroupable Key = "ungroupable"

// Index maps GroupKey -> *State. Safe for concurrent use.
type Index struct {
	mu     sync.RWMutex
	states map[Key]*State
	// NewState is called when a previously-unseen key is requested. It is
	// injected so tests/CLI can use a constructor without an import cycle.
	NewState func(Key) *State
}

// State holds one group's runtime state. The fields here are filled in by
// the scorer; we leave them public so the scorer (in package algo2) can set
// them without a setter boilerplate, accessed only under the Index lock.
type State struct {
	Key     Key
	Frozen  bool // true -> stop online learning; only score
	// baseline window counters (debug only; full Baseline lives in scorer)
	fileSeq int
	execSeq int
	netSeq  int
}

// NewIndex constructs an Index with the given state constructor.
func NewIndex(newState func(Key) *State) *Index {
	if newState == nil {
		newState = func(k Key) *State { return &State{Key: k} }
	}
	return &Index{states: make(map[Key]*State), NewState: newState}
}

// Resolve maps an event to a GroupKey.
func Resolve(ev event.Event) Key {
	if ev.Pod.Name == "" && ev.Pod.UID == "" {
		return Ungroupable
	}
	if g, ok := ev.Pod.Labels["group"]; ok && g != "" {
		return Key("labels:group=" + g)
	}
	return Key(ev.Pod.Namespace + "/" + ev.Pod.Name)
}

// Get returns the State for a key, creating it on first use.
func (i *Index) Get(k Key) *State {
	i.mu.RLock()
	s, ok := i.states[k]
	i.mu.RUnlock()
	if ok {
		return s
	}
	i.mu.Lock()
	defer i.mu.Unlock()
	if s, ok = i.states[k]; ok {
		return s
	}
	s = i.NewState(k)
	i.states[k] = s
	return s
}

// Freeze marks a group as scoring-only (no online learning).
func (i *Index) Freeze(k Key) {
	i.mu.Lock()
	defer i.mu.Unlock()
	if s, ok := i.states[k]; ok {
		s.Frozen = true
	}
}

// Reset removes a group (used by the actuator's teardown in Phase 4).
func (i *Index) Reset(k Key) {
	i.mu.Lock()
	defer i.mu.Unlock()
	delete(i.states, k)
}

// Snapshot returns a list of all known keys (for /baselines debug endpoint).
func (i *Index) Snapshot() []Key {
	i.mu.RLock()
	defer i.mu.RUnlock()
	out := make([]Key, 0, len(i.states))
	for k := range i.states {
		out = append(out, k)
	}
	return out
}
