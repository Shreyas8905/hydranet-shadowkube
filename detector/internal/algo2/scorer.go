// Package algo2: Scorer implements Algorithm 2 — per-event suspicion d and
// windowed cumulative D, with the alarm boundary D > L.
//
// The scorer coordinates three sub-baselines (file/exec/net) per group and
// observes events into both the baseline (online learning) and the group's
// ring-buffered window.
package algo2

import (
	"sync"
	"time"

	"github.com/shadowkube-repro/detector/internal/baseline"
	"github.com/shadowkube-repro/detector/internal/group"
	"github.com/shadowkube-repro/detector/internal/window"
	"github.com/shadowkube-repro/pkg/event"
)

// Scorer is the Algorithm 2 implementation.
type Scorer struct {
	Cfg     ScorerConfig
	idx     *group.Index
	windows map[group.Key]*window.Window
	bs      map[group.Key]*BaselineGroup

	mu sync.Mutex
}

// ScorerConfig is the scorer-specific subset of detector config.
type ScorerConfig struct {
	Ti                time.Duration
	L                 float64
	PenaltyUngroup    float64
	PenaltyNetBad     float64
	Algorithm1Online  bool
}

// BaselineGroup bundles the three per-group Baseline impls.
type BaselineGroup struct {
	File *baseline.FileBaseline
	Exec *baseline.ExecBaseline
	Net  *baseline.NetBaseline
}

// NewScorer constructs a Scorer with the given configuration.
func NewScorer(cfg ScorerConfig, idx *group.Index) *Scorer {
	return &Scorer{
		Cfg:     cfg,
		idx:     idx,
		windows: make(map[group.Key]*window.Window),
		bs:      make(map[group.Key]*BaselineGroup),
	}
}

// BaselineGroupFor returns (creating if needed) the three baselines for a
// group. Used by the server (in cmd/detector) when loading a persisted
// baseline.
func (s *Scorer) BaselineGroupFor(k group.Key) *BaselineGroup {
	s.mu.Lock()
	defer s.mu.Unlock()
	bg, ok := s.bs[k]
	if ok {
		return bg
	}
	netCfg := baseline.Config{PenaltyNetBad: s.Cfg.PenaltyNetBad}
	bg = &BaselineGroup{
		File: baseline.NewFileBaseline(1024),
		Exec: baseline.NewExecBaseline(1024),
		Net:  baseline.NewNetBaseline(512, netCfg),
	}
	s.bs[k] = bg
	return bg
}

// WindowFor returns (creating if needed) the per-group ring buffer.
func (s *Scorer) WindowFor(k group.Key) *window.Window {
	s.mu.Lock()
	defer s.mu.Unlock()
	w, ok := s.windows[k]
	if ok {
		return w
	}
	w = window.New(s.Cfg.Ti)
	s.windows[k] = w
	return w
}

// Observe applies Algorithm 2 to one event. Returns (alarm, D, groupKey).
func (s *Scorer) Observe(ev event.Event) (bool, float64, group.Key) {
	k := group.Resolve(ev)
	w := s.WindowFor(k)
	state := s.idx.Get(k)

	if k == group.Ungroupable {
		w.Add(ev.TS, s.Cfg.PenaltyUngroup)
	} else {
		bg := s.BaselineGroupFor(k)
		var d float64
		switch ev.Type {
		case event.TypeExec:
			d = bg.Exec.Score(ev)
		case event.TypeFile:
			d = bg.File.Score(ev)
		case event.TypeNet:
			d = bg.Net.Score(ev)
		}
		if d < 0 {
			d = 0
		}
		w.Add(ev.TS, d)
		if s.Cfg.Algorithm1Online && !state.Frozen {
			bg.File.Observe(ev)
			bg.Exec.Observe(ev)
			bg.Net.Observe(ev)
		}
	}

	sum := w.Sum(ev.TS)
	if sum > s.Cfg.L {
		w.Reset()
		return true, sum, k
	}
	return false, sum, k
}
