// Package window is a time-windowed ring buffer of (timestamp, score) pairs.
//
// Each pod group owns one Window. Window.Sum() returns the total score
// accumulated over events whose TS is within [now-Ti, now]; older entries
// are evicted lazily on Add.
package window

import (
	"sync"
	"time"
)

// Window is a thread-safe, time-bounded sum.
type Window struct {
	mu   sync.Mutex
	ti   time.Duration
	ring []entry
}

// entry is one scored observation.
type entry struct {
	ts    time.Time
	score float64
}

// New constructs a Window with the given window length.
func New(ti time.Duration) *Window {
	return &Window{ti: ti}
}

// Add inserts (ts, score) and evicts anything older than ts - Ti.
func (w *Window) Add(ts time.Time, score float64) {
	w.mu.Lock()
	defer w.mu.Unlock()
	cutoff := ts.Add(-w.ti)
	kept := w.ring[:0]
	for _, e := range w.ring {
		if e.ts.After(cutoff) {
			kept = append(kept, e)
		}
	}
	w.ring = append(kept, entry{ts: ts, score: score})
}

// Sum returns the cumulative score over the trailing Ti window ending at
// `now`. If now is zero, time.Now() is used.
func (w *Window) Sum(now time.Time) float64 {
	if now.IsZero() {
		now = time.Now()
	}
	w.mu.Lock()
	defer w.mu.Unlock()
	cutoff := now.Add(-w.ti)
	var sum float64
	for _, e := range w.ring {
		if !e.ts.Before(cutoff) {
			sum += e.score
		}
	}
	return sum
}

// Reset clears the window.
func (w *Window) Reset() {
	w.mu.Lock()
	w.ring = w.ring[:0]
	w.mu.Unlock()
}

// Len returns the count of entries currently retained (useful for tests).
func (w *Window) Len() int {
	w.mu.Lock()
	defer w.mu.Unlock()
	return len(w.ring)
}
