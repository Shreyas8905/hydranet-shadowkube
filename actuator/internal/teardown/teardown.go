// Package teardown schedules the per-conversion restoration of the cluster
// to its pre-alarm state.
//
// After a successful in-situ conversion, the compromised pod has been
// "captured" — its traffic is now redirected to the shadow cluster and any
// peer pods on the node have been rescheduled elsewhere. The paper's
// Case Studies give the attacker roughly 20 minutes to continue their
// reconnaissance against the now-honeypot, then:
//
//   1. Switch the proxy into full-capture mode (record every byte, drop
//      forward) for the known-bad source IPs.
//   2. Undo Phase 1 iptables rules.
//   3. Notify the detector to reset the affected group's baseline so the
//      next cycle starts fresh.
//   4. Mark the conversion record as torn down.
//
// Phase 2 (pod sanitation) and Phase 3 (SA token replacement) are
// effectively irreversible; "undo" for them is a no-op + log line. The
// pods the attacker saw are already gone.
package teardown

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"time"

	"github.com/shadowkube-repro/actuator/internal/conversion"
	"github.com/shadowkube-repro/actuator/internal/proxy"
	"github.com/shadowkube-repro/actuator/internal/state"
)

// Scheduler is the single goroutine that owns teardown scheduling.
type Scheduler struct {
	State      *state.State
	Proxy      *proxy.Proxy
	Conversion *conversion.Kube
	// HTTPClient is used to notify the detector's baseline-reset endpoint.
	HTTPClient *http.Client
	// DetectorURL is the base URL for the detector's reset endpoint
	// (e.g. http://shadowkube-detector.shadowkube-system.svc.cluster.local:8080).
	// We POST to <DetectorURL>/baseline/<group>/reset.
	DetectorURL string
	// ActOnAlarm controls whether teardown actually fires iptables undo
	// and proxy full-capture (true) or just logs (false).
	ActOnAlarm bool
}

// Schedule queues a teardown for record r to fire after d. Returns
// immediately; the goroutine is fire-and-forget. If d <= 0, the teardown
// fires on the next tick (used by manual teardown endpoint).
func (s *Scheduler) Schedule(ctx context.Context, r *state.Record, params conversion.RedirectParams, d time.Duration) {
	go s.run(ctx, r, params, d)
}

func (s *Scheduler) run(ctx context.Context, r *state.Record, params conversion.RedirectParams, d time.Duration) {
	if d > 0 {
		select {
		case <-time.After(d):
		case <-ctx.Done():
			return
		}
	}

	t0 := time.Now()

	// 1. Flip proxy into full-capture mode for the attacker IPs.
	if r.PodIP != "" {
		if err := s.Proxy.FullCapture(r.PodIP); err != nil {
			log.Printf("teardown: proxy.FullCapture(%s): %v", r.PodIP, err)
		}
	}

	// 2. Undo Phase 1 iptables.
	if err := conversion.UndoPhase1(ctx, params, s.ActOnAlarm); err != nil {
		log.Printf("teardown: UndoPhase1: %v", err)
	}

	// 3. Reset detector baseline for the group.
	if s.DetectorURL != "" && r.Group != "" {
		if err := s.resetDetectorBaseline(ctx, r.Group); err != nil {
			log.Printf("teardown: reset baseline for %s: %v", r.Group, err)
		}
	}

	if err := s.State.MarkTorndown(r.Pod, t0); err != nil {
		log.Printf("teardown: mark torn down: %v", err)
	}

	log.Printf("teardown: podUID=%s group=%s decision=%s elapsed=%s",
		r.Pod, r.Group, r.Decision, time.Since(t0))
}

func (s *Scheduler) resetDetectorBaseline(ctx context.Context, group string) error {
	url := fmt.Sprintf("%s/baseline/%s/reset", s.DetectorURL, group)
	body, _ := json.Marshal(map[string]string{"group": group})
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, url, bytes.NewReader(body))
	if err != nil {
		return err
	}
	req.Header.Set("Content-Type", "application/json")
	resp, err := s.HTTPClient.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode >= 300 {
		return fmt.Errorf("detector baseline reset returned %s", resp.Status)
	}
	return nil
}
