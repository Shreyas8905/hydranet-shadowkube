// Command detector is the ShadowKube behavioral detector (Phase 3).
//
// Endpoints:
//
//   POST /events                  ingest NDJSON events (one Event per line)
//   GET  /baselines               list groups with persisted baselines
//   POST /baseline/{group}/freeze switch a group to scoring-only
//   POST /baseline/{group}/reset  clear a group's in-memory state
//   GET  /healthz                 health check
//
// On alarm, the detector:
//   1. logs a structured "Detected" line
//   2. fans out a webhook POST to ACTUATOR_URL (if configured)
package main

import (
	"bufio"
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net/http"
	"os"
	"os/signal"
	"strings"
	"sync"
	"syscall"
	"time"

	"github.com/shadowkube-repro/detector/internal/algo2"
	"github.com/shadowkube-repro/detector/internal/baseline"
	"github.com/shadowkube-repro/detector/internal/config"
	"github.com/shadowkube-repro/detector/internal/group"
	"github.com/shadowkube-repro/pkg/event"
)

func main() {
	log.SetFlags(log.LstdFlags | log.Lmicroseconds)
	if err := run(); err != nil {
		log.Fatalf("detector: %v", err)
	}
}

func run() error {
	cfg, err := config.FromEnv()
	if err != nil {
		return fmt.Errorf("config: %w", err)
	}
	log.Printf("detector: addr=%s baselineDir=%s Ti=%s L=%.2f x=%.2f c=%.2f algo1Online=%t actuator=%s",
		cfg.Addr, cfg.BaselineDir, cfg.Ti, cfg.L, cfg.PenaltyUngroup, cfg.PenaltyNetBad,
		cfg.Algorithm1Online, cfg.ActuatorURL)

	store, err := baseline.NewStore(cfg.BaselineDir)
	if err != nil {
		return err
	}

	idx := group.NewIndex(nil)
	scorer := algo2.NewScorer(algo2.ScorerConfig{
		Ti:               cfg.Ti,
		L:                cfg.L,
		PenaltyUngroup:   cfg.PenaltyUngroup,
		PenaltyNetBad:    cfg.PenaltyNetBad,
		Algorithm1Online: cfg.Algorithm1Online,
	}, idx)

	// Cold-load any persisted baselines (best-effort).
	if err := loadPersisted(store, idx, scorer); err != nil {
		log.Printf("detector: baseline cold-load: %v (continuing)", err)
	}

	// Pre-create logs dir + open append file.
	if err := os.MkdirAll(parentDir(cfg.LogPath), 0o755); err != nil {
		return fmt.Errorf("create log dir: %w", err)
	}

	// Start a periodic baselines-saver.
	go periodicSave(context.Background(), store, idx, scorer, cfg)

	// HTTP handlers.
	mux := http.NewServeMux()
	mux.HandleFunc("/healthz", func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte("ok"))
	})
	mux.HandleFunc("/events", ingestHandler(scorer, cfg, idx))
	mux.HandleFunc("/baselines", baselinesHandler(store))
	mux.HandleFunc("/baseline/", baselineGroupHandler(idx, store, scorer, cfg))

	srv := &http.Server{Addr: cfg.Addr, Handler: mux}

	ctx, cancel := signal.NotifyContext(context.Background(),
		syscall.SIGINT, syscall.SIGTERM)
	defer cancel()

	go func() {
		log.Printf("detector: listening on %s", cfg.Addr)
		if err := srv.ListenAndServe(); err != nil && err != http.ErrServerClosed {
			log.Fatalf("detector: listen: %v", err)
		}
	}()
	<-ctx.Done()
	log.Printf("detector: shutting down")
	shutdown, cancelShutdown := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancelShutdown()
	return srv.Shutdown(shutdown)
}

// ingestHandler reads NDJSON from the request body and scores each event.
// Emits Detected log lines + actuator webhook on alarm.
func ingestHandler(scorer *algo2.Scorer, cfg *config.Config, idx *group.Index) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
			return
		}
		scanner := bufio.NewScanner(r.Body)
		scanner.Buffer(make([]byte, 0, 64*1024), 1024*1024)

		logFile, err := openAppend(cfg.LogPath)
		if err != nil {
			log.Printf("detector: open log: %v (continuing without on-disk log)", err)
			logFile = nil
		}
		var logMu sync.Mutex
		defer func() {
			if logFile != nil {
				_ = logFile.Close()
			}
		}()

		var count, alarms int
		for scanner.Scan() {
			line := scanner.Bytes()
			if len(line) == 0 {
				continue
			}
			var ev event.Event
			if err := json.Unmarshal(line, &ev); err != nil {
				continue
			}
			if logFile != nil {
				logMu.Lock()
				logFile.Write(append(line, '\n'))
				logMu.Unlock()
			}
			alarm, sum, gk := scorer.Observe(ev)
			count++
			if alarm {
				alarms++
				det := struct {
					Level  string  `json:"level"`
					When   time.Time `json:"ts"`
					Group  group.Key `json:"group"`
					Node   string   `json:"node"`
					Score  float64  `json:"score"`
					Event  event.Event `json:"event"`
				}{
					"alarm", ev.TS, gk, ev.Node, sum, ev,
				}
				buf, _ := json.Marshal(det)
				log.Println(string(buf))
				if cfg.ActuatorURL != "" {
					go postWebhook(cfg.ActuatorURL, buf)
				}
			}
		}
		if err := scanner.Err(); err != nil {
			http.Error(w, "read error", http.StatusBadRequest)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]any{
			"received": count, "alarms": alarms,
		})
	}
}

// baselinesHandler returns the list of groups with persisted baselines.
func baselinesHandler(store *baseline.Store) http.HandlerFunc {
	return func(w http.ResponseWriter, _ *http.Request) {
		groups, err := store.List()
		if err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
		_ = json.NewEncoder(w).Encode(map[string]any{"groups": groups})
	}
}

// baselineGroupHandler dispatches /baseline/{group}/freeze and .../reset.
func baselineGroupHandler(idx *group.Index, store *baseline.Store, scorer *algo2.Scorer, cfg *config.Config) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		parts := strings.Split(strings.TrimPrefix(r.URL.Path, "/baseline/"), "/")
		if len(parts) != 2 {
			http.Error(w, "expected /baseline/<group>/<action>", http.StatusBadRequest)
			return
		}
		groupName, action := parts[0], parts[1]
		k := group.Key(groupName)
		switch action {
		case "freeze":
			idx.Freeze(k)
			persistOne(store, scorer, cfg, k)
			w.WriteHeader(http.StatusOK)
		case "reset":
			idx.Reset(k)
			_ = os.Remove(store.PathFor(groupName))
			w.WriteHeader(http.StatusOK)
		default:
			http.Error(w, "unknown action", http.StatusBadRequest)
		}
	}
}

// postWebhook fans out the alarm to the actuator's webhook. Failures are
// logged but not retried (Phase 4 will own its own backoff).
func postWebhook(url string, body []byte) {
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, url, bytes.NewReader(body))
	if err != nil {
		log.Printf("detector: actuator req: %v", err)
		return
	}
	req.Header.Set("Content-Type", "application/json")
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		log.Printf("detector: actuator post: %v", err)
		return
	}
	defer resp.Body.Close()
	io.Copy(io.Discard, resp.Body)
}

// loadPersisted reads all baseline files from disk and feeds them into the
// scorer's per-group baselineGroup structures.
func loadPersisted(store *baseline.Store, idx *group.Index, scorer *algo2.Scorer) error {
	safes, err := store.List()
	if err != nil {
		return err
	}
	for _, safe := range safes {
		// On disk we use a safe-encoded key (no "/"). Detect the canonical
		// group key from the safe name: try unescaping "_" back to "/" and
		// also try with a "labels:group=" prefix.
		k := groupResolveFromSafeName(safe)
		if k == "" {
			continue
		}
		_ = idx.Get(k) // ensure state
		bg := scorer.BaselineGroupFor(k)
		gf, err := store.Load(safe)
		if err != nil || gf == nil {
			continue
		}
		if gf.File != nil {
			_ = bg.File.Load(gf.File)
		}
		if gf.Exec != nil {
			_ = bg.Exec.Load(gf.Exec)
		}
		if gf.Net != nil {
			_ = bg.Net.Load(gf.Net)
		}
		if gf.Frozen {
			idx.Freeze(k)
		}
		log.Printf("detector: cold-loaded baseline group=%s", k)
	}
	return nil
}

// groupResolveFromSafeName translates the disk-safe name back to a GroupKey.
// We store using "_" for "/" in the path, so any sequence of underscores
// in the safe filename came from a "/" in the original key.
func groupResolveFromSafeName(safe string) group.Key {
	if safe == "ungroupable" {
		return group.Ungroupable
	}
	if strings.HasPrefix(safe, "labels_group_") {
		rest := strings.TrimPrefix(safe, "labels_group_")
		return group.Key("labels:group=" + rest)
	}
	// default: re-inflate underscores to "/" once
	return group.Key(strings.ReplaceAll(safe, "_", "/"))
}

func periodicSave(ctx context.Context, store *baseline.Store, idx *group.Index, scorer *algo2.Scorer, cfg *config.Config) {
	t := time.NewTicker(30 * time.Second)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-t.C:
			for _, k := range idx.Snapshot() {
				persistOne(store, scorer, cfg, k)
			}
		}
	}
}

func persistOne(store *baseline.Store, scorer *algo2.Scorer, cfg *config.Config, k group.Key) {
	bg := scorer.BaselineGroupFor(k)
	if bg == nil {
		return
	}
	gf := &baseline.GroupFile{
		File: bg.File.Snapshot(),
		Exec: bg.Exec.Snapshot(),
		Net:  bg.Net.Snapshot(),
	}
	if err := store.Save(groupNameString(k), gf); err != nil {
		log.Printf("detector: save baseline %s: %v", k, err)
	}
}

// groupNameString is the user-facing form of a GroupKey.
func groupNameString(k group.Key) string { return string(k) }

func openAppend(path string) (*os.File, error) {
	if path == "" {
		return nil, fmt.Errorf("empty path")
	}
	return os.OpenFile(path, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0o644)
}

func parentDir(p string) string {
	i := strings.LastIndex(p, "/")
	if i < 0 {
		return "."
	}
	return p[:i]
}

// unescapeGroupName is kept for backwards compatibility with earlier code
// paths. The canonical reverse mapping is in groupResolveFromSafeName.
func unescapeGroupName(safe string) string {
	return strings.ReplaceAll(safe, "_", "/")
}
