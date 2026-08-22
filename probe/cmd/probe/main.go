// Command probe is the ShadowKube behavioral probe (Phase 2).
//
// Pipeline:
//
//   Backend (eBPF/auditd) -- raw events -->
//     Enricher -- PodMeta attached -->
//       Transport (HTTP NDJSON / dry-run) --> Detector
//
// Mode selection:
//   PROBE_MODE=auto   (default) try ebpf, fall back to auditd
//   PROBE_MODE=ebpf   force bpftrace, fail if unavailable
//   PROBE_MODE=auditd force auditd tail
//
// In --dry-run (PROBE_DRY_RUN=true) the transport is replaced by a stdout
// printer so the probe can be verified before the detector exists.
package main

import (
	"context"
	"encoding/json"
	"flag"
	"fmt"
	"log"
	"os"
	"os/signal"
	"sync"
	"syscall"
	"time"

	"github.com/shadowkube-repro/probe/internal/backend"
	"github.com/shadowkube-repro/probe/internal/config"
	"github.com/shadowkube-repro/probe/internal/enrich"
	"github.com/shadowkube-repro/probe/internal/event"
	"github.com/shadowkube-repro/probe/internal/transport"
)

// scriptsDir is the path inside the probe container where bpftrace scripts
// are baked in (see probe/Dockerfile).
const scriptsDir = "/opt/shadowkube/bpftrace"

func main() {
	log.SetFlags(log.LstdFlags | log.Lmicroseconds)
	if err := run(); err != nil {
		log.Fatalf("probe: %v", err)
	}
}

func run() error {
	cfg, err := config.FromEnv()
	if err != nil {
		return fmt.Errorf("config: %w", err)
	}

	// Banner so users can confirm what mode actually started from logs.
	log.Printf("probe: starting node=%s mode=%s dryRun=%t detector=%s",
		cfg.NodeName, cfg.Mode, cfg.DryRun, cfg.DetectorURL)

	ctx, cancel := signal.NotifyContext(context.Background(),
		syscall.SIGINT, syscall.SIGTERM)
	defer cancel()

	// Backend.
	be, err := selectBackend(ctx, cfg)
	if err != nil {
		return fmt.Errorf("backend: %w", err)
	}
	log.Printf("probe: backend=%s", be.Name())

	// Enricher.
	en, err := enrich.New(cfg.KubeconfigPath, cfg.EnrichRefreshInterval, cfg.NodeName)
	if err != nil {
		return fmt.Errorf("enricher: %w", err)
	}

	// Transport (HTTP or dry-run).
	var tp transport.Transport
	if cfg.DryRun {
		tp = newDryRunTransport()
	} else {
		tp = transport.New(cfg.DetectorURL, cfg.BatchSize, cfg.FlushInterval)
	}

	// Goroutines: backend, enricher refresh, transport flush, drain.
	var wg sync.WaitGroup
	errCh := make(chan error, 4)

	wg.Add(1)
	go func() {
		defer wg.Done()
		if err := be.Run(ctx); err != nil && ctx.Err() == nil {
			errCh <- fmt.Errorf("backend %s: %w", be.Name(), err)
		}
	}()

	wg.Add(1)
	go func() {
		defer wg.Done()
		if err := en.Run(ctx); err != nil && ctx.Err() == nil {
			errCh <- fmt.Errorf("enricher: %w", err)
		}
	}()

	if httpTp, ok := tp.(*transport.HttpTransport); ok {
		wg.Add(1)
		go func() {
			defer wg.Done()
			if err := httpTp.Run(ctx); err != nil && ctx.Err() == nil {
				errCh <- fmt.Errorf("transport: %w", err)
			}
		}()
	}

	// Drain loop: backend events -> enrich -> transport.
	wg.Add(1)
	go func() {
		defer wg.Done()
		drain(ctx, be.Events(), en, tp)
	}()

	// Wait for signal.
	<-ctx.Done()
	log.Printf("probe: shutdown signal received")
	_ = tp.Close()

	// Give goroutines a moment to drain, then return.
	done := make(chan struct{})
	go func() { wg.Wait(); close(done) }()
	select {
	case <-done:
	case <-time.After(5 * time.Second):
		log.Printf("probe: goroutines did not exit in time; forcing shutdown")
	}

	// Surface any non-context errors.
	close(errCh)
	for err := range errCh {
		if err != nil {
			log.Printf("probe: component error: %v", err)
		}
	}
	return nil
}

// selectBackend picks a backend based on Mode. In ModeAuto we try ebpf first
// and fall back to auditd on ErrUnavailable; any other error is fatal.
func selectBackend(ctx context.Context, cfg *config.Config) (backend.Backend, error) {
	tryEbpf := func() (backend.Backend, error) {
		be := backend.NewEbpfBackend(scriptsDir, cfg.NodeName)
		// We don't *run* the backend here, just probe availability — bpftrace
		// attach can fail at Run() time if BTF appeared OK on stat but the
		// probe can't load for some reason. The first event will surface it.
		if !backend.HasBTF() {
			return nil, backend.ErrUnavailable
		}
		return be, nil
	}

	switch cfg.Mode {
	case config.ModeEbpf:
		return tryEbpf()
	case config.ModeAuditd:
		return backend.NewAuditdBackend("", cfg.NodeName), nil
	case config.ModeAuto:
		if be, err := tryEbpf(); err == nil {
			return be, nil
		} else {
			log.Printf("probe: ebpf unavailable (%v); falling back to auditd", err)
		}
		return backend.NewAuditdBackend("", cfg.NodeName), nil
	default:
		return nil, fmt.Errorf("unknown mode %q", cfg.Mode)
	}
}

// drain reads events from the backend, enriches, and forwards.
func drain(ctx context.Context, src <-chan event.Event, en *enrich.Enricher, tp transport.Transport) {
	for {
		select {
		case <-ctx.Done():
			return
		case ev, ok := <-src:
			if !ok {
				return
			}
			en.Enrich(&ev)
			if err := tp.Send(ctx, ev); err != nil && ctx.Err() == nil {
				log.Printf("probe: transport send: %v", err)
			}
		}
	}
}

// dryRunTransport prints each event as JSON to stdout.
type dryRunTransport struct{}

func newDryRunTransport() transport.Transport { return &dryRunTransport{} }

func (d *dryRunTransport) Send(ctx context.Context, ev event.Event) error {
	b, err := json.Marshal(ev)
	if err != nil {
		return err
	}
	_, err = os.Stdout.Write(append(b, '\n'))
	return err
}

func (d *dryRunTransport) Close() error { return nil }

// We pull flag into scope so future flags can be wired in via the same
// mechanism; currently configuration is env-driven per the ConfigMap.
var _ = flag.String
