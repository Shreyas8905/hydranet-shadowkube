// Package backend: EbpfBackend drives three bpftrace scripts (execve, openat,
// connect) by spawning them as long-running subprocesses and parsing their
// JSON-per-line stdout.
//
// Each script's output is merged into a single events channel via a fan-in
// goroutine. On failure to attach any one script, Run returns the first
// non-nil error so callers (in ModeAuto) can fall back to auditd.
package backend

import (
	"bufio"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log"
	"os"
	"os/exec"
	"sync"
	"time"

	"github.com/shadowkube-repro/probe/internal/event"
)

const btfPath = "/sys/kernel/btf/vmlinux"

// HasBTF reports whether the host kernel exposes CO-RE BTF. The devcontainer's
// postcreate.sh writes the same check to /tmp/ebpf_supported.flag; we re-check
// here so the probe is self-sufficient.
func HasBTF() bool {
	_, err := os.Stat(btfPath)
	return err == nil
}

// EbpfBackend is a Backend backed by bpftrace one-liners.
type EbpfBackend struct {
	scriptsDir string
	node       string
	out        chan event.Event
}

// NewEbpfBackend constructs an EbpfBackend. scriptsDir is the directory
// containing execve.bt, openat.bt, connect.bt; node is included in emitted
// events for downstream grouping.
func NewEbpfBackend(scriptsDir, node string) *EbpfBackend {
	return &EbpfBackend{
		scriptsDir: scriptsDir,
		node:       node,
		out:        make(chan event.Event, 1024),
	}
}

func (b *EbpfBackend) Name() string { return "ebpf" }

func (b *EbpfBackend) Events() <-chan event.Event { return b.out }

// Run launches one bpftrace subprocess per script and fans their stdout lines
// into the events channel. It blocks until ctx is cancelled or any subprocess
// exits with an error.
func (b *EbpfBackend) Run(ctx context.Context) error {
	if !HasBTF() {
		return fmt.Errorf("%w: %s missing", ErrUnavailable, btfPath)
	}
	if _, err := exec.LookPath("bpftrace"); err != nil {
		return fmt.Errorf("%w: bpftrace binary not in PATH", ErrUnavailable)
	}

	scripts := []string{"execve.bt", "openat.bt", "connect.bt"}
	var wg sync.WaitGroup
	errCh := make(chan error, len(scripts))

	for _, s := range scripts {
		wg.Add(1)
		go func(script string) {
			defer wg.Done()
			path := b.scriptsDir + "/" + script
			if _, err := os.Stat(path); err != nil {
				errCh <- fmt.Errorf("missing script %s: %w", path, err)
				return
			}
			if err := b.runScript(ctx, path); err != nil && !errors.Is(err, context.Canceled) {
				errCh <- fmt.Errorf("%s: %w", script, err)
			}
		}(s)
	}

	// Wait for context cancellation or the first hard error.
	go func() {
		wg.Wait()
		close(errCh)
		close(b.out)
	}()

	select {
	case <-ctx.Done():
		return ctx.Err()
	case err, ok := <-errCh:
		if ok && err != nil {
			return err
		}
		return nil
	}
}

// runScript spawns one bpftrace instance and pumps its stdout lines into the
// shared events channel. bpftrace emits two kinds of lines on stdout: the
// script's printf output (which we want) and any error/info banner lines
// (which we log and discard).
func (b *EbpfBackend) runScript(ctx context.Context, scriptPath string) error {
	cmd := exec.CommandContext(ctx, "bpftrace", scriptPath)
	stdout, err := cmd.StdoutPipe()
	if err != nil {
		return err
	}
	stderr, err := cmd.StderrPipe()
	if err != nil {
		return err
	}

	if err := cmd.Start(); err != nil {
		return fmt.Errorf("start bpftrace: %w", err)
	}

	// Drain stderr into logs so probe failures are debuggable from `kubectl logs`.
	go func() {
		s := bufio.NewScanner(stderr)
		s.Buffer(make([]byte, 0, 64*1024), 1024*1024)
		for s.Scan() {
			log.Printf("[bpftrace %s stderr] %s", scriptPath, s.Text())
		}
	}()

	scanner := bufio.NewScanner(stdout)
	scanner.Buffer(make([]byte, 0, 64*1024), 1024*1024)
	for scanner.Scan() {
		line := scanner.Bytes()
		if len(line) == 0 || line[0] != '{' {
			// Not JSON; probably bpftrace's "Attaching..." banner. Log it.
			log.Printf("[bpftrace %s] %s", scriptPath, string(line))
			continue
		}
		ev, err := parseBpftraceLine(line, b.node)
		if err != nil {
			log.Printf("[bpftrace %s] parse error: %v (line=%q)", scriptPath, err, string(line))
			continue
		}
		select {
		case b.out <- *ev:
		case <-ctx.Done():
			return ctx.Err()
		}
	}
	if err := scanner.Err(); err != nil && !errors.Is(err, io.EOF) {
		return err
	}
	return cmd.Wait()
}

// parseBpftraceLine decodes the JSON printed by a bpftrace script into an
// event.Event with Pod intentionally empty (the enricher fills it).
func parseBpftraceLine(line []byte, node string) (*event.Event, error) {
	// bpftrace's nsecs / 1000000000 prints as a *float*, not an int, so we
	// can't strict-parse ts into time.Time directly. Decode into a generic
	// struct first, then convert.
	var raw struct {
		TS       float64 `json:"ts"`
		Type     string  `json:"type"`
		PID      int     `json:"pid"`
		CgroupID uint64  `json:"cgroupId"`
		Cmd      string  `json:"cmd"`
		Path     string  `json:"path"`
		FileOp   string  `json:"fileOp"`
		DstIP    string  `json:"dstIp"`
		DstPort  uint16  `json:"dstPort"`
	}
	if err := json.Unmarshal(line, &raw); err != nil {
		return nil, err
	}

	ev := &event.Event{
		TS:       time.Unix(int64(raw.TS), int64((raw.TS-float64(int64(raw.TS)))*1e9)),
		Type:     event.Type(raw.Type),
		Node:     node,
		CgroupID: raw.CgroupID,
		PID:      raw.PID,
		Payload: event.Payload{
			Cmd:     raw.Cmd,
			Path:    raw.Path,
			FileOp:  raw.FileOp,
			DstIP:   raw.DstIP,
			DstPort: raw.DstPort,
		},
	}
	return ev, nil
}
