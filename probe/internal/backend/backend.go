// Package backend contains the syscall-collection backends.
//
// Two backends are provided: EbpfBackend (bpftrace-based, requires CO-RE BTF)
// and AuditdBackend (auditd rules, broader compatibility). Both implement the
// Backend interface and emit raw events on a channel; enrichment (mapping
// cgroup_id/PID to pod metadata) happens downstream in package enrich.
package backend

import (
	"context"
	"errors"

	"github.com/shadowkube-repro/probe/internal/event"
)

// ErrUnavailable is returned by a backend that cannot run on the current host
// (e.g., EbpfBackend when /sys/kernel/btf/vmlinux is missing). Callers in
// ModeAuto should fall back to the auditd backend on this error.
var ErrUnavailable = errors.New("backend unavailable on this host")

// Backend produces a stream of raw events. Run blocks until ctx is cancelled
// or the backend errors fatally; Events is the consumer channel.
type Backend interface {
	// Name is a short identifier for logs ("ebpf" or "auditd").
	Name() string
	// Run blocks until ctx is cancelled or a fatal error occurs.
	// The caller is expected to be draining Events() concurrently.
	Run(ctx context.Context) error
	// Events returns the read-only event channel. It is valid for the entire
	// lifetime of Run; closing it signals backend shutdown.
	Events() <-chan event.Event
}
