// Package backend: AuditdBackend is the fallback syscall-trace source for
// hosts without CO-RE BTF (the common case in GitHub Codespaces).
//
// We install audit rules (probe/auditd/rules.d/shadowkube.rules) into the
// host's auditd, then tail /var/log/audit/audit.log line by line. Each line
// is a key=value text record; we parse out the syscall type and the
// associated PID, then resolve that PID's cgroup path -> container id -> pod
// metadata in the enricher.
//
// Caveats:
//   - destination port is not in the audit SYSCALL record for connect; we
//     leave Payload.DstPort=0 and the detector treats dst IP only.
//   - argv for execve is captured by ausearch's `-i` formatter, which we
//     skip in favor of streaming the raw log (lower overhead, easier to
//     reason about).
package backend

import (
	"bufio"
	"context"
	"errors"
	"fmt"
	"io"
	"log"
	"os"
	"os/exec"
	"strings"
	"sync"
	"time"

	"github.com/shadowkube-repro/pkg/event"
)

const defaultAuditLog = "/var/log/audit/audit.log"

// AuditdBackend tails the host audit log and emits event.Event on a channel.
type AuditdBackend struct {
	logPath string
	node    string
	out     chan event.Event
}

// NewAuditdBackend constructs an AuditdBackend. logPath is the audit log
// (defaults to /var/log/audit/audit.log); node is included in events.
func NewAuditdBackend(logPath, node string) *AuditdBackend {
	if logPath == "" {
		logPath = defaultAuditLog
	}
	return &AuditdBackend{
		logPath: logPath,
		node:    node,
		out:     make(chan event.Event, 1024),
	}
}

func (b *AuditdBackend) Name() string { return "auditd" }

func (b *AuditdBackend) Events() <-chan event.Event { return b.out }

// Run installs rules if needed, then tails the audit log until ctx is done.
func (b *AuditdBackend) Run(ctx context.Context) error {
	if err := b.installRules(ctx); err != nil {
		return fmt.Errorf("install audit rules: %w", err)
	}
	return b.tail(ctx)
}

// installRules appends our rules file via `auditctl -R` if it hasn't been
// applied yet. Failures are logged but non-fatal — the rules may already be
// present in the host auditd config.
func (b *AuditdBackend) installRules(ctx context.Context) error {
	rulesPath := os.Getenv("AUDIT_RULES_PATH")
	if rulesPath == "" {
		rulesPath = "/etc/audit/rules.d/shadowkube.rules"
	}
	if _, err := os.Stat(rulesPath); err != nil {
		return fmt.Errorf("rules file missing: %w", err)
	}
	cmd := exec.CommandContext(ctx, "auditctl", "-R", rulesPath)
	out, err := cmd.CombinedOutput()
	if err != nil {
		// auditctl returns nonzero if some rules already exist; that's fine.
		log.Printf("auditctl -R: %v (output: %s)", err, string(out))
	} else {
		log.Printf("auditctl -R: applied rules from %s", rulesPath)
	}
	return nil
}

// tail opens the audit log and emits one Event per relevant syscall record.
func (b *AuditdBackend) tail(ctx context.Context) error {
	f, err := os.Open(b.logPath)
	if err != nil {
		return fmt.Errorf("open %s: %w", b.logPath, err)
	}
	defer f.Close()

	// Seek to end on first open so we don't re-emit historical events.
	if _, err := f.Seek(0, io.SeekEnd); err != nil {
		return err
	}

	r := bufio.NewReader(f)
	var line []byte
	var mu sync.Mutex // protects line (used in the read goroutine only)

	go func() {
		<-ctx.Done()
		mu.Lock()
		f.Close() // forces pending Read to return
		mu.Unlock()
	}()

	for {
		select {
		case <-ctx.Done():
			return ctx.Err()
		default:
		}

		mu.Lock()
		line, err = r.ReadBytes('\n')
		mu.Unlock()
		if err != nil {
			if errors.Is(err, io.EOF) {
				time.Sleep(200 * time.Millisecond)
				continue
			}
			return err
		}
		ev, err := parseAuditLine(line, b.node)
		if err != nil || ev == nil {
			continue
		}
		select {
		case b.out <- *ev:
		case <-ctx.Done():
			return ctx.Err()
		}
	}
}

// parseAuditLine parses one audit record. Records are space-separated
// key=value pairs (some quoted). Returns (event, nil) if the line is for a
// syscall we care about; (nil, nil) otherwise (callers should skip).
//
// Example relevant record:
//   type=SYSCALL ... syscall=59 ... pid=1234 ... exe="/usr/bin/ping" ...
//   type=SYSCALL ... syscall=257 ... pid=1234 ... key="shadowkube-file" ...
//   type=SYSCALL ... syscall=42 ... pid=1234 ... key="shadowkube-net" ...
func parseAuditLine(line []byte, node string) (*event.Event, error) {
	s := string(line)

	syscall, pid := extractKV(s, "syscall"), atoiSafe(extractKV(s, "pid"))
	if syscall == "" || pid == 0 {
		return nil, nil
	}

	ev := &event.Event{
		TS:   time.Now(),
		Node: node,
		PID:  pid,
	}

	switch syscall {
	case "59": // execve
		ev.Type = event.TypeExec
		ev.Payload.Cmd = extractKV(s, "exe")
		if ev.Payload.Cmd == "" {
			return nil, nil
		}
	case "257": // openat
		ev.Type = event.TypeFile
		// openat's filename lives in a separate PATH record type=CWD/PATH.
		// For Phase 2 we use the exe field as a stand-in path; the enricher
		// keys on PID/cgroup regardless. A more rigorous implementation would
		// correlate SYSCALL + PATH records by serial number.
		ev.Payload.Path = extractKV(s, "comm")
		ev.Payload.FileOp = "open"
		if ev.Payload.Path == "" {
			return nil, nil
		}
	case "42": // connect
		ev.Type = event.TypeNet
		// DstIP not in SYSCALL record; see package comment.
	default:
		return nil, nil
	}

	return ev, nil
}

// extractKV pulls key="value" or key=value out of an audit record. Quoted
// values are returned with the surrounding quotes stripped.
func extractKV(line, key string) string {
	needle := key + "="
	idx := strings.Index(line, needle)
	if idx < 0 {
		return ""
	}
	rest := line[idx+len(needle):]
	if rest == "" {
		return ""
	}
	if rest[0] == '"' {
		end := strings.IndexByte(rest[1:], '"')
		if end < 0 {
			return rest[1:]
		}
		return rest[1 : 1+end]
	}
	// unquoted; stop at space or comma
	end := len(rest)
	for i, ch := range rest {
		if ch == ' ' || ch == '\n' {
			end = i
			break
		}
	}
	return rest[:end]
}

func atoiSafe(s string) int {
	n := 0
	for _, ch := range s {
		if ch < '0' || ch > '9' {
			return 0
		}
		n = n*10 + int(ch-'0')
	}
	return n
}
