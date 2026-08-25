package baseline

import (
	"strings"
	"sync"

	"github.com/shadowkube-repro/pkg/event"
)

// ExecBaseline stores, per binary, the argv strings observed during normal
// operation.
//
// Mirrors paper §3.2: "command execution -> min Levenshtein dev. vs. binary's
// seq array". Each binary is identified by the first whitespace-delimited
// token of the command (e.g., "/usr/bin/ping", "python3").
type ExecBaseline struct {
	mu      sync.RWMutex
	maxCmds int // total cap across all binaries
	cmds    map[string][]string // binary -> []argv (each argv is the full cmd tail)
	count   int                  // total commands stored (across all binaries)
}

// NewExecBaseline constructs an ExecBaseline with the given total cap.
func NewExecBaseline(maxCmds int) *ExecBaseline {
	if maxCmds <= 0 {
		maxCmds = 1024
	}
	return &ExecBaseline{
		maxCmds: maxCmds,
		cmds:    make(map[string][]string),
	}
}

// Observe splits the cmd into (binary, argv). Binary is the first whitespace-
// separated token; argv is the remainder joined back to a string.
func (b *ExecBaseline) Observe(ev event.Event) {
	if ev.Type != event.TypeExec {
		return
	}
	cmd := strings.TrimSpace(ev.Payload.Cmd)
	if cmd == "" {
		return
	}
	bin, argv := splitCmd(cmd)
	if bin == "" {
		return
	}
	b.mu.Lock()
	defer b.mu.Unlock()
	existing, ok := b.cmds[bin]
	if ok && containsString(existing, argv) {
		return
	}
	if b.count >= b.maxCmds {
		// Drop a single entry from any bin to keep things bounded.
		for k, v := range b.cmds {
			if len(v) > 0 {
				b.cmds[k] = v[:len(v)-1]
				b.count--
				break
			}
		}
	}
	b.cmds[bin] = append(b.cmds[bin], argv)
	b.count++
}

// Score returns min Levenshtein vs. the binary's observed argv array.
// Returns 0 if the binary is not in the baseline (we have no signal either
// way), matching the paper's "min Levenshtein over an array" rule — an empty
// array yields min of nothing, treated as 0.
//
// To distinguish "saw this exact argv" from "saw this binary", exact match
// returns 0; near-match returns the Levenshtein distance.
func (b *ExecBaseline) Score(ev event.Event) float64 {
	if ev.Type != event.TypeExec {
		return 0
	}
	cmd := strings.TrimSpace(ev.Payload.Cmd)
	if cmd == "" {
		return 0
	}
	bin, argv := splitCmd(cmd)
	if bin == "" {
		return 0
	}
	b.mu.RLock()
	existing, ok := b.cmds[bin]
	b.mu.RUnlock()
	if !ok || len(existing) == 0 {
		return 0
	}
	return minLevenshtein(argv, existing)
}

// levenshteinNorm is package-local so package baseline doesn't import
// package algo2 (which would create an import cycle when baselinectl imports
// both). Mirrors algo2.Levenshtein.
func levenshteinNorm(a, b string) float64 {
	if a == b {
		return 0
	}
	ar := []byte(a)
	br := []byte(b)
	if len(ar) == 0 && len(br) == 0 {
		return 0
	}
	if len(ar) == 0 || len(br) == 0 {
		return 1
	}
	if len(ar) < len(br) {
		ar, br = br, ar
	}
	n, m := len(ar), len(br)
	prev := make([]int, m+1)
	cur := make([]int, m+1)
	for j := 0; j <= m; j++ {
		prev[j] = j
	}
	for i := 1; i <= n; i++ {
		cur[0] = i
		for j := 1; j <= m; j++ {
			cost := 1
			if ar[i-1] == br[j-1] {
				cost = 0
			}
			del := prev[j] + 1
			ins := cur[j-1] + 1
			sub := prev[j-1] + cost
			m := del
			if ins < m {
				m = ins
			}
			if sub < m {
				m = sub
			}
			cur[j] = m
		}
		prev, cur = cur, prev
	}
	d := prev[m]
	maxLen := len(ar)
	if len(br) > maxLen {
		maxLen = len(br)
	}
	return float64(d) / float64(maxLen)
}

func minLevenshtein(s string, baselines []string) float64 {
	if len(baselines) == 0 {
		return 0
	}
	best := 1.0
	for _, b := range baselines {
		if d := levenshteinNorm(s, b); d < best {
			best = d
		}
	}
	return best
}

// Snapshot returns the per-binary map.
func (b *ExecBaseline) Snapshot() any {
	b.mu.RLock()
	defer b.mu.RUnlock()
	out := make(map[string][]string, len(b.cmds))
	for k, v := range b.cmds {
		cp := make([]string, len(v))
		copy(cp, v)
		out[k] = cp
	}
	return out
}

// Load restores the per-binary map.
func (b *ExecBaseline) Load(v any) error {
	m, ok := v.(map[string]any)
	if !ok {
		return nil
	}
	out := make(map[string][]string, len(m))
	for k, raw := range m {
		arr, ok := raw.([]any)
		if !ok {
			continue
		}
		vals := make([]string, 0, len(arr))
		for _, x := range arr {
			if s, ok := x.(string); ok {
				vals = append(vals, s)
			}
		}
		out[k] = vals
	}
	b.mu.Lock()
	defer b.mu.Unlock()
	b.cmds = out
	b.count = 0
	for _, v := range out {
		b.count += len(v)
	}
	return nil
}

func splitCmd(cmd string) (binary, argv string) {
	idx := strings.IndexAny(cmd, " \t")
	if idx < 0 {
		return cmd, ""
	}
	return cmd[:idx], strings.TrimSpace(cmd[idx+1:])
}

func containsString(slice []string, s string) bool {
	for _, x := range slice {
		if x == s {
			return true
		}
	}
	return false
}
