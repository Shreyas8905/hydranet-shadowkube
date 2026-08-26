// Package proxy implements the Traffic Proxy component of ShadowKube §3.3.
//
// The proxy is the edge-level filter that intercepts new external connections
// from known-bad source IPs and routes them to the shadow cluster. The
// in-cluster / node-level redirection for the already-compromised pod is done
// via iptables in conversion/iptables.go (Phase 1).
//
// In the lab, standing up an actual TCP proxy in front of the Codespace
// ingress is a separate piece of infra we don't need to verify the decision
// logic. We run the proxy in "passive" mode:
//
//   - When ACT_ON_ALARM=true, real iptables REDIRECT/REJECT rules on the
//     host's INPUT chain drop new conns from blacklisted source IPs.
//   - When ACT_ON_ALARM=false (dry-run), we log the decision and skip.
//
// Either way, the proxy tracks blacklisted IPs with an expiry timestamp so
// the teardown scheduler can clear them.
package proxy

import (
	"encoding/json"
	"fmt"
	"log"
	"os"
	"path/filepath"
	"sync"
	"time"
)

// Entry is one blacklisted source IP.
type Entry struct {
	IP        string    `json:"ip"`
	AddedAt   time.Time `json:"addedAt"`
	ExpiresAt time.Time `json:"expiresAt"`
	Reason    string    `json:"reason,omitempty"`
	// FullCapture, when true, indicates the proxy should record every byte
	// of the connection and NOT forward it. Set by teardown.FullCapture.
	FullCapture bool `json:"fullCapture,omitempty"`
}

// Proxy is the in-memory + on-disk blacklist manager.
type Proxy struct {
	mu      sync.RWMutex
	dir     string
	byIP    map[string]*Entry
}

// New constructs a Proxy rooted at dir (created if missing).
func New(dir string) (*Proxy, error) {
	if err := os.MkdirAll(dir, 0o755); err != nil {
		return nil, fmt.Errorf("create proxy dir: %w", err)
	}
	p := &Proxy{dir: dir, byIP: make(map[string]*Entry)}
	if err := p.load(); err != nil {
		return nil, err
	}
	return p, nil
}

// Blacklist adds ip to the blacklist until ttl elapses, with the given
// reason. If ip is already blacklisted with a later expiry, the existing
// entry is preserved.
func (p *Proxy) Blacklist(ip, reason string, ttl time.Duration) error {
	if ip == "" {
		return nil
	}
	p.mu.Lock()
	defer p.mu.Unlock()
	now := time.Now()
	exp := now.Add(ttl)
	if cur, ok := p.byIP[ip]; ok && cur.ExpiresAt.After(exp) {
		// Already blacklisted longer; keep existing entry.
		return nil
	}
	p.byIP[ip] = &Entry{
		IP:        ip,
		AddedAt:   now,
		ExpiresAt: exp,
		Reason:    reason,
	}
	return p.save()
}

// FullCapture flips an entry (or every active entry) into full-capture
// mode. Called by teardown after the case-study window elapses.
func (p *Proxy) FullCapture(ip string) error {
	p.mu.Lock()
	defer p.mu.Unlock()
	if ip != "" {
		e, ok := p.byIP[ip]
		if !ok {
			return fmt.Errorf("ip %s not in blacklist", ip)
		}
		e.FullCapture = true
		return p.save()
	}
	for _, e := range p.byIP {
		e.FullCapture = true
	}
	return p.save()
}

// IsBlacklisted reports whether ip is currently blacklisted (and not
// expired).
func (p *Proxy) IsBlacklisted(ip string) bool {
	if ip == "" {
		return false
	}
	p.mu.RLock()
	defer p.mu.RUnlock()
	e, ok := p.byIP[ip]
	if !ok {
		return false
	}
	return time.Now().Before(e.ExpiresAt)
}

// Lookup returns the entry for ip, if any.
func (p *Proxy) Lookup(ip string) (*Entry, bool) {
	p.mu.RLock()
	defer p.mu.RUnlock()
	e, ok := p.byIP[ip]
	return e, ok
}

// Snapshot returns all currently-blacklisted IPs (including expired ones,
// since teardown may want to see what expired).
func (p *Proxy) Snapshot() []Entry {
	p.mu.RLock()
	defer p.mu.RUnlock()
	out := make([]Entry, 0, len(p.byIP))
	for _, e := range p.byIP {
		out = append(out, *e)
	}
	return out
}

// Active returns entries whose expiry has not yet passed.
func (p *Proxy) Active() []Entry {
	all := p.Snapshot()
	out := all[:0]
	now := time.Now()
	for _, e := range all {
		if now.Before(e.ExpiresAt) {
			out = append(out, e)
		}
	}
	return out
}

// Sweep removes expired entries.
func (p *Proxy) Sweep() error {
	p.mu.Lock()
	defer p.mu.Unlock()
	now := time.Now()
	changed := false
	for ip, e := range p.byIP {
		if !now.Before(e.ExpiresAt) {
			delete(p.byIP, ip)
			changed = true
		}
	}
	if changed {
		return p.save()
	}
	return nil
}

// Decide is called for every observed source IP at the edge. It returns
// the routing decision (always "prod" unless blacklisted) and the action
// ("forward", "drop", "capture"). In lab mode we log the decision.
func (p *Proxy) Decide(srcIP string) (cluster, action string) {
	e, ok := p.Lookup(srcIP)
	if !ok || !time.Now().Before(e.ExpiresAt) {
		return "prod", "forward"
	}
	if e.FullCapture {
		return "shadow", "capture"
	}
	return "shadow", "drop"
}

// LogDecide is a convenience wrapper around Decide that logs the result.
func (p *Proxy) LogDecide(srcIP string) (cluster, action string) {
	c, a := p.Decide(srcIP)
	log.Printf("proxy: src=%s -> cluster=%s action=%s", srcIP, c, a)
	return c, a
}

func (p *Proxy) save() error {
	out := make([]Entry, 0, len(p.byIP))
	for _, e := range p.byIP {
		out = append(out, *e)
	}
	data, err := json.MarshalIndent(out, "", "  ")
	if err != nil {
		return err
	}
	path := filepath.Join(p.dir, "blacklist.json")
	tmp := path + ".tmp"
	if err := os.WriteFile(tmp, data, 0o644); err != nil {
		return err
	}
	return os.Rename(tmp, path)
}

func (p *Proxy) load() error {
	path := filepath.Join(p.dir, "blacklist.json")
	data, err := os.ReadFile(path)
	if err != nil {
		if os.IsNotExist(err) {
			return nil
		}
		return err
	}
	var arr []Entry
	if err := json.Unmarshal(data, &arr); err != nil {
		return fmt.Errorf("decode %s: %w", path, err)
	}
	p.mu.Lock()
	for i := range arr {
		p.byIP[arr[i].IP] = &arr[i]
	}
	p.mu.Unlock()
	return nil
}
