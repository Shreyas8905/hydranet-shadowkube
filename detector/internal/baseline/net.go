package baseline

import (
	"sync"

	"github.com/shadowkube-repro/pkg/event"
)

// NetBaseline stores, per group, the set of allowed (dstIp, dstPort) pairs.
// Score is 0 if the new event's destination matches, else cfg.PenaltyNetBad.
//
// "Match" is exact on dstIP and dstPort. For richer rules (CIDR, IP ranges)
// Phase 5 evaluation can extend — not needed for the lab.
type NetBaseline struct {
	mu       sync.RWMutex
	peers    map[string]struct{} // "ip:port" canonical
	maxPeers int
	cfg      Config
}

// NewNetBaseline constructs a NetBaseline.
func NewNetBaseline(maxPeers int, cfg Config) *NetBaseline {
	if maxPeers <= 0 {
		maxPeers = 512
	}
	if cfg.PenaltyNetBad <= 0 {
		cfg.PenaltyNetBad = 1.0
	}
	return &NetBaseline{
		peers:    make(map[string]struct{}),
		maxPeers: maxPeers,
		cfg:      cfg,
	}
}

// Observe records the destination of a net event as allowed.
func (b *NetBaseline) Observe(ev event.Event) {
	if ev.Type != event.TypeNet {
		return
	}
	if ev.Payload.DstIP == "" {
		return
	}
	key := b.canonical(ev)
	b.mu.Lock()
	defer b.mu.Unlock()
	if _, ok := b.peers[key]; ok {
		return
	}
	if len(b.peers) >= b.maxPeers {
		// Evict an arbitrary entry (small enough that ordering doesn't matter
		// for the lab; for production use an LRU).
		for k := range b.peers {
			delete(b.peers, k)
			break
		}
	}
	b.peers[key] = struct{}{}
}

// Score returns 0 if dest is allowed, else cfg.PenaltyNetBad.
func (b *NetBaseline) Score(ev event.Event) float64 {
	if ev.Type != event.TypeNet {
		return 0
	}
	if ev.Payload.DstIP == "" {
		return 0
	}
	key := b.canonical(ev)
	b.mu.RLock()
	defer b.mu.RUnlock()
	if _, ok := b.peers[key]; ok {
		return 0
	}
	return b.cfg.PenaltyNetBad
}

func (b *NetBaseline) canonical(ev event.Event) string {
	return ev.Payload.DstIP + ":" + uitoa(uint(ev.Payload.DstPort))
}

// Snapshot returns the peer set as a sorted slice for stable JSON.
func (b *NetBaseline) Snapshot() any {
	b.mu.RLock()
	defer b.mu.RUnlock()
	out := make([]string, 0, len(b.peers))
	for k := range b.peers {
		out = append(out, k)
	}
	return out
}

// Load replaces the peer set.
func (b *NetBaseline) Load(v any) error {
	arr, ok := v.([]any)
	if !ok {
		return nil
	}
	out := make(map[string]struct{}, len(arr))
	for _, x := range arr {
		if s, ok := x.(string); ok {
			out[s] = struct{}{}
		}
	}
	b.mu.Lock()
	defer b.mu.Unlock()
	b.peers = out
	return nil
}

func uitoa(u uint) string {
	if u == 0 {
		return "0"
	}
	var buf [5]byte
	i := len(buf)
	for u > 0 {
		i--
		buf[i] = byte('0' + u%10)
		u /= 10
	}
	return string(buf[i:])
}
