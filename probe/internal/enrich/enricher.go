// Package enrich maps raw syscall events to Table 1 pod metadata.
//
// Two flows feed the enricher:
//
//  1. bpftrace path: events carry CgroupID (from bpf_get_current_cgroup_id)
//     or, as a fallback when the helper is unsupported, a PID we resolve by
//     reading /proc/<pid>/cgroup on the host (via the container's mounted
//     /proc/<host-pid>/cgroup through /proc/<pid>/cgroup).
//
//  2. auditd path: events carry a PID that maps the same way.
//
// In both cases the cgroup path looks like:
//
//   /kubepods/burstable/pod<UID>/<container-id>
//
// We extract the pod UID, list pods in the cluster, and cache the match.
//
// Because this is a probe running on every node, the cgroup paths are
// *host* cgroups even when the probe runs inside a privileged container.
// The kernel's view of the container is what matters; reading
// /proc/<pid>/cgroup from inside the probe container (which shares the host
// PID namespace via hostPID:true) gives us the host cgroup paths directly.
package enrich

import (
	"context"
	"fmt"
	"log"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"

	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/rest"
	"k8s.io/client-go/tools/clientcmd"

	"github.com/shadowkube-repro/pkg/event"
)

// Enricher maintains a cache of pod UID -> PodMeta and looks up PodMeta for
// incoming events.
type Enricher struct {
	client    kubernetes.Interface
	refresh   time.Duration
	node      string
	procRoot  string // root for /proc reads; defaults to /proc
	mu        sync.RWMutex
	cache     map[string]event.PodMeta // key: pod UID
	cacheByNS map[string]string        // key: "<namespace>/<name>" -> pod UID
}

// New constructs an Enricher. kubeconfigPath "" -> in-cluster config.
func New(kubeconfigPath string, refresh time.Duration, node string) (*Enricher, error) {
	cfg, err := loadConfig(kubeconfigPath)
	if err != nil {
		return nil, err
	}
	cs, err := kubernetes.NewForConfig(cfg)
	if err != nil {
		return nil, fmt.Errorf("k8s client: %w", err)
	}
	return &Enricher{
		client:    cs,
		refresh:   refresh,
		node:      node,
		procRoot:  "/proc",
		cache:     make(map[string]event.PodMeta),
		cacheByNS: make(map[string]string),
	}, nil
}

func loadConfig(kubeconfigPath string) (*rest.Config, error) {
	if kubeconfigPath != "" {
		return clientcmd.BuildConfigFromFlags("", kubeconfigPath)
	}
	return rest.InClusterConfig()
}

// Run periodically refreshes the pod cache. Returns when ctx is done.
func (e *Enricher) Run(ctx context.Context) error {
	if err := e.refreshCache(ctx); err != nil {
		log.Printf("enricher: initial refresh failed: %v (continuing with empty cache)", err)
	}
	t := time.NewTicker(e.refresh)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-t.C:
			if err := e.refreshCache(ctx); err != nil {
				log.Printf("enricher: refresh failed: %v", err)
			}
		}
	}
}

func (e *Enricher) refreshCache(ctx context.Context) error {
	list, err := e.client.CoreV1().Pods("").List(ctx, metav1.ListOptions{
		FieldSelector: "spec.nodeName=" + e.node,
	})
	if err != nil {
		return err
	}
	e.mu.Lock()
	defer e.mu.Unlock()
	e.cache = make(map[string]event.PodMeta, len(list.Items))
	e.cacheByNS = make(map[string]string, len(list.Items))
	for _, p := range list.Items {
		meta := event.PodMeta{
			UID:         string(p.UID),
			Name:        p.Name,
			Namespace:   p.Namespace,
			Labels:      p.Labels,
			Annotations: p.Annotations,
		}
		for _, or := range p.OwnerReferences {
			meta.ControlledBy = append(meta.ControlledBy, event.OwnerRef{
				Kind: or.Kind, Name: or.Name,
			})
		}
		e.cache[string(p.UID)] = meta
		e.cacheByNS[p.Namespace+"/"+p.Name] = string(p.UID)
	}
	log.Printf("enricher: refreshed cache with %d pods on node %s", len(list.Items), e.node)
	return nil
}

// Enrich fills ev.Pod in place. If the event's PID cannot be mapped to a pod
// running on this node, Pod remains the zero value (the detector will treat
// such events as ungroupable and add the constant penalty x).
func (e *Enricher) Enrich(ev *event.Event) {
	if ev.PID == 0 {
		return
	}
	uid, err := e.podUIDForPID(ev.PID)
	if err != nil {
		return // PID is not a container on this node
	}
	e.mu.RLock()
	meta, ok := e.cache[uid]
	e.mu.RUnlock()
	if ok {
		ev.Pod = meta
	}
}

// podUIDForPID reads /proc/<pid>/cgroup and extracts the pod UID from the
// kubepods path component.
//
// Layout we look for:
//
//   0::/kubepods.slice/kubepods-burstable.slice/kubepods-burstable-pod<podUID>.slice/...
//
// (cgroup v2) or
//
//   12:cpuset:/kubepods/burstable/pod<podUID>/<containerID>     (cgroup v1)
//
// We look for the substring "pod<podUID>" where podUID is a 36-char UUID.
func (e *Enricher) podUIDForPID(pid int) (string, error) {
	data, err := os.ReadFile(filepath.Join(e.procRoot, fmt.Sprintf("%d", pid), "cgroup"))
	if err != nil {
		return "", err
	}
	for _, line := range strings.Split(string(data), "\n") {
		// cgroup v2: "0::/kubepods.slice/.../kubepods-burstable-pod<podUID>.slice/..."
		// cgroup v1: "N:cpuset:/kubepods/burstable/pod<podUID>/..."
		idx := strings.Index(line, "pod")
		if idx < 0 {
			continue
		}
		// The pod UID begins after "pod" and runs 36 chars (8-4-4-4-12).
		rest := line[idx+3:]
		// Skip over a trailing "-p" or similar in slice names.
		if strings.HasPrefix(rest, "-") {
			rest = rest[1:]
		}
		if len(rest) < 36 {
			continue
		}
		uid := rest[:36]
		// Validate it looks like a UUID (8-4-4-4-12 hex).
		if !looksLikeUUID(uid) {
			continue
		}
		return uid, nil
	}
	return "", fmt.Errorf("no kubepods cgroup for pid %d", pid)
}

func looksLikeUUID(s string) bool {
	if len(s) != 36 {
		return false
	}
	for i := 0; i < len(s); i++ {
		switch i {
		case 8, 13, 18, 23:
			if s[i] != '-' {
				return false
			}
		default:
			if !isHex(s[i]) {
				return false
			}
		}
	}
	return true
}

func isHex(b byte) bool {
	return (b >= '0' && b <= '9') || (b >= 'a' && b <= 'f') || (b >= 'A' && b <= 'F')
}

// PodForUID looks up a pod by UID directly (used by tests / future correlation).
func (e *Enricher) PodForUID(uid string) (event.PodMeta, bool) {
	e.mu.RLock()
	defer e.mu.RUnlock()
	m, ok := e.cache[uid]
	return m, ok
}

// Ensure corev1 is referenced (the import is currently used indirectly via the
// k8s types in refreshCache). This keeps go vet happy even before client-go
// generates the typed list.
var _ = (*corev1.PodList)(nil)
