// Command actuator is the ShadowKube response engine.
//
// It receives alarm webhooks from the detector, runs the strategy selector,
// and either runs the 3-phase honeypot conversion (preferred) or directly
// eliminates the malicious pod (fallback). It also owns the Traffic Proxy
// blacklist and schedules teardown after the case-study window.
package main

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log"
	"net/http"
	"os/signal"
	"sync"
	"syscall"
	"time"

	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/types"
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/rest"

	"github.com/shadowkube-repro/pkg/event"

	"github.com/shadowkube-repro/actuator/internal/config"
	"github.com/shadowkube-repro/actuator/internal/conversion"
	"github.com/shadowkube-repro/actuator/internal/proxy"
	"github.com/shadowkube-repro/actuator/internal/state"
	"github.com/shadowkube-repro/actuator/internal/strategy"
	"github.com/shadowkube-repro/actuator/internal/teardown"
)

// alarmBody is the webhook payload from the detector.
type alarmBody struct {
	Group     string      `json:"group"`
	Node      string      `json:"node"`
	Pod       string      `json:"pod"`
	PodIP     string      `json:"podIp"`
	SourceIP  string      `json:"sourceIp,omitempty"`
	SourceEvt *event.Event `json:"sourceEvent,omitempty"`
}

// Server holds the actuator's runtime state.
type Server struct {
	Cfg        *config.Config
	State      *state.State
	Proxy      *proxy.Proxy
	Kube       *conversion.Kube
	Teardown   *teardown.Scheduler
	HTTPClient *http.Client

	mu sync.Mutex
	// cancelTeardown, if set, cancels the scheduled teardown for a pod.
	// Currently a no-op (we let teardowns run to completion) but reserved
	// for future "abort" endpoint.
	cancelTeardown map[string]context.CancelFunc
}

func main() {
	cfg, err := config.FromEnv()
	if err != nil {
		log.Fatalf("actuator: config: %v", err)
	}

	stateStore, err := state.New(cfg.StateDir)
	if err != nil {
		log.Fatalf("actuator: state: %v", err)
	}
	proxyStore, err := proxy.New(cfg.StateDir)
	if err != nil {
		log.Fatalf("actuator: proxy: %v", err)
	}

	var kubeClient kubernetes.Interface
	if cfg.ActOnAlarm {
		rc, err := rest.InClusterConfig()
		if err != nil {
			log.Fatalf("actuator: in-cluster config: %v", err)
		}
		cs, err := kubernetes.NewForConfig(rc)
		if err != nil {
			log.Fatalf("actuator: client-go: %v", err)
		}
		kubeClient = cs
	}
	k := conversion.NewKube(kubeClient)

	sched := &teardown.Scheduler{
		State:       stateStore,
		Proxy:       proxyStore,
		Conversion:  k,
		HTTPClient:  &http.Client{Timeout: 10 * time.Second},
		DetectorURL: cfg.DetectorURL,
		ActOnAlarm:  cfg.ActOnAlarm,
	}

	srv := &Server{
		Cfg:            cfg,
		State:          stateStore,
		Proxy:          proxyStore,
		Kube:           k,
		Teardown:       sched,
		HTTPClient:     &http.Client{Timeout: 10 * time.Second},
		cancelTeardown: make(map[string]context.CancelFunc),
	}

	mux := http.NewServeMux()
	mux.HandleFunc("POST /alarms", srv.handleAlarm)
	mux.HandleFunc("GET /status", srv.handleStatus)
	mux.HandleFunc("POST /teardown/{pod}", srv.handleTeardown)
	mux.HandleFunc("GET /blacklist", srv.handleBlacklist)
	mux.HandleFunc("POST /blacklist/{ip}", srv.handleBlacklistAdd)
	mux.HandleFunc("GET /decide/{src}", srv.handleDecide)
	mux.HandleFunc("GET /healthz", srv.handleHealth)

	httpSrv := &http.Server{
		Addr:              cfg.Addr,
		Handler:           mux,
		ReadHeaderTimeout: 5 * time.Second,
	}

	// Background sweeper — removes expired proxy entries every minute.
	rootCtx, cancel := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer cancel()
	go runSweeper(rootCtx, proxyStore)

	log.Printf("actuator: addr=%s threshold=%d teardown=%s shadowCluster=%s:%d actOnAlarm=%t node=%s",
		cfg.Addr, cfg.ThresholdNodes, cfg.TeardownAfter,
		cfg.ShadowClusterIP, cfg.ShadowServicePort,
		cfg.ActOnAlarm, cfg.NodeName)

	go func() {
		if err := httpSrv.ListenAndServe(); err != nil && !errors.Is(err, http.ErrServerClosed) {
			log.Fatalf("actuator: serve: %v", err)
		}
	}()

	<-rootCtx.Done()
	log.Printf("actuator: shutdown signal received")
	shutCtx, shutCancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer shutCancel()
	if err := httpSrv.Shutdown(shutCtx); err != nil {
		log.Printf("actuator: shutdown: %v", err)
	}
}

func runSweeper(ctx context.Context, p *proxy.Proxy) {
	t := time.NewTicker(60 * time.Second)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-t.C:
			if err := p.Sweep(); err != nil {
				log.Printf("actuator: proxy sweep: %v", err)
			}
		}
	}
}

func (s *Server) handleHealth(w http.ResponseWriter, _ *http.Request) {
	writeJSON(w, http.StatusOK, map[string]string{"status": "ok"})
}

// handleAlarm receives the detector's webhook and dispatches the response.
func (s *Server) handleAlarm(w http.ResponseWriter, r *http.Request) {
	var body alarmBody
	if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
		writeError(w, http.StatusBadRequest, fmt.Sprintf("decode body: %v", err))
		return
	}
	if body.Pod == "" || body.Node == "" {
		writeError(w, http.StatusBadRequest, "pod and node required")
		return
	}

	// Use background context; the HTTP handler lifetime is short but the
	// conversion (3 phases + teardown) outlives it.
	ctx := context.Background()

	pod, err := s.Kube.PodByUID(ctx, body.Pod)
	if err != nil {
		if !s.Cfg.ActOnAlarm {
			// In dry-run we may not have cluster access; build a stub pod.
			pod = &corev1.Pod{
				ObjectMeta: metav1.ObjectMeta{
					Name:      body.Pod,
					Namespace: "weather-app",
					UID:       k8sUID(body.Pod),
				},
				Status: corev1.PodStatus{PodIP: body.PodIP},
			}
		} else {
			writeError(w, http.StatusNotFound, fmt.Sprintf("lookup pod: %v", err))
			return
		}
	}

	// Node count + replica presence inform the strategy selector.
	nodeCount := 0
	hasReplicas := false
	if s.Cfg.ActOnAlarm && s.Kube.Client != nil {
		if names, err := s.Kube.NodeNames(ctx); err == nil {
			nodeCount = len(names)
		}
		hasReplicas = replicaExistsElsewhere(ctx, s.Kube, pod)
	} else {
		// Dry-run path: assume the strategy gates pass so the operator can
		// see the conversion flow without a live cluster.
		nodeCount = s.Cfg.ThresholdNodes + 1
		hasReplicas = true
	}

	result, err := strategy.Select(ctx, s.Kube.Client, pod, nodeCount, s.Cfg.ThresholdNodes, hasReplicas)
	if err != nil {
		writeError(w, http.StatusInternalServerError, fmt.Sprintf("strategy: %v", err))
		return
	}

	log.Printf("actuator: alarm pod=%s node=%s decision=%s reason=%q",
		body.Pod, body.Node, result.Decision, result.Reason)

	rec := &state.Record{
		Alarm:       time.Now(),
		StartedAt:   time.Now(),
		Group:       body.Group,
		Node:        body.Node,
		Pod:         body.Pod,
		PodIP:       body.PodIP,
		Decision:    stateDecision(result.Decision),
		Reason:      result.Reason,
		SourceEvent: body.SourceEvt,
	}

	switch result.Decision {
	case strategy.ConvertInSitu:
		params := conversion.RedirectParams{
			ShadowIP:         s.Cfg.ShadowClusterIP,
			ShadowPort:       s.Cfg.ShadowServicePort,
			CompromisedPodIP: body.PodIP,
			TargetNode:       body.Node,
			ClusterSvcPorts:  []uint16{8000, 9000},
		}
		// OtherNodes used by Phase 1 — populated from cluster if possible.
		if s.Cfg.ActOnAlarm && s.Kube.Client != nil {
			if names, err := s.Kube.NodeNames(ctx); err == nil {
				for _, n := range names {
					if n != body.Node {
						params.OtherNodes = append(params.OtherNodes, n)
					}
				}
			}
		}

		convRec, err := conversion.Run(ctx, s.Kube, conversion.Alarm{
			Group:    body.Group,
			Node:     body.Node,
			Pod:      body.Pod,
			PodIP:    body.PodIP,
			SourceIP: body.SourceIP,
		}, params, s.Cfg.ActOnAlarm, nodeCount)
		if err != nil {
			writeError(w, http.StatusInternalServerError, fmt.Sprintf("conversion: %v", err))
			return
		}
		rec = convRec
		// Always blacklist the source IP — the detector's alarm implies
		// known-bad activity. TTL = teardown window so the proxy entry
		// expires when the case-study ends.
		if body.SourceIP != "" {
			if err := s.Proxy.Blacklist(body.SourceIP, "alarm source IP", s.Cfg.TeardownAfter); err != nil {
				log.Printf("actuator: blacklist %s: %v", body.SourceIP, err)
			}
		}
		// Schedule teardown.
		s.Teardown.Schedule(ctx, rec, params, s.Cfg.TeardownAfter)

	case strategy.DirectEliminate:
		rec.Decision = state.DecisionDirectEliminate
		if s.Cfg.ActOnAlarm {
			grace := int64(1)
			if err := s.Kube.Client.CoreV1().Pods(pod.Namespace).Delete(ctx, pod.Name, metav1.DeleteOptions{
				GracePeriodSeconds: &grace,
			}); err != nil {
				log.Printf("actuator: direct-eliminate delete pod: %v", err)
			} else {
				log.Printf("actuator: direct-eliminate: pod %s/%s deleted", pod.Namespace, pod.Name)
			}
		} else {
			log.Printf("actuator: direct-eliminate (dry-run): would delete pod %s/%s", pod.Namespace, pod.Name)
		}
		// Blacklist both the source IP (external attacker) and the pod IP
		// (in-cluster follow-on).
		if body.SourceIP != "" {
			_ = s.Proxy.Blacklist(body.SourceIP, "direct-eliminate source", s.Cfg.TeardownAfter)
		}
		if body.PodIP != "" {
			_ = s.Proxy.Blacklist(body.PodIP, "direct-eliminate pod", s.Cfg.TeardownAfter)
		}
		// No teardown for eliminated pods (they're already gone).
	}

	if err := s.State.Add(rec); err != nil {
		log.Printf("actuator: state.Add: %v", err)
	}

	writeJSON(w, http.StatusOK, map[string]any{
		"decision": result.Decision.String(),
		"reason":   result.Reason,
		"record":   rec,
	})
}

// handleStatus returns the current state (active conversions + history).
func (s *Server) handleStatus(w http.ResponseWriter, _ *http.Request) {
	writeJSON(w, http.StatusOK, map[string]any{
		"active":      s.State.Active(),
		"conversions": s.State.Snapshot(),
		"blacklist":   s.Proxy.Snapshot(),
		"config": map[string]any{
			"shadowClusterIP":   s.Cfg.ShadowClusterIP,
			"shadowServicePort": s.Cfg.ShadowServicePort,
			"thresholdNodes":    s.Cfg.ThresholdNodes,
			"teardownAfter":     s.Cfg.TeardownAfter.String(),
			"actOnAlarm":        s.Cfg.ActOnAlarm,
		},
	})
}

// handleTeardown manually triggers teardown for a pod. Used by tests + the
// Phase 5 timing evaluation. Pass ?immediate=1 to skip the wait.
func (s *Server) handleTeardown(w http.ResponseWriter, r *http.Request) {
	podUID := r.PathValue("pod")
	if podUID == "" {
		writeError(w, http.StatusBadRequest, "pod required")
		return
	}
	rec, ok := s.State.Get(podUID)
	if !ok {
		writeError(w, http.StatusNotFound, fmt.Sprintf("no record for pod %s", podUID))
		return
	}
	if rec.Torndown {
		writeError(w, http.StatusConflict, "already torn down")
		return
	}

	immediate := r.URL.Query().Get("immediate") == "1"
	wait := s.Cfg.TeardownAfter
	if immediate {
		wait = 0
	}
	params := conversion.RedirectParams{
		ShadowIP:         s.Cfg.ShadowClusterIP,
		ShadowPort:       s.Cfg.ShadowServicePort,
		CompromisedPodIP: rec.PodIP,
		TargetNode:       rec.Node,
		ClusterSvcPorts:  []uint16{8000, 9000},
	}
	s.Teardown.Schedule(r.Context(), rec, params, wait)

	writeJSON(w, http.StatusAccepted, map[string]any{
		"pod":       podUID,
		"immediate": immediate,
		"wait":      wait.String(),
	})
}

// handleBlacklist returns the current blacklist.
func (s *Server) handleBlacklist(w http.ResponseWriter, _ *http.Request) {
	writeJSON(w, http.StatusOK, s.Proxy.Snapshot())
}

// handleBlacklistAdd manually blacklists an IP (manual operator override).
func (s *Server) handleBlacklistAdd(w http.ResponseWriter, r *http.Request) {
	ip := r.PathValue("ip")
	if ip == "" {
		writeError(w, http.StatusBadRequest, "ip required")
		return
	}
	ttl := s.Cfg.TeardownAfter
	if v := r.URL.Query().Get("ttl"); v != "" {
		d, err := time.ParseDuration(v)
		if err != nil {
			writeError(w, http.StatusBadRequest, fmt.Sprintf("ttl: %v", err))
			return
		}
		ttl = d
	}
	reason := r.URL.Query().Get("reason")
	if reason == "" {
		reason = "manual operator blacklist"
	}
	if err := s.Proxy.Blacklist(ip, reason, ttl); err != nil {
		writeError(w, http.StatusInternalServerError, err.Error())
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"ip": ip, "ttl": ttl.String()})
}

// handleDecide is a passive-mode debug endpoint that returns the proxy
// routing decision for a given source IP without actually proxying.
func (s *Server) handleDecide(w http.ResponseWriter, r *http.Request) {
	src := r.PathValue("src")
	c, a := s.Proxy.LogDecide(src)
	writeJSON(w, http.StatusOK, map[string]string{"src": src, "cluster": c, "action": a})
}

func writeJSON(w http.ResponseWriter, code int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(code)
	_ = json.NewEncoder(w).Encode(v)
}

func writeError(w http.ResponseWriter, code int, msg string) {
	writeJSON(w, code, map[string]string{"error": msg})
}

// stateDecision converts the strategy.Decision enum to state.Decision.
func stateDecision(d strategy.Decision) state.Decision {
	switch d {
	case strategy.ConvertInSitu:
		return state.DecisionConvertInSitu
	}
	return state.DecisionDirectEliminate
}

// k8sUID makes a types.UID from a string (used in dry-run stubs).
func k8sUID(s string) types.UID {
	return types.UID(s)
}

// replicaExistsElsewhere reports whether there are pods matching the
// compromised pod's labels running on other nodes. We use the pod's own
// labels as a proxy for the workload selector — in practice these match
// for pods created by Deployments, which is what the paper targets.
func replicaExistsElsewhere(ctx context.Context, k *conversion.Kube, pod *corev1.Pod) bool {
	if k.Client == nil || pod == nil {
		return false
	}
	if len(pod.Labels) == 0 {
		return false
	}
	list, err := k.Client.CoreV1().Pods(pod.Namespace).List(ctx, metav1.ListOptions{
		LabelSelector: labelsToSelector(pod.Labels),
	})
	if err != nil {
		log.Printf("actuator: replica lookup: %v", err)
		return false
	}
	for i := range list.Items {
		if list.Items[i].UID == pod.UID {
			continue
		}
		if list.Items[i].Spec.NodeName != pod.Spec.NodeName {
			return true
		}
	}
	return false
}

func labelsToSelector(m map[string]string) string {
	parts := make([]string, 0, len(m))
	for k, v := range m {
		parts = append(parts, k+"="+v)
	}
	out := ""
	for i, p := range parts {
		if i > 0 {
			out += ","
		}
		out += p
	}
	return out
}
