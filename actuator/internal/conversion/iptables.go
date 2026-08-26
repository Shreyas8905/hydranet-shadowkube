// Package conversion: iptables.go implements Phase 1 (network
// reconfiguration) of the honeypot conversion.
//
// We shell out to `iptables` via os/exec rather than linking netlink. This
// keeps the build hermetic, makes the rules visible in pod logs for
// debugging, and matches what the paper's lab implementation typically
// does. Each shell-out uses nsenter into the target node's network
// namespace when running off-cluster, but inside a privileged pod with
// hostNetwork:true the host's iptables is reachable directly.
//
// Two rule sets:
//
//   1. On the compromised node:
//        -t nat -A OUTPUT  -p tcp --dport <cluster-svc-port> -j DNAT --to-destination <shadowIP>:<shadowPort>
//
//   2. On every OTHER node:
//        -t filter -A INPUT -s <compromisedPodIP> -j DROP
//
// In lab mode (ActOnAlarm=false) we log the iptables command lines without
// running them.
package conversion

import (
	"context"
	"fmt"
	"log"
	"os/exec"
	"strings"
	"time"

	"github.com/shadowkube-repro/actuator/internal/state"
)

// iptablesRunner shells out to iptables. Replaced in tests via
// SetRunner.
var iptablesRunner = func(args ...string) error {
	cmd := exec.Command("iptables", args...)
	out, err := cmd.CombinedOutput()
	if err != nil {
		return fmt.Errorf("iptables %s: %v (%s)", strings.Join(args, " "), err, string(out))
	}
	return nil
}

// SetIptablesRunner overrides the runner (for tests).
func SetIptablesRunner(r func(args ...string) error) { iptablesRunner = r }

// RedirectParams describes the redirection rule(s) to install.
type RedirectParams struct {
	ShadowIP         string        // e.g. "172.18.0.5"
	ShadowPort       uint16        // e.g. 30081
	CompromisedPodIP string        // e.g. "10.42.0.7"
	ClusterSvcPorts  []uint16      // ports of in-cluster services to redirect
	TargetNode       string        // node hosting the compromised pod
	OtherNodes       []string      // every other node
}

// Phase1 redirects cluster traffic from the compromised pod to the shadow
// cluster and isolates the pod from peer nodes. Records timing in the state
// Record.
func Phase1(ctx context.Context, k *Kube, rec *state.Record, p RedirectParams, actOnAlarm bool) error {
	t0 := time.Now()

	if len(p.ClusterSvcPorts) == 0 {
		// Default: redirect the weather app's service ports.
		p.ClusterSvcPorts = []uint16{8000, 9000}
	}

	if actOnAlarm {
		// 1. DNAT on the target node for each in-cluster service port.
		for _, port := range p.ClusterSvcPorts {
			dest := fmt.Sprintf("%s:%d", p.ShadowIP, p.ShadowPort)
			// The --dport is the cluster service port on the *destination*
			// (i.e. what the application dialed). With k3d sharing the host
			// network, the cluster's service IP resolves to localhost:port.
			// We intercept outbound to those local ports and forward to the
			// shadow cluster's address.
			if err := iptablesRunner(
				"-t", "nat", "-A", "OUTPUT",
				"-p", "tcp",
				"--dport", fmt.Sprintf("%d", port),
				"-j", "DNAT",
				"--to-destination", dest,
			); err != nil {
				return fmt.Errorf("phase1 dnat port %d: %w", port, err)
			}
			log.Printf("phase1: iptables -t nat -A OUTPUT -p tcp --dport %d -j DNAT --to-destination %s", port, dest)
		}
		// 2. Drop traffic from the compromised pod on every other node.
		for _, node := range p.OtherNodes {
			_ = node // In a DaemonSet model we'd execute iptables on each
			// node's network namespace via nsenter. In the lab Deployment
			// model we rely on the host iptables (hostNetwork:true) which
			// applies cluster-wide already; the per-node distinction is
			// conceptual. We still log it for fidelity.
			log.Printf("phase1: would isolate pod %s on node %s (host iptables already global)", p.CompromisedPodIP, node)
		}
		// Also: drop the INPUT chain on the host for the pod IP, to prevent
		// the pod from receiving responses from cluster peers.
		if err := iptablesRunner(
			"-t", "filter", "-I", "INPUT", "1",
			"-s", p.CompromisedPodIP,
			"-j", "DROP",
		); err != nil {
			return fmt.Errorf("phase1 isolate: %w", err)
		}
		log.Printf("phase1: iptables -t filter -I INPUT 1 -s %s -j DROP", p.CompromisedPodIP)
	} else {
		log.Printf("phase1 (dry-run): would DNAT %v -> %s:%d; would isolate %s",
			p.ClusterSvcPorts, p.ShadowIP, p.ShadowPort, p.CompromisedPodIP)
	}

	rec.Timings.Phase1 = time.Since(t0)
	return nil
}

// UndoPhase1 removes the iptables rules installed by Phase1.
func UndoPhase1(ctx context.Context, p RedirectParams, actOnAlarm bool) error {
	if !actOnAlarm {
		log.Printf("phase1-undo (dry-run): would remove DNAT/INPUT rules for pod %s", p.CompromisedPodIP)
		return nil
	}
	// Drop the INPUT rule (-I was at position 1; remove from any position).
	if err := iptablesRunner(
		"-t", "filter", "-D", "INPUT",
		"-s", p.CompromisedPodIP,
		"-j", "DROP",
	); err != nil {
		log.Printf("phase1-undo: remove INPUT rule: %v", err)
	}
	for _, port := range p.ClusterSvcPorts {
		if err := iptablesRunner(
			"-t", "nat", "-D", "OUTPUT",
			"-p", "tcp",
			"--dport", fmt.Sprintf("%d", port),
			"-j", "DNAT",
			"--to-destination", fmt.Sprintf("%s:%d", p.ShadowIP, p.ShadowPort),
		); err != nil {
			log.Printf("phase1-undo: remove DNAT rule for port %d: %v", port, err)
		}
	}
	log.Printf("phase1-undo: removed iptables rules for pod %s", p.CompromisedPodIP)
	return nil
}