// Package strategy decides what to do when an alarm fires.
//
// Mirrors the paper's feasibility gate for in-situ honeypot conversion:
//   1. No persistent storage on the target node (no writeable hostPath).
//   2. Cluster node count > ThresholdNodes (so the workload can survive
//      the pod sanitation step).
//   3. Replica pods of the compromised workload exist on OTHER nodes
//      (so rescheduling restores service continuity).
//
// All three must be true for ConvertInSitu; otherwise DirectEliminate.
package strategy

import (
	"context"
	"fmt"

	corev1 "k8s.io/api/core/v1"
	"k8s.io/client-go/kubernetes"

	"github.com/shadowkube-repro/actuator/internal/conversion"
)

// Decision is what the strategy chose.
type Decision int

const (
	// ConvertInSitu runs the 3-phase honeypot conversion.
	ConvertInSitu Decision = iota
	// DirectEliminate deletes the malicious pod and blacklists the IP.
	DirectEliminate
)

func (d Decision) String() string {
	switch d {
	case ConvertInSitu:
		return "convert_in_situ"
	case DirectEliminate:
		return "direct_eliminate"
	}
	return "unknown"
}

// Result is the decision + a human-readable reason (for state records).
type Result struct {
	Decision Decision
	Reason   string
}

// Select runs the feasibility checks and returns the chosen action.
//
// pod is the compromised pod (must have UID, Name, Namespace set).
// nodeCount is the total number of nodes in the cluster (caller's job).
// hasReplicas is whether the pod's workload selector matches pods on
// other nodes (caller's job, computed by selector.HasReplicasElsewhere).
func Select(ctx context.Context, k8s kubernetes.Interface, pod *corev1.Pod, nodeCount, threshold int, hasReplicas bool) (Result, error) {
	if pod == nil {
		return Result{Decision: DirectEliminate, Reason: "no pod info"}, fmt.Errorf("nil pod")
	}

	if conversion.HasWriteableHostPath(pod) {
		return Result{
			Decision: DirectEliminate,
			Reason:   "compromised pod mounts writeable hostPath; node holds attacker state",
		}, nil
	}

	if nodeCount <= threshold {
		return Result{
			Decision: DirectEliminate,
			Reason:   fmt.Sprintf("node count %d <= threshold %d", nodeCount, threshold),
		}, nil
	}

	if !hasReplicas {
		return Result{
			Decision: DirectEliminate,
			Reason:   "no replica pods of this workload on other nodes; sanitation would cause downtime",
		}, nil
	}

	return Result{
		Decision: ConvertInSitu,
		Reason:   "all feasibility checks passed: no hostPath, sufficient nodes, replicas elsewhere",
	}, nil
}