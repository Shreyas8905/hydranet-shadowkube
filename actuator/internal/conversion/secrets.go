// Package conversion: secrets.go implements Phase 3 (sensitive info
// alteration).
//
// The paper replaces SA tokens on the target node + pod with shadow-cluster
// equivalents and installs the monitor. In our lab, Phase 1 (iptables) has
// already neutered the pod's effective cluster access, so Phase 3 is
// largely defense-in-depth: we log the action and write a marker file so
// the operator can see what would have happened.
package conversion

import (
	"context"
	"log"
	"os"
	"time"

	"github.com/shadowkube-repro/actuator/internal/state"
)

// Phase3 writes a marker file documenting the would-be token replacement.
// On a real cluster this is where you'd `kubectl exec` into the pod and
// overwrite /var/run/secrets/kubernetes.io/serviceaccount/token.
func Phase3(ctx context.Context, rec *state.Record, podUID, node string, actOnAlarm bool) error {
	t0 := time.Now()
	markerPath := "/var/lib/shadowkube/actuator/phase3.log"

	if !actOnAlarm {
		log.Printf("phase3 (dry-run): would replace SA token on pod %s (node %s) and install monitor", podUID, node)
		rec.Timings.Phase3 = time.Since(t0)
		return nil
	}

	// Write a structured line so an operator can audit later.
	line := "phase3 token replacement pending; monitor already present (probe DaemonSet)\n"
	if err := appendToFile(markerPath, line); err != nil {
		log.Printf("phase3: marker file: %v (continuing)", err)
	}
	log.Printf("phase3: token replacement noted for pod %s on node %s", podUID, node)
	rec.Timings.Phase3 = time.Since(t0)
	return nil
}

func appendToFile(path, line string) error {
	f, err := os.OpenFile(path, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0o644)
	if err != nil {
		return err
	}
	defer f.Close()
	_, err = f.WriteString(line)
	return err
}