// Package conversion: sanitize.go implements Phase 2 (pods sanitation).
//
// Lists every pod on the target node EXCEPT the compromised one, and
// deletes them. The API server reschedules them on other nodes (where
// replicas of their workloads exist, per the strategy selector).
package conversion

import (
	"context"
	"fmt"
	"log"
	"time"

	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"

	"github.com/shadowkube-repro/actuator/internal/state"
)

// Phase2 deletes all pods on the target node except the compromised pod.
// Returns the count of pods deleted (for telemetry).
func Phase2(ctx context.Context, k *Kube, rec *state.Record, compromisedPodUID, targetNode string, actOnAlarm bool) (int, error) {
	t0 := time.Now()
	pods, err := k.PodsOnNode(ctx, targetNode)
	if err != nil {
		return 0, fmt.Errorf("list pods on %s: %w", targetNode, err)
	}
	deleted := 0
	for _, p := range pods {
		if string(p.UID) == compromisedPodUID {
			continue
		}
		// Don't delete kube-system pods (it would kill the actuator itself).
		if p.Namespace == "kube-system" || p.Namespace == "shadowkube-system" {
			continue
		}
		if !actOnAlarm {
			log.Printf("phase2 (dry-run): would delete pod %s/%s uid=%s", p.Namespace, p.Name, p.UID)
			deleted++
			continue
		}
		grace := int64(5)
		err := k.Client.CoreV1().Pods(p.Namespace).Delete(ctx, p.Name, metav1.DeleteOptions{
			GracePeriodSeconds: &grace,
		})
		if err != nil {
			log.Printf("phase2: delete pod %s/%s: %v", p.Namespace, p.Name, err)
			continue
		}
		deleted++
		log.Printf("phase2: deleted pod %s/%s uid=%s", p.Namespace, p.Name, p.UID)
	}
	rec.Timings.Phase2 = time.Since(t0)
	return deleted, nil
}