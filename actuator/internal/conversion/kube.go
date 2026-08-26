// Package conversion contains the 3-phase honeypot-conversion pipeline plus
// shared k8s API helpers. The kube.go file in this package centralizes the
// thin wrappers other files need so they don't all import client-go.
package conversion

import (
	"context"
	"fmt"

	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/kubernetes"
)

// Kube is the small subset of the k8s API the actuator needs.
type Kube struct {
	Client kubernetes.Interface
}

// NewKube constructs a Kube.
func NewKube(c kubernetes.Interface) *Kube { return &Kube{Client: c} }

// NodeNames returns all node names in the cluster.
func (k *Kube) NodeNames(ctx context.Context) ([]string, error) {
	nodes, err := k.Client.CoreV1().Nodes().List(ctx, metav1.ListOptions{})
	if err != nil {
		return nil, err
	}
	out := make([]string, 0, len(nodes.Items))
	for _, n := range nodes.Items {
		out = append(out, n.Name)
	}
	return out, nil
}

// PodsOnNode returns pods scheduled on a specific node.
func (k *Kube) PodsOnNode(ctx context.Context, node string) ([]corev1.Pod, error) {
	list, err := k.Client.CoreV1().Pods("").List(ctx, metav1.ListOptions{
		FieldSelector: "spec.nodeName=" + node,
	})
	if err != nil {
		return nil, err
	}
	return list.Items, nil
}

// PodByUID returns the pod with the given UID.
func (k *Kube) PodByUID(ctx context.Context, uid string) (*corev1.Pod, error) {
	if k == nil || k.Client == nil {
		return nil, fmt.Errorf("no k8s client (dry-run mode?)")
	}
	list, err := k.Client.CoreV1().Pods("").List(ctx, metav1.ListOptions{})
	if err != nil {
		return nil, err
	}
	for i := range list.Items {
		if string(list.Items[i].UID) == uid {
			return &list.Items[i], nil
		}
	}
	return nil, fmt.Errorf("pod with uid %s not found", uid)
}

// PodIP returns the pod's IP (status.podIP), or "" if not assigned yet.
func PodIP(p *corev1.Pod) string {
	return p.Status.PodIP
}

// HasWriteableHostPath reports whether any of the pod's volumes is a host
// path to a writeable mount. Used by strategy selection: if the compromised
// node already holds attacker state on disk, we shouldn't do an in-situ
// conversion (attacker could still see their old files after the iptables
// redirection).
func HasWriteableHostPath(p *corev1.Pod) bool {
	for _, v := range p.Spec.Volumes {
		if v.HostPath == nil {
			continue
		}
		// Any hostPath with type != "FileOrCreate" / "File" is writeable.
		// Treat absence of type as DirectoryOrCreate (writeable).
		t := v.HostPath.Type
		if t == nil {
			return true
		}
		switch *t {
		case corev1.HostPathDirectoryOrCreate,
			corev1.HostPathDirectory,
			corev1.HostPathUnset:
			return true
		}
	}
	return false
}