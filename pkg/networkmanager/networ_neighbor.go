package networkmanager

import (
	"fmt"

	instanceidhandlerV1 "github.com/kubescape/k8s-interface/instanceidhandler/v1"
	"github.com/kubescape/k8s-interface/k8sinterface"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

type NetworkNeighbors struct {
	APIVersion string   `json:"apiVersion"`
	Kind       string   `json:"kind"`
	Metadata   Metadata `json:"metadata"`
	Spec       Spec     `json:"spec"`
}

type Metadata struct {
	Name      string            `json:"name"`
	Kind      string            `json:"kind"`
	Namespace string            `json:"namespace"`
	Labels    map[string]string `json:"labels"` // Assuming the labels are key-value pairs
}

type Spec struct {
	MatchLabels      map[string]string                 `json:"matchLabels"`
	MatchExpressions []metav1.LabelSelectorRequirement `json:"matchExpressions"`
	Ingress          []NeighborEntry                   `json:"ingress"`
	Egress           []NeighborEntry                   `json:"egress"`
}

type NeighborEntry struct {
	Type              string                `json:"type"`
	Identifier        string                `json:"identifier"`
	NamespaceSelector *metav1.LabelSelector `json:"namespaceSelector"`
	PodSelector       *metav1.LabelSelector `json:"podSelector"`
	Ports             []Port                `json:"ports"`
	IPAddress         string                `json:"ipAddress"`
	DNS               string                `json:"dns"`
}

type Port struct {
	Name     string `json:"name"`
	Protocol string `json:"protocol"`
	Port     uint16 `json:"port"`
}

func createNetworkNeighborsCRD(parentWorkload k8sinterface.IWorkload, parentWorkloadSelector *metav1.LabelSelector) *NetworkNeighbors {
	networkNeighbors := &NetworkNeighbors{
		Kind: "NetworkNeighbors",
		Metadata: Metadata{
			Name:      fmt.Sprintf("%s-%s", parentWorkload.GetKind(), parentWorkload.GetName()),
			Kind:      parentWorkload.GetKind(),
			Namespace: parentWorkload.GetNamespace(),
			Labels:    generateNetworkNeighborsLabels(parentWorkload),
		},
		Spec: Spec{
			MatchLabels:      parentWorkloadSelector.MatchLabels,
			MatchExpressions: parentWorkloadSelector.MatchExpressions,
		},
	}
	return networkNeighbors
}

func generateNetworkNeighborsLabels(workload k8sinterface.IWorkload) map[string]string {
	return map[string]string{
		instanceidhandlerV1.ApiGroupMetadataKey:   "NetworkNeighbor", // TOOD: take from storage sdk
		instanceidhandlerV1.ApiVersionMetadataKey: "v1",              // TOOD: take from storage sdk
		instanceidhandlerV1.NamespaceMetadataKey:  workload.GetNamespace(),
		instanceidhandlerV1.KindMetadataKey:       workload.GetKind(),
		instanceidhandlerV1.NameMetadataKey:       workload.GetName(),
	}
}

func filterLabels(labels map[string]string) map[string]string {
	filteredLabels := make(map[string]string)

	for i := range labels {
		if _, ok := defaultLabelsToIgnore[i]; ok {
			continue
		}
		filteredLabels[i] = labels[i]
	}

	return filteredLabels
}
