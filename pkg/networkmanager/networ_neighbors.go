package networkmanager

import (
	"fmt"
	"strings"

	"github.com/kubescape/k8s-interface/instanceidhandler/v1"
	instanceidhandlerV1 "github.com/kubescape/k8s-interface/instanceidhandler/v1"
	"github.com/kubescape/k8s-interface/k8sinterface"
	"github.com/kubescape/storage/pkg/apis/softwarecomposition/v1beta1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

const (
	completeStatus = "complete"
	incomplete     = "incomplete"
)

func generateNetworkNeighborsCRD(parentWorkload k8sinterface.IWorkload, parentWorkloadSelector *metav1.LabelSelector) *v1beta1.NetworkNeighbors {
	return &v1beta1.NetworkNeighbors{
		TypeMeta: metav1.TypeMeta{
			Kind:       "NetworkNeighbors",
			APIVersion: "softwarecomposition.kubescape.io/v1beta1",
		},
		ObjectMeta: metav1.ObjectMeta{
			Annotations: map[string]string{
				instanceidhandler.StatusMetadataKey: incomplete,
			},
			Name:      generateNetworkNeighborsName(parentWorkload),
			Namespace: parentWorkload.GetNamespace(),
			Labels:    generateNetworkNeighborsLabels(parentWorkload),
		},
		Spec: v1beta1.NetworkNeighborsSpec{
			LabelSelector: &metav1.LabelSelector{
				MatchLabels:      parentWorkloadSelector.MatchLabels,
				MatchExpressions: parentWorkloadSelector.MatchExpressions,
			},
		},
	}
}

func generateNetworkNeighborsName(parentWorkload k8sinterface.IWorkload) string {
	return fmt.Sprintf("%s-%s", strings.ToLower(parentWorkload.GetKind()), parentWorkload.GetName())
}

func generateNetworkNeighborsLabels(workload k8sinterface.IWorkload) map[string]string {
	var apiVersion, apiGroup string
	apiVersionSplitted := strings.Split(workload.GetApiVersion(), "/")
	if len(apiVersionSplitted) == 2 {
		apiGroup = apiVersionSplitted[0]
		apiVersion = apiVersionSplitted[1]
	}

	return map[string]string{
		instanceidhandlerV1.ApiGroupMetadataKey:   apiGroup,
		instanceidhandlerV1.ApiVersionMetadataKey: apiVersion,
		instanceidhandlerV1.NamespaceMetadataKey:  workload.GetNamespace(),
		instanceidhandlerV1.KindMetadataKey:       workload.GetKind(),
		instanceidhandlerV1.NameMetadataKey:       workload.GetName(),
	}
}

// filterLabels filters out labels that are not relevant for the network neighbor
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
