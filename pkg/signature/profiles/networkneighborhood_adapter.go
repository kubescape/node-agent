package profiles

import (
	"github.com/kubescape/storage/pkg/apis/softwarecomposition/v1beta1"
)

type NetworkNeighborhoodAdapter struct {
	nn *v1beta1.NetworkNeighborhood
}

func NewNetworkNeighborhoodAdapter(nn *v1beta1.NetworkNeighborhood) *NetworkNeighborhoodAdapter {
	return &NetworkNeighborhoodAdapter{
		nn: nn,
	}
}

func (a *NetworkNeighborhoodAdapter) GetAnnotations() map[string]string {
	if a.nn.Annotations == nil {
		a.nn.Annotations = make(map[string]string)
	}
	return a.nn.Annotations
}

func (a *NetworkNeighborhoodAdapter) SetAnnotations(annotations map[string]string) {
	a.nn.Annotations = annotations
}

func (a *NetworkNeighborhoodAdapter) GetUID() string {
	return string(a.nn.UID)
}

func (a *NetworkNeighborhoodAdapter) GetNamespace() string {
	return a.nn.Namespace
}

func (a *NetworkNeighborhoodAdapter) GetName() string {
	return a.nn.Name
}

func (a *NetworkNeighborhoodAdapter) GetContent() interface{} {
	apiVersion := a.nn.APIVersion
	if apiVersion == "" {
		apiVersion = "spdx.softwarecomposition.kubescape.io/v1beta1"
	}
	kind := a.nn.Kind
	if kind == "" {
		kind = "NetworkNeighborhood"
	}
	return map[string]interface{}{
		"apiVersion": apiVersion,
		"kind":       kind,
		"metadata": map[string]interface{}{
			"name":      a.nn.Name,
			"namespace": a.nn.Namespace,
			"labels":    a.nn.Labels,
		},
		"spec": a.nn.Spec,
	}
}

func (a *NetworkNeighborhoodAdapter) GetUpdatedObject() interface{} {
	return a.nn
}
