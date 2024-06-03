package utils

import (
	"crypto/sha256"
	"fmt"

	"github.com/kubescape/storage/pkg/apis/softwarecomposition/v1beta1"
)

func CreateNetworkPatchOperations(ingress, egress []v1beta1.NetworkNeighbor, containerType string, containerIndex int) []PatchOperation {
	var networkOperations []PatchOperation
	patchNeighbors := func(neighborType string, neighbors []v1beta1.NetworkNeighbor) {
		networkPath := fmt.Sprintf("/spec/%s/%d/%s/-", containerType, containerIndex, neighborType)
		for _, neighbor := range neighbors {
			networkOperations = append(networkOperations, PatchOperation{
				Op:    "add",
				Path:  networkPath,
				Value: neighbor,
			})
		}
	}
	patchNeighbors("ingress", ingress)
	patchNeighbors("egress", egress)
	return networkOperations
}

func EnrichNeighborhoodContainer(container *v1beta1.NetworkNeighborhoodContainer, ingress, egress []v1beta1.NetworkNeighbor) {
	if container == nil {
		return
	}
	container.Ingress = append(container.Ingress, ingress...)
	container.Egress = append(container.Egress, egress...)
}

// TODO make generic?
func GetNetworkNeighborhoodContainer(object *v1beta1.NetworkNeighborhood, containerType ContainerType, containerIndex int) *v1beta1.NetworkNeighborhoodContainer {
	if object == nil {
		return nil
	}
	switch containerType {
	case Container:
		if len(object.Spec.Containers) > containerIndex {
			return &object.Spec.Containers[containerIndex]
		}
	case InitContainer:
		if len(object.Spec.InitContainers) > containerIndex {
			return &object.Spec.InitContainers[containerIndex]
		}
	case EphemeralContainer:
		if len(object.Spec.EphemeralContainers) > containerIndex {
			return &object.Spec.EphemeralContainers[containerIndex]
		}
	}
	return nil
}

func GenerateNeighborsIdentifier(neighborEntry v1beta1.NetworkNeighbor) (string, error) {
	// identifier is hash of everything in egress except ports
	identifier := fmt.Sprintf("%s-%s-%s-%s-%s", neighborEntry.Type, neighborEntry.IPAddress, neighborEntry.DNS, neighborEntry.NamespaceSelector, neighborEntry.PodSelector)
	hash := sha256.New()
	_, err := hash.Write([]byte(identifier))
	if err != nil {
		return "", err
	}
	return fmt.Sprintf("%x", hash.Sum(nil)), nil
}

func GetNamespaceMatchLabels(destinationNamespace, sourceNamespace string) map[string]string {
	if destinationNamespace != sourceNamespace {
		// from version 1.22, all namespace have the kubernetes.io/metadata.name label
		return map[string]string{
			"kubernetes.io/metadata.name": destinationNamespace,
		}
	}
	return nil
}
