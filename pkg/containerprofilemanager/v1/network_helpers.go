package containerprofilemanager

import (
	"crypto/sha256"
	"fmt"
	"sort"
	"strings"

	"github.com/kubescape/storage/pkg/apis/softwarecomposition/v1beta1"
)

type EndpointKind string

var DefaultLabelsToIgnore = map[string]struct{}{
	"controller-revision-hash": {},
	"pod-template-generation":  {},
	"pod-template-hash":        {},
}

const (
	InternalTrafficType = "internal"
	ExternalTrafficType = "external"
)

const (
	EndpointKindPod     EndpointKind = "pod"
	EndpointKindService EndpointKind = "svc"
	EndpointKindRaw     EndpointKind = "raw"
)

type NetworkEvent struct {
	Port        uint16
	PktType     string
	Protocol    string
	PodLabels   string
	Destination Destination
}

type Destination struct {
	Namespace string
	Name      string
	Kind      EndpointKind
	PodLabels string
	IPAddress string
}

func (ne *NetworkEvent) String() string {
	return fmt.Sprintf("Port: %d, PktType: %s, Protocol: %s, PodLabels: %s, Destination: %s", ne.Port, ne.PktType, ne.Protocol, ne.PodLabels, ne.Destination)
}

// GetDestinationPodLabels returns a map of pod labels from the string in the network event. The labels are saved separated by commas, so we need to split them
func (ne *NetworkEvent) GetDestinationPodLabels() map[string]string {
	podLabels := make(map[string]string, 0)

	if ne.Destination.PodLabels == "" {
		return podLabels
	}

	podLabelsSlice := strings.Split(ne.Destination.PodLabels, ",")
	for _, podLabel := range podLabelsSlice {
		podLabelSlice := strings.Split(podLabel, "=")
		if len(podLabelSlice) == 2 {
			podLabels[podLabelSlice[0]] = podLabelSlice[1]
		}
	}

	return podLabels
}

func (ne *NetworkEvent) SetPodLabels(podLabels map[string]string) {
	ne.PodLabels = generatePodLabels(podLabels)
}

func (ne *NetworkEvent) SetDestinationPodLabels(podLabels map[string]string) {
	ne.Destination.PodLabels = generatePodLabels(podLabels)
}

// generatePodLabels generates a single string from a map of pod labels. This string is separated with commas and is needed so the set in network manager will work
func generatePodLabels(podLabels map[string]string) string {
	var keys []string
	for key := range podLabels {
		keys = append(keys, key)
	}

	sort.Strings(keys)

	var podLabelsString string
	for _, key := range keys {
		podLabelsString = podLabelsString + key + "=" + podLabels[key] + ","
	}

	if len(podLabelsString) > 0 {
		podLabelsString = podLabelsString[:len(podLabelsString)-1]
	}

	return podLabelsString
}

func generatePortIdentifierFromEvent(networkEvent NetworkEvent) string {
	return generatePortIdentifier(networkEvent.Protocol, int32(networkEvent.Port))
}

func generatePortIdentifier(protocol string, port int32) string {
	return fmt.Sprintf("%s-%d", protocol, port)
}

// filterLabels filters out labels that are not relevant for the network neighbor
func filterLabels(labels map[string]string) map[string]string {
	filteredLabels := make(map[string]string)

	for i := range labels {
		if _, ok := DefaultLabelsToIgnore[i]; ok {
			continue
		}
		filteredLabels[i] = labels[i]
	}

	return filteredLabels
}

func generateNeighborsIdentifier(neighborEntry v1beta1.NetworkNeighbor) (string, error) {
	// identifier is hash of everything in egress except ports
	identifier := fmt.Sprintf("%s-%s-%s-%s-%s", neighborEntry.Type, neighborEntry.IPAddress, neighborEntry.DNS, neighborEntry.NamespaceSelector, neighborEntry.PodSelector)
	hash := sha256.New()
	_, err := hash.Write([]byte(identifier))
	if err != nil {
		return "", err
	}
	return fmt.Sprintf("%x", hash.Sum(nil)), nil
}

func getNamespaceMatchLabels(destinationNamespace, sourceNamespace string) map[string]string {
	if destinationNamespace != sourceNamespace {
		// from version 1.22, all namespace have the kubernetes.io/metadata.name label
		return map[string]string{
			"kubernetes.io/metadata.name": destinationNamespace,
		}
	}
	return nil
}
