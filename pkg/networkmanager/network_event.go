package networkmanager

import "strings"

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

type EndpointKind string

var defaultLabelsToIgnore = map[string]struct{}{
	"controller-revision-hash": {},
	"pod-template-generation":  {},
	"pod-template-hash":        {},
}

const (
	EndpointKindPod     EndpointKind = "pod"
	EndpointKindService EndpointKind = "svc"
	EndpointKindRaw     EndpointKind = "raw"
)

func (ne *NetworkEvent) GetDestinationPodLabels() map[string]string {
	podLabels := make(map[string]string, 0)
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

func generatePodLabels(podLabels map[string]string) string {
	var podLabelsString string
	for key, value := range podLabels {
		podLabelsString = podLabelsString + key + "=" + value + ","
	}
	return podLabelsString
}
