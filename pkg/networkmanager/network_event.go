package networkmanager

import (
	"fmt"
	"sort"
	"strings"
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

func (ne *NetworkEvent) String() string {
	return fmt.Sprintf("Port: %d, PktType: %s, Protocol: %s, PodLabels: %s, Destination: %s", ne.Port, ne.PktType, ne.Protocol, ne.PodLabels, ne.Destination)
}

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
