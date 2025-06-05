package containerprofilemanager

import (
	"fmt"
	"sort"
	"strings"

	mapset "github.com/deckarep/golang-set/v2"
	"github.com/goradd/maps"
	"github.com/kubescape/node-agent/pkg/utils"
	"github.com/kubescape/storage/pkg/apis/softwarecomposition/v1beta1"
)

var ErrContainerNotFound = fmt.Errorf("container not found")

type containerData struct {
	// WatchedContainerData contains the data for a watched container
	WatchedContainerData *utils.WatchedContainerData // TODO: move watched container data to here

	// Events reported for this container that needs to be saved to the profile
	capabilites  mapset.Set[string]
	endpoints    *maps.SafeMap[string, *v1beta1.HTTPEndpoint]
	execs        *maps.SafeMap[string, []string]                     // Map of execs reported for this container, key is the SHA256 hash of the exec
	opens        *maps.SafeMap[string, mapset.Set[string]]           // Map of opens reported for this container, key is the file path
	rulePolicies *maps.SafeMap[string, *v1beta1.RulePolicy]          // Map of rule policies reported for this container, key is the rule ID
	callStacks   *maps.SafeMap[string, *v1beta1.IdentifiedCallStack] // Map of callstacks reported for this container, key is the SHA256 hash of the callstack
	networks     mapset.Set[NetworkEvent]
	// TODO: syscalls?

	// TODO: cache events we reported already, so we don't report them again
}

// TODO: Add functions to check for events stuff.

// TODO: Check what we can get rid of from here.
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

var DefaultLabelsToIgnore = map[string]struct{}{
	"controller-revision-hash": {},
	"pod-template-generation":  {},
	"pod-template-hash":        {},
}

const (
	InternalTrafficType = "internal"
	ExternalTrafficType = "external"
	HostPktType         = "HOST"
	OutgoingPktType     = "OUTGOING"
)

const (
	EndpointKindPod     EndpointKind = "pod"
	EndpointKindService EndpointKind = "svc"
	EndpointKindRaw     EndpointKind = "raw"
)

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

func GeneratePortIdentifierFromEvent(networkEvent NetworkEvent) string {
	return GeneratePortIdentifier(networkEvent.Protocol, int32(networkEvent.Port))
}

func GeneratePortIdentifier(protocol string, port int32) string {
	return fmt.Sprintf("%s-%d", protocol, port)
}
