package containerprofilemanager

import (
	"net"
	"sort"
	"time"

	"github.com/DmitriyVTitov/size"
	mapset "github.com/deckarep/golang-set/v2"
	"github.com/inspektor-gadget/inspektor-gadget/pkg/operators/common"
	"github.com/kubescape/go-logger"
	"github.com/kubescape/go-logger/helpers"
	"github.com/kubescape/k8s-interface/k8sinterface"
	"github.com/kubescape/node-agent/pkg/dnsmanager"
	"github.com/kubescape/node-agent/pkg/k8sclient"
	"github.com/kubescape/node-agent/pkg/objectcache"
	"github.com/kubescape/node-agent/pkg/utils"
	"github.com/kubescape/storage/pkg/apis/softwarecomposition/v1beta1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

// emptyEvents clears all event data, but retains deferred network events for re-resolution
func (cd *containerData) emptyEvents() {
	cd.size.Store(0)
	cd.capabilites = nil
	cd.syscalls = nil
	cd.endpoints = nil
	cd.execs = nil
	cd.opens = nil
	cd.rulePolicies = nil
	cd.callStacks = nil
	if cd.networkFlushForSize {
		// Pressure flushes only consumed the active batch. Keep untouched pending
		// peers in place rather than scanning or cloning their growing backlog.
		if cd.activeNetworks != nil {
			for _, event := range cd.activeNetworks.ToSlice() {
				if cd.deferredNetworks != nil && cd.deferredNetworks.Contains(event) {
					if cd.prevDeferredNetworks == nil {
						cd.prevDeferredNetworks = mapset.NewSet[NetworkEvent]()
					}
					cd.prevDeferredNetworks.Add(event)
					continue
				}
				cd.networks.Remove(event)
				if cd.prevDeferredNetworks != nil {
					cd.prevDeferredNetworks.Remove(event)
				}
				delete(cd.servicePorts, event)
				delete(cd.networkDeferredUntil, event)
				cd.releaseDeferredNetworkSize(event)
			}
		}
		cd.deferredNetworks = nil
		if cd.networks != nil && cd.networks.Cardinality() == 0 {
			cd.networks = nil
			cd.prevDeferredNetworks = nil
		}
		if len(cd.servicePorts) == 0 {
			cd.servicePorts = nil
		}
		if len(cd.networkDeferredUntil) == 0 {
			cd.networkDeferredUntil = nil
		}
	} else if cd.deferredNetworks != nil && cd.deferredNetworks.Cardinality() > 0 {
		cd.networks = cd.deferredNetworks.Clone()
		cd.prevDeferredNetworks = cd.deferredNetworks.Clone()
		cd.deferredNetworks = nil
		// Retained observations must keep the ports captured at ingestion.
		for event := range cd.servicePorts {
			if !cd.networks.Contains(event) {
				delete(cd.servicePorts, event)
			}
		}
		if len(cd.servicePorts) == 0 {
			cd.servicePorts = nil
		}
		for event := range cd.networkDeferredUntil {
			if !cd.networks.Contains(event) {
				delete(cd.networkDeferredUntil, event)
			}
		}
		if len(cd.networkDeferredUntil) == 0 {
			cd.networkDeferredUntil = nil
		}
		for event := range cd.networkDeferredSizes {
			if !cd.networks.Contains(event) {
				cd.releaseDeferredNetworkSize(event)
			}
		}
	} else {
		cd.networks = nil
		cd.prevDeferredNetworks = nil
		cd.deferredNetworks = nil
		cd.servicePorts = nil
		cd.networkDeferredUntil = nil
		cd.networkDeferredSizes = nil
		cd.networkDeferredSize = 0
	}
	cd.activeNetworks = nil
	if cd.watchedContainerData != nil {
		cd.lastReportedCompletion = string(cd.watchedContainerData.GetCompletionStatus())
		cd.lastReportedStatus = string(cd.watchedContainerData.GetStatus())
	}
}

// isEmpty returns true if the container data is empty
func (cd *containerData) isEmpty() bool {
	networks := cd.networkEventsForFlush(false)
	if cd.capabilites != nil ||
		cd.syscalls != nil ||
		cd.endpoints != nil ||
		cd.execs != nil ||
		cd.opens != nil ||
		cd.rulePolicies != nil ||
		cd.callStacks != nil ||
		(networks != nil && networks.Cardinality() > 0) {
		return false
	}

	return !cd.hasUnreportedStatusChange()
}

// hasUnreportedStatusChange reports whether a metadata-only update still needs saving.
func (cd *containerData) hasUnreportedStatusChange() bool {
	return cd.watchedContainerData != nil &&
		(cd.lastReportedCompletion != string(cd.watchedContainerData.GetCompletionStatus()) ||
			cd.lastReportedStatus != string(cd.watchedContainerData.GetStatus()))
}

// getCapabilities returns a sorted slice of capabilities
func (cd *containerData) getCapabilities() []string {
	var capabilities []string
	if cd.capabilites == nil {
		return capabilities
	}

	capabilities = cd.capabilites.ToSlice()
	sort.Strings(capabilities)
	return capabilities
}

// getExecs returns all execution calls recorded for this container
func (cd *containerData) getExecs() []v1beta1.ExecCalls {
	var execs []v1beta1.ExecCalls
	if cd.execs == nil {
		return execs
	}

	cd.execs.Range(func(_ string, value []string) bool {
		path := value[0]
		var args []string
		if len(value) > 1 {
			args = value[1:]
		}
		execs = append(execs, v1beta1.ExecCalls{
			Path: path,
			Args: args,
		})
		return true
	})

	return execs
}

// getOpens returns all file open calls recorded for this container
func (cd *containerData) getOpens() []v1beta1.OpenCalls {
	var opens []v1beta1.OpenCalls
	if cd.opens == nil {
		return opens
	}

	cd.opens.Range(func(path string, flags mapset.Set[string]) bool {
		flagsSlice := flags.ToSlice()
		opens = append(opens, v1beta1.OpenCalls{
			Path:  path,
			Flags: flagsSlice,
		})
		return true
	})

	return opens
}

func (cd *containerData) getSyscalls() []string {
	if cd.syscalls == nil {
		return []string{}
	}
	return cd.syscalls.ToSlice()
}

// getEndpoints returns all HTTP endpoints recorded for this container
func (cd *containerData) getEndpoints() []v1beta1.HTTPEndpoint {
	var endpoints []v1beta1.HTTPEndpoint
	if cd.endpoints == nil {
		return endpoints
	}

	cd.endpoints.Range(func(_ string, value *v1beta1.HTTPEndpoint) bool {
		endpoints = append(endpoints, *value)
		return true
	})

	return endpoints
}

// getRulePolicies returns all rule policies recorded for this container
func (cd *containerData) getRulePolicies() map[string]v1beta1.RulePolicy {
	rulePolicies := make(map[string]v1beta1.RulePolicy)
	if cd.rulePolicies == nil {
		return rulePolicies
	}

	cd.rulePolicies.Range(func(ruleID string, value *v1beta1.RulePolicy) bool {
		rulePolicies[ruleID] = *value
		return true
	})

	return rulePolicies
}

// getCallStacks returns all call stacks recorded for this container
func (cd *containerData) getCallStacks() []v1beta1.IdentifiedCallStack {
	var callStacks []v1beta1.IdentifiedCallStack
	if cd.callStacks == nil {
		return callStacks
	}

	cd.callStacks.Range(func(_ string, value *v1beta1.IdentifiedCallStack) bool {
		callStacks = append(callStacks, *value)
		return true
	})

	return callStacks
}

// isPrivateIP reports whether a valid address belongs to a private IPv4 or IPv6 range.
func isPrivateIP(ipStr string) bool {
	ip := net.ParseIP(ipStr)
	return ip != nil && ip.IsPrivate()
}

// resolveEndpoint resolves unknown peers from inventory, then the pod cache, excluding host-network pods.
func resolveEndpoint(
	event *NetworkEvent,
	k8sInventory common.K8sInventoryCache,
	k8sObjectCache objectcache.K8sObjectCache,
) {
	if event.Destination.Kind == EndpointKindPod || event.Destination.Kind == EndpointKindService {
		return
	}
	ip := event.Destination.IPAddress
	if ip == "" || ip == "127.0.0.1" {
		return
	}

	if k8sInventory != nil {
		if pod := k8sInventory.GetPodByIp(ip); pod != nil && !pod.Spec.HostNetwork {
			event.Destination.Kind = EndpointKindPod
			event.Destination.Name = pod.Name
			event.Destination.Namespace = pod.Namespace
			event.SetDestinationPodLabels(pod.Labels)
			return
		}
		if svc := k8sInventory.GetSvcByIp(ip); svc != nil {
			event.Destination.Kind = EndpointKindService
			event.Destination.Name = svc.Name
			event.Destination.Namespace = svc.Namespace
			event.SetDestinationPodLabels(svc.Labels)
			return
		}
	}

	if k8sObjectCache != nil {
		if pod := k8sObjectCache.GetPodByIP(ip); pod != nil && !pod.Spec.HostNetwork {
			event.Destination.Kind = EndpointKindPod
			event.Destination.Name = pod.Name
			event.Destination.Namespace = pod.Namespace
			event.SetDestinationPodLabels(pod.Labels)
			return
		}
	}
}

// networkEventsForFlush selects fresh observations for pressure saves and all retained
// observations for interval or final saves, without copying either set.
func (cd *containerData) networkEventsForFlush(forceSend bool) mapset.Set[NetworkEvent] {
	if cd.networkFlushForSize && !forceSend {
		return cd.activeNetworks
	}
	return cd.networks
}

// getIngressNetworkNeighbors returns ingress network neighbors for this container
func (cd *containerData) getIngressNetworkNeighbors(
	containerID string,
	namespace string,
	k8sClient k8sclient.K8sClientInterface,
	dnsResolverClient dnsmanager.DNSResolver,
	k8sInventory common.K8sInventoryCache,
	k8sObjectCache objectcache.K8sObjectCache,
	forceSend bool,
) []v1beta1.NetworkNeighbor {
	var ingress []v1beta1.NetworkNeighbor
	networks := cd.networkEventsForFlush(forceSend)
	if networks == nil {
		return ingress
	}

	seen := make(map[string]networkNeighborIndex)
	for _, event := range networks.ToSlice() {
		if event.PktType == utils.HostPktType {
			neighbor := cd.createNetworkNeighbor(containerID, event, namespace, k8sClient, dnsResolverClient, k8sInventory, k8sObjectCache, forceSend)
			if neighbor == nil {
				continue
			}
			ingress = appendNetworkNeighbor(ingress, seen, *neighbor)
		}
	}

	return ingress
}

// getEgressNetworkNeighbors returns egress network neighbors for this container
func (cd *containerData) getEgressNetworkNeighbors(
	containerID string,
	namespace string,
	k8sClient k8sclient.K8sClientInterface,
	dnsResolverClient dnsmanager.DNSResolver,
	k8sInventory common.K8sInventoryCache,
	k8sObjectCache objectcache.K8sObjectCache,
	forceSend bool,
) []v1beta1.NetworkNeighbor {
	var egress []v1beta1.NetworkNeighbor
	networks := cd.networkEventsForFlush(forceSend)
	if networks == nil {
		return egress
	}

	seen := make(map[string]networkNeighborIndex)
	for _, event := range networks.ToSlice() {
		if event.PktType != utils.HostPktType {
			neighbor := cd.createNetworkNeighbor(containerID, event, namespace, k8sClient, dnsResolverClient, k8sInventory, k8sObjectCache, forceSend)
			if neighbor == nil {
				continue
			}
			egress = appendNetworkNeighbor(egress, seen, *neighbor)
		}
	}

	return egress
}

type networkNeighborIndex struct {
	index int
	ports map[string]struct{}
}

// appendNetworkNeighbor merges all observed ports for neighbors with the same identity.
func appendNetworkNeighbor(neighbors []v1beta1.NetworkNeighbor, seen map[string]networkNeighborIndex, neighbor v1beta1.NetworkNeighbor) []v1beta1.NetworkNeighbor {
	if entry, ok := seen[neighbor.Identifier]; ok {
		for _, port := range neighbor.Ports {
			if _, exists := entry.ports[port.Name]; !exists {
				neighbors[entry.index].Ports = append(neighbors[entry.index].Ports, port)
				entry.ports[port.Name] = struct{}{}
			}
		}
		return neighbors
	}
	ports := make(map[string]struct{}, len(neighbor.Ports))
	for _, port := range neighbor.Ports {
		ports[port.Name] = struct{}{}
	}
	seen[neighbor.Identifier] = networkNeighborIndex{index: len(neighbors), ports: ports}
	return append(neighbors, neighbor)
}

// releaseDeferredNetworkSize removes one consumed observation from the independent
// backlog budget. Pressure cleanup calls this only for events in its active batch.
func (cd *containerData) releaseDeferredNetworkSize(event NetworkEvent) {
	if estimate, exists := cd.networkDeferredSizes[event]; exists {
		cd.networkDeferredSize -= estimate
		delete(cd.networkDeferredSizes, event)
		if len(cd.networkDeferredSizes) == 0 {
			cd.networkDeferredSizes = nil
		}
	}
}

// deferNetworkEvent retains an unresolved observation until its first deadline,
// provided the independent backlog budget has room. Overflow falls through to raw
// delivery. Nonpositive limits preserve the uncapped behavior of zero-config callers.
func (cd *containerData) deferNetworkEvent(event NetworkEvent) bool {
	now := time.Now()
	deadline, hasDeadline := cd.networkDeferredUntil[event]
	if cd.networkDeferralDuration > 0 {
		if hasDeadline && !now.Before(deadline) {
			return false
		}
	} else if cd.prevDeferredNetworks != nil && cd.prevDeferredNetworks.Contains(event) {
		return false
	}
	if _, accounted := cd.networkDeferredSizes[event]; !accounted && cd.networkDeferredSizeLimit > 0 {
		estimate := int64(size.Of(event) + networkNeighborIncrement(cd, event))
		if estimate > cd.networkDeferredSizeLimit-cd.networkDeferredSize {
			return false
		}
		if cd.networkDeferredSizes == nil {
			cd.networkDeferredSizes = make(map[NetworkEvent]int64)
		}
		cd.networkDeferredSizes[event] = estimate
		cd.networkDeferredSize += estimate
	}
	if cd.networkDeferralDuration > 0 && !hasDeadline {
		if cd.networkDeferredUntil == nil {
			cd.networkDeferredUntil = make(map[NetworkEvent]time.Time)
		}
		cd.networkDeferredUntil[event] = now.Add(cd.networkDeferralDuration)
	}
	if cd.deferredNetworks == nil {
		cd.deferredNetworks = mapset.NewSet[NetworkEvent]()
	}
	cd.deferredNetworks.Add(event)
	return true
}

// createNetworkNeighbor creates a network neighbor from a network event
func (cd *containerData) createNetworkNeighbor(
	containerID string,
	networkEvent NetworkEvent,
	namespace string,
	k8sClient k8sclient.K8sClientInterface,
	dnsResolverClient dnsmanager.DNSResolver,
	k8sInventory common.K8sInventoryCache,
	k8sObjectCache objectcache.K8sObjectCache,
	forceSend bool,
) *v1beta1.NetworkNeighbor {
	originalEvent := networkEvent
	resolveEndpoint(&networkEvent, k8sInventory, k8sObjectCache)

	var neighborEntry v1beta1.NetworkNeighbor

	enforcementPorts := []uint16{networkEvent.Port}
	var serviceWorkload k8sinterface.IWorkload

	if networkEvent.Destination.Kind == EndpointKindPod {
		// For Pods, we need to remove the default labels
		neighborEntry.PodSelector = &metav1.LabelSelector{
			MatchLabels: filterLabels(networkEvent.GetDestinationPodLabels()),
		}

		if namespaceLabels := getNamespaceMatchLabels(networkEvent.Destination.Namespace, namespace); namespaceLabels != nil {
			neighborEntry.NamespaceSelector = &metav1.LabelSelector{
				MatchLabels: namespaceLabels,
			}
		}

	} else if networkEvent.Destination.Kind == EndpointKindService {
		// For service, we need to retrieve it and use its selector
		var selector map[string]string
		if k8sClient != nil {
			svc, err := k8sClient.GetWorkload(networkEvent.Destination.Namespace, "Service", networkEvent.Destination.Name) // TODO: use IG inventory as this can generate a lot of API calls.
			if err != nil {
				logger.L().Warning("failed to get service",
					helpers.String("reason", err.Error()),
					helpers.String("service name", networkEvent.Destination.Name))
			} else if svc != nil {
				serviceWorkload = svc

				if svc.GetName() == "kubernetes" && svc.GetNamespace() == "default" {
					// The default service has no selectors, in addition, we want to save the default service address
					selector = svc.GetLabels()
					neighborEntry.IPAddress = networkEvent.Destination.IPAddress
				} else {
					selector = svc.GetServiceSelector()
				}
			}
		}

		if len(selector) == 0 {
			// Preserve observed IP traffic when promotion cannot provide a selector.
			if networkEvent.Destination.IPAddress == "" {
				return nil
			}
			networkEvent.Destination.Kind = EndpointKindRaw
		} else {
			neighborEntry.PodSelector = &metav1.LabelSelector{
				MatchLabels: selector,
			}
			if namespaceLabels := getNamespaceMatchLabels(networkEvent.Destination.Namespace, namespace); namespaceLabels != nil {
				neighborEntry.NamespaceSelector = &metav1.LabelSelector{
					MatchLabels: namespaceLabels,
				}
			}
		}

	}

	if networkEvent.Destination.Kind != EndpointKindPod && networkEvent.Destination.Kind != EndpointKindService {
		if networkEvent.Destination.IPAddress == "127.0.0.1" {
			// No need to generate for localhost
			return nil
		}

		// Let inventory catch up before persisting unresolved private traffic as raw IP.
		if isPrivateIP(networkEvent.Destination.IPAddress) && !forceSend && cd != nil && cd.deferNetworkEvent(originalEvent) {
			return nil
		}

		neighborEntry.IPAddress = networkEvent.Destination.IPAddress

		if dnsResolverClient != nil {
			domain, ok := dnsResolverClient.ResolveIPAddress(containerID, networkEvent.Destination.IPAddress)
			if ok {
				neighborEntry.DNS = domain
				neighborEntry.DNSNames = []string{domain}
			}
		}
	}

	hasPortSnapshot := false
	if cd != nil && networkEvent.Destination.Kind == EndpointKindService {
		if ports, ok := cd.servicePorts[networkEvent]; ok {
			hasPortSnapshot = true
			enforcementPorts = ports
		}
	}
	if !hasPortSnapshot {
		if networkEvent.Destination.Kind == EndpointKindService && serviceWorkload != nil && k8sClient != nil {
			enforcementPorts = resolveServiceEnforcementPorts(
				k8sClient,
				networkEvent.Destination.Namespace,
				networkEvent.Destination.Name,
				serviceWorkload,
				networkEvent.Port,
				networkEvent.Protocol,
			)
		}
	}
	neighborEntry.Ports = buildNetworkPorts(networkEvent.Protocol, enforcementPorts)

	neighborEntry.Type = InternalTrafficType
	if neighborEntry.NamespaceSelector == nil && neighborEntry.PodSelector == nil {
		neighborEntry.Type = ExternalTrafficType
	}

	identifier, err := generateNeighborsIdentifier(neighborEntry)
	if err != nil {
		identifier = createUUID()
	}
	neighborEntry.Identifier = identifier

	return &neighborEntry
}
