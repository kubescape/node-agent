package containerprofilemanager

import (
	"sort"

	mapset "github.com/deckarep/golang-set/v2"
	"github.com/google/uuid"
	"github.com/goradd/maps"
	"github.com/kubescape/go-logger"
	"github.com/kubescape/go-logger/helpers"
	"github.com/kubescape/node-agent/pkg/dnsmanager"
	"github.com/kubescape/node-agent/pkg/k8sclient"
	"github.com/kubescape/node-agent/pkg/utils"
	"github.com/kubescape/storage/pkg/apis/softwarecomposition/v1beta1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/utils/ptr"
)

type containerData struct {
	// watchedContainerData contains the data for a watched container
	watchedContainerData *utils.WatchedContainerData // TODO: move watched container data to here

	// Events reported for this container that needs to be saved to the profile
	capabilites  mapset.Set[string]
	syscalls     mapset.Set[string]
	endpoints    *maps.SafeMap[string, *v1beta1.HTTPEndpoint]
	execs        *maps.SafeMap[string, []string]                     // Map of execs reported for this container, key is the SHA256 hash of the exec
	opens        *maps.SafeMap[string, mapset.Set[string]]           // Map of opens reported for this container, key is the file path
	rulePolicies *maps.SafeMap[string, *v1beta1.RulePolicy]          // Map of rule policies reported for this container, key is the rule ID
	callStacks   *maps.SafeMap[string, *v1beta1.IdentifiedCallStack] // Map of callstacks reported for this container, key is the SHA256 hash of the callstack
	networks     mapset.Set[NetworkEvent]

	// TODO: cache events we reported already, so we don't report them again, currently the cache is only done between updates but we might want to keep the events for a longer period of time.
}

func (cd *containerData) isEmpty() bool {
	return cd.capabilites == nil &&
		// cd.syscalls == nil && // This is intentionally not set to nil, as we want to keep the syscalls reported for the container because of the peek function.
		cd.execs == nil &&
		cd.opens == nil &&
		cd.endpoints == nil &&
		cd.rulePolicies == nil &&
		cd.callStacks == nil &&
		cd.networks == nil
}

func (cd *containerData) emptyEvents() {
	cd.capabilites = nil
	// cd.syscalls = nil // This is intentionally not set to nil, as we want to keep the syscalls reported for the container because of the peek function.
	cd.endpoints = nil
	cd.execs = nil
	cd.opens = nil
	cd.rulePolicies = nil
	cd.callStacks = nil
	cd.networks = nil
}

func (cd *containerData) getCapabilities() []string {
	var capabilities []string
	if cd.capabilites == nil {
		return capabilities
	}

	capabilities = cd.capabilites.ToSlice()
	sort.Strings(capabilities)
	return capabilities
}

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

func (cd *containerData) getOpens() []v1beta1.OpenCalls {
	var opens []v1beta1.OpenCalls
	if cd.opens == nil {
		return opens
	}

	cd.opens.Range(func(path string, flags mapset.Set[string]) bool {
		flagsSlice := flags.ToSlice()
		sort.Strings(flagsSlice)
		opens = append(opens, v1beta1.OpenCalls{
			Path:  path,
			Flags: flagsSlice,
		})
		return true
	})

	return opens
}

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

func (cd *containerData) getRulePolicies() map[string]v1beta1.RulePolicy { // TODO: check here if we need to check if the policy is not empty or something like that.
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

func (cd *containerData) getIngressNetworkNeighbors(namespace string, k8sClient k8sclient.K8sClientInterface, dnsResolverClient dnsmanager.DNSResolver) []v1beta1.NetworkNeighbor {
	var ingress []v1beta1.NetworkNeighbor
	if cd.networks == nil {
		return ingress
	}

	for _, event := range cd.networks.ToSlice() {
		if event.PktType == HostPktType {
			neighbor := cd.createNetworkNeighbor(event, namespace, k8sClient, dnsResolverClient)
			if neighbor == nil {
				logger.L().Debug("NetworkManager - skipping network neighbor creation for event", helpers.String("event", event.String()))
				continue
			}
			ingress = append(ingress, *neighbor)
		}
	}

	return ingress
}

func (cd *containerData) getEgressNetworkNeighbors(namespace string, k8sClient k8sclient.K8sClientInterface, dnsResolverClient dnsmanager.DNSResolver) []v1beta1.NetworkNeighbor {
	var egress []v1beta1.NetworkNeighbor
	if cd.networks == nil {
		return egress
	}

	for _, event := range cd.networks.ToSlice() {
		if event.PktType != HostPktType {
			neighbor := cd.createNetworkNeighbor(event, namespace, k8sClient, dnsResolverClient)
			if neighbor == nil {
				logger.L().Debug("NetworkManager - skipping network neighbor creation for event", helpers.String("event", event.String()))
				continue
			}
			egress = append(egress, *neighbor)
		}
	}

	return egress
}

func (cd *containerData) createNetworkNeighbor(networkEvent NetworkEvent, namespace string, k8sClient k8sclient.K8sClientInterface, dnsResolverClient dnsmanager.DNSResolver) *v1beta1.NetworkNeighbor {
	var neighborEntry v1beta1.NetworkNeighbor

	portIdentifier := generatePortIdentifierFromEvent(networkEvent)
	neighborEntry.Ports = []v1beta1.NetworkPort{{
		Protocol: v1beta1.Protocol(networkEvent.Protocol),
		Port:     ptr.To(int32(networkEvent.Port)),
		Name:     portIdentifier,
	}}

	if networkEvent.Destination.Kind == EndpointKindPod {
		// for Pods, we need to remove the default labels
		neighborEntry.PodSelector = &metav1.LabelSelector{
			MatchLabels: filterLabels(networkEvent.GetDestinationPodLabels()),
		}

		if namespaceLabels := utils.GetNamespaceMatchLabels(networkEvent.Destination.Namespace, namespace); namespaceLabels != nil {
			neighborEntry.NamespaceSelector = &metav1.LabelSelector{
				MatchLabels: namespaceLabels,
			}
		}

	} else if networkEvent.Destination.Kind == EndpointKindService {
		// for service, we need to retrieve it and use its selector
		svc, err := k8sClient.GetWorkload(networkEvent.Destination.Namespace, "Service", networkEvent.Destination.Name) // TODO: replace this with ig k8sInventory.
		if err != nil {
			logger.L().Warning("NetworkManager - failed to get service", helpers.String("reason", err.Error()), helpers.String("service name", networkEvent.Destination.Name))
			return nil
		}

		var selector map[string]string
		if svc.GetName() == "kubernetes" && svc.GetNamespace() == "default" {
			// the default service has no selectors, in addition, we want to save the default service address
			selector = svc.GetLabels()
			neighborEntry.IPAddress = networkEvent.Destination.IPAddress
		} else {
			selector = svc.GetServiceSelector()
		}
		if len(selector) == 0 {
			// FIXME check if we need to handle services with no selectors
			return nil
		} else {
			neighborEntry.PodSelector = &metav1.LabelSelector{
				MatchLabels: selector,
			}
			if namespaceLabels := utils.GetNamespaceMatchLabels(networkEvent.Destination.Namespace, namespace); namespaceLabels != nil {
				neighborEntry.NamespaceSelector = &metav1.LabelSelector{
					MatchLabels: namespaceLabels,
				}
			}
		}

	} else {
		if networkEvent.Destination.IPAddress == "127.0.0.1" {
			// No need to generate for localhost
			return nil
		}
		neighborEntry.IPAddress = networkEvent.Destination.IPAddress

		if dnsResolverClient != nil {
			domain, ok := dnsResolverClient.ResolveIPAddress(networkEvent.Destination.IPAddress)
			if ok {
				neighborEntry.DNS = domain
				neighborEntry.DNSNames = []string{domain}
			}
		}
	}

	neighborEntry.Type = InternalTrafficType
	if neighborEntry.NamespaceSelector == nil && neighborEntry.PodSelector == nil {
		neighborEntry.Type = ExternalTrafficType
	}

	identifier, err := utils.GenerateNeighborsIdentifier(neighborEntry)
	if err != nil {
		identifier = uuid.New().String()
	}
	neighborEntry.Identifier = identifier

	return &neighborEntry
}
