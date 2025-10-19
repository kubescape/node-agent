package containerprofilemanager

import (
	"fmt"
	"sort"

	mapset "github.com/deckarep/golang-set/v2"
	"github.com/kubescape/go-logger"
	"github.com/kubescape/go-logger/helpers"
	"github.com/kubescape/node-agent/pkg/dnsmanager"
	"github.com/kubescape/node-agent/pkg/k8sclient"
	"github.com/kubescape/node-agent/pkg/utils"
	"github.com/kubescape/storage/pkg/apis/softwarecomposition/v1beta1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/utils/ptr"
)

// emptyEvents clears all event data
func (cd *containerData) emptyEvents() {
	cd.size.Store(0)
	cd.capabilites = nil
	cd.syscalls = nil
	cd.endpoints = nil
	cd.execs = nil
	cd.opens = nil
	cd.rulePolicies = nil
	cd.callStacks = nil
	cd.networks = nil
	cd.lastReportedCompletion = string(cd.watchedContainerData.GetCompletionStatus())
	cd.lastReportedStatus = string(cd.watchedContainerData.GetStatus())
}

// isEmpty returns true if the container data is empty
func (cd *containerData) isEmpty() bool {
	return cd.capabilites == nil &&
		cd.endpoints == nil &&
		cd.execs == nil &&
		cd.opens == nil &&
		cd.rulePolicies == nil &&
		cd.callStacks == nil &&
		cd.networks == nil &&
		cd.lastReportedCompletion == string(cd.watchedContainerData.GetCompletionStatus()) &&
		cd.lastReportedStatus == string(cd.watchedContainerData.GetStatus())
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

// getIngressNetworkNeighbors returns ingress network neighbors for this container
func (cd *containerData) getIngressNetworkNeighbors(namespace string, k8sClient k8sclient.K8sClientInterface, dnsResolverClient dnsmanager.DNSResolver) []v1beta1.NetworkNeighbor {
	var ingress []v1beta1.NetworkNeighbor
	if cd.networks == nil {
		return ingress
	}

	for _, event := range cd.networks.ToSlice() {
		if event.PktType == utils.HostPktType {
			neighbor := cd.createNetworkNeighbor(event, namespace, k8sClient, dnsResolverClient)
			if neighbor == nil {
				continue
			}
			ingress = append(ingress, *neighbor)
		}
	}

	return ingress
}

// getEgressNetworkNeighbors returns egress network neighbors for this container
func (cd *containerData) getEgressNetworkNeighbors(namespace string, k8sClient k8sclient.K8sClientInterface, dnsResolverClient dnsmanager.DNSResolver) []v1beta1.NetworkNeighbor {
	var egress []v1beta1.NetworkNeighbor
	if cd.networks == nil {
		return egress
	}

	for _, event := range cd.networks.ToSlice() {
		if event.PktType != utils.HostPktType {
			neighbor := cd.createNetworkNeighbor(event, namespace, k8sClient, dnsResolverClient)
			if neighbor == nil {
				continue
			}
			egress = append(egress, *neighbor)
		}
	}

	return egress
}

// createNetworkNeighbor creates a network neighbor from a network event
func (cd *containerData) createNetworkNeighbor(networkEvent NetworkEvent, namespace string, k8sClient k8sclient.K8sClientInterface, dnsResolverClient dnsmanager.DNSResolver) *v1beta1.NetworkNeighbor {
	var neighborEntry v1beta1.NetworkNeighbor

	portIdentifier := generatePortIdentifierFromEvent(networkEvent)
	neighborEntry.Ports = []v1beta1.NetworkPort{{
		Protocol: v1beta1.Protocol(networkEvent.Protocol),
		Port:     ptr.To(int32(networkEvent.Port)),
		Name:     portIdentifier,
	}}

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
		svc, err := k8sClient.GetWorkload(networkEvent.Destination.Namespace, "Service", networkEvent.Destination.Name) // TODO: use IG inventory as this can generate a lot of API calls.
		if err != nil {
			logger.L().Warning("failed to get service",
				helpers.String("reason", err.Error()),
				helpers.String("service name", networkEvent.Destination.Name))
			return nil
		}

		var selector map[string]string
		if svc.GetName() == "kubernetes" && svc.GetNamespace() == "default" {
			// The default service has no selectors, in addition, we want to save the default service address
			selector = svc.GetLabels()
			neighborEntry.IPAddress = networkEvent.Destination.IPAddress
		} else {
			selector = svc.GetServiceSelector()
		}

		if len(selector) == 0 {
			// TODO: check if we need to handle services with no selectors
			return nil
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

	} else {
		if networkEvent.Destination.IPAddress == "127.0.0.1" {
			// No need to generate for localhost
			return nil
		}
		neighborEntry.IPAddress = networkEvent.Destination.IPAddress

		if dnsResolverClient != nil {
			domain, ok := dnsResolverClient.ResolveIPAddress(networkEvent.Destination.IPAddress)
			logger.L().Info("Matthias - dns resolved", helpers.String("ip", networkEvent.Destination.IPAddress), helpers.String("domain", domain))
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

	identifier, err := generateNeighborsIdentifier(neighborEntry)
	if err != nil {
		identifier = createUUID()
	}
	neighborEntry.Identifier = identifier

	logger.L().Info("Matthias - network neighbor created", helpers.String("neighbor", fmt.Sprintf("%+v", neighborEntry)))

	return &neighborEntry
}
