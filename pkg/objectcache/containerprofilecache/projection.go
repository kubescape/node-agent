package containerprofilecache

import (
	"github.com/kubescape/node-agent/pkg/utils"
	"github.com/kubescape/storage/pkg/apis/softwarecomposition/v1beta1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

// projectUserManagedCP overlays a user-authored ContainerProfile (the migrated
// "ug-<workloadName>" user-managed overlay) onto a base ContainerProfile and
// returns a DeepCopy of the base with the user fields unioned in.
//
// The migrated overlay is a single ContainerProfile whose spec is already flat
// for one container, so the merge is a direct field union with no per-container
// lookup. userCP may be nil (no overlay); cp MUST be non-nil.
func projectUserManagedCP(cp *v1beta1.ContainerProfile, userCP *v1beta1.ContainerProfile) *v1beta1.ContainerProfile {
	projected := cp.DeepCopy()
	if userCP == nil {
		return projected
	}
	// Defensive copy: appended slices (Execs[i].Args, Opens[i].Flags, …) and the
	// LabelSelector would otherwise alias the caller's cached CRD object.
	u := userCP.DeepCopy()

	projected.Spec.Capabilities = append(projected.Spec.Capabilities, u.Spec.Capabilities...)
	projected.Spec.Execs = append(projected.Spec.Execs, u.Spec.Execs...)
	projected.Spec.Opens = append(projected.Spec.Opens, u.Spec.Opens...)
	projected.Spec.Syscalls = append(projected.Spec.Syscalls, u.Spec.Syscalls...)
	projected.Spec.Endpoints = append(projected.Spec.Endpoints, u.Spec.Endpoints...)
	projected.Spec.Ingress = mergeNetworkNeighbors(projected.Spec.Ingress, u.Spec.Ingress)
	projected.Spec.Egress = mergeNetworkNeighbors(projected.Spec.Egress, u.Spec.Egress)

	if len(u.Spec.PolicyByRuleId) > 0 {
		if projected.Spec.PolicyByRuleId == nil {
			projected.Spec.PolicyByRuleId = make(map[string]v1beta1.RulePolicy, len(u.Spec.PolicyByRuleId))
		}
		for k, v := range u.Spec.PolicyByRuleId {
			if existing, ok := projected.Spec.PolicyByRuleId[k]; ok {
				projected.Spec.PolicyByRuleId[k] = utils.MergePolicies(existing, v)
			} else {
				projected.Spec.PolicyByRuleId[k] = v
			}
		}
	}

	// Merge the embedded LabelSelector (ContainerProfileSpec embeds it).
	if u.Spec.LabelSelector.MatchLabels != nil {
		if projected.Spec.LabelSelector.MatchLabels == nil {
			projected.Spec.LabelSelector.MatchLabels = make(map[string]string)
		}
		for k, v := range u.Spec.LabelSelector.MatchLabels {
			projected.Spec.LabelSelector.MatchLabels[k] = v
		}
	}
	projected.Spec.LabelSelector.MatchExpressions = append(
		projected.Spec.LabelSelector.MatchExpressions,
		u.Spec.LabelSelector.MatchExpressions...,
	)

	return projected
}

// mergeNetworkNeighbors merges user neighbors into a normal-neighbor list,
// keyed by Identifier. ported from
// pkg/objectcache/networkneighborhoodcache/networkneighborhoodcache.go:617-636.
func mergeNetworkNeighbors(normalNeighbors, userNeighbors []v1beta1.NetworkNeighbor) []v1beta1.NetworkNeighbor {
	neighborMap := make(map[string]int, len(normalNeighbors))
	for i, neighbor := range normalNeighbors {
		neighborMap[neighbor.Identifier] = i
	}
	for _, userNeighbor := range userNeighbors {
		if idx, exists := neighborMap[userNeighbor.Identifier]; exists {
			normalNeighbors[idx] = mergeNetworkNeighbor(normalNeighbors[idx], userNeighbor)
		} else {
			normalNeighbors = append(normalNeighbors, userNeighbor)
		}
	}
	return normalNeighbors
}

// mergeNetworkNeighbor merges a user-managed neighbor into an existing one.
// ported from
// pkg/objectcache/networkneighborhoodcache/networkneighborhoodcache.go:638-706.
func mergeNetworkNeighbor(normal, user v1beta1.NetworkNeighbor) v1beta1.NetworkNeighbor {
	merged := normal.DeepCopy()

	dnsNamesSet := make(map[string]struct{})
	for _, dns := range normal.DNSNames {
		dnsNamesSet[dns] = struct{}{}
	}
	for _, dns := range user.DNSNames {
		dnsNamesSet[dns] = struct{}{}
	}
	merged.DNSNames = make([]string, 0, len(dnsNamesSet))
	for dns := range dnsNamesSet {
		merged.DNSNames = append(merged.DNSNames, dns)
	}

	merged.Ports = mergeNetworkPorts(merged.Ports, user.Ports)

	if user.PodSelector != nil {
		if merged.PodSelector == nil {
			merged.PodSelector = &metav1.LabelSelector{}
		}
		if user.PodSelector.MatchLabels != nil {
			if merged.PodSelector.MatchLabels == nil {
				merged.PodSelector.MatchLabels = make(map[string]string)
			}
			for k, v := range user.PodSelector.MatchLabels {
				merged.PodSelector.MatchLabels[k] = v
			}
		}
		merged.PodSelector.MatchExpressions = append(
			merged.PodSelector.MatchExpressions,
			user.PodSelector.MatchExpressions...,
		)
	}

	if user.NamespaceSelector != nil {
		if merged.NamespaceSelector == nil {
			merged.NamespaceSelector = &metav1.LabelSelector{}
		}
		if user.NamespaceSelector.MatchLabels != nil {
			if merged.NamespaceSelector.MatchLabels == nil {
				merged.NamespaceSelector.MatchLabels = make(map[string]string)
			}
			for k, v := range user.NamespaceSelector.MatchLabels {
				merged.NamespaceSelector.MatchLabels[k] = v
			}
		}
		merged.NamespaceSelector.MatchExpressions = append(
			merged.NamespaceSelector.MatchExpressions,
			user.NamespaceSelector.MatchExpressions...,
		)
	}

	if user.IPAddress != "" {
		merged.IPAddress = user.IPAddress
	}
	if len(user.IPAddresses) > 0 {
		ipSet := make(map[string]struct{})
		for _, ip := range merged.IPAddresses {
			ipSet[ip] = struct{}{}
		}
		for _, ip := range user.IPAddresses {
			ipSet[ip] = struct{}{}
		}
		merged.IPAddresses = make([]string, 0, len(ipSet))
		for ip := range ipSet {
			merged.IPAddresses = append(merged.IPAddresses, ip)
		}
	}
	if user.Type != "" {
		merged.Type = user.Type
	}

	return *merged
}

// mergeNetworkPorts merges user ports into a normal-ports list, keyed by Name.
// ported from
// pkg/objectcache/networkneighborhoodcache/networkneighborhoodcache.go:708-727.
func mergeNetworkPorts(normalPorts, userPorts []v1beta1.NetworkPort) []v1beta1.NetworkPort {
	portMap := make(map[string]int, len(normalPorts))
	for i, port := range normalPorts {
		portMap[port.Name] = i
	}
	for _, userPort := range userPorts {
		if idx, exists := portMap[userPort.Name]; exists {
			normalPorts[idx] = userPort
		} else {
			normalPorts = append(normalPorts, userPort)
		}
	}
	return normalPorts
}
