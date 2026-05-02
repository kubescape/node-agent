package containerprofilecache

import (
	"github.com/kubescape/node-agent/pkg/utils"
	"github.com/kubescape/storage/pkg/apis/softwarecomposition/v1beta1"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

// partialProfileWarning describes a user-authored legacy CRD that couldn't be
// fully merged into the ContainerProfile (e.g. the user CRD is missing entries
// for containers that exist in the pod spec). Emitted by the cache at merge
// time for deprecation observability.
type partialProfileWarning struct {
	Kind              string // "application" | "network"
	Namespace         string
	Name              string
	ResourceVersion   string
	MissingContainers []string
}

// projectUserProfiles overlays a user-authored ApplicationProfile and/or
// NetworkNeighborhood onto a base ContainerProfile for a single container.
// Returns a DeepCopy of the base with user fields merged in and a list of
// partial-merge warnings when the user CRD doesn't cover every container in
// the pod spec.
//
// cp MUST be non-nil. Either (or both) of userAP / userNN may be nil; nil
// user inputs contribute no merge but also no warning. pod may be nil, in
// which case the missing-container check is skipped (but the name-based
// per-container merge still runs).
func projectUserProfiles(
	cp *v1beta1.ContainerProfile,
	userAP *v1beta1.ApplicationProfile,
	userNN *v1beta1.NetworkNeighborhood,
	pod *corev1.Pod,
	containerName string,
) (projected *v1beta1.ContainerProfile, warnings []partialProfileWarning) {
	projected = cp.DeepCopy()

	if userAP != nil {
		if missing := mergeApplicationProfile(projected, userAP, pod, containerName); len(missing) > 0 {
			warnings = append(warnings, partialProfileWarning{
				Kind:              kindApplication,
				Namespace:         userAP.Namespace,
				Name:              userAP.Name,
				ResourceVersion:   userAP.ResourceVersion,
				MissingContainers: missing,
			})
		}
	}

	if userNN != nil {
		if missing := mergeNetworkNeighborhood(projected, userNN, pod, containerName); len(missing) > 0 {
			warnings = append(warnings, partialProfileWarning{
				Kind:              kindNetwork,
				Namespace:         userNN.Namespace,
				Name:              userNN.Name,
				ResourceVersion:   userNN.ResourceVersion,
				MissingContainers: missing,
			})
		}
	}

	return projected, warnings
}

// mergeApplicationProfile finds the container entry in userAP matching
// containerName (across Spec.Containers / InitContainers / EphemeralContainers)
// and merges its fields into projected.Spec. Returns the list of pod-spec
// container names that are not present anywhere in userAP.Spec.
//
// ported from pkg/objectcache/applicationprofilecache/applicationprofilecache.go:660-673
// (mergeContainer), applied here to a single-container ContainerProfile
// instead of a full ApplicationProfile.
func mergeApplicationProfile(projected *v1beta1.ContainerProfile, userAP *v1beta1.ApplicationProfile, pod *corev1.Pod, containerName string) []string {
	// Defensive copy: slices inside matched (e.g. Execs[i].Args, Opens[i].Flags,
	// Endpoints[i].Methods) would otherwise alias the caller's CRD object and
	// could change if the CRD is refreshed concurrently.
	userAP = userAP.DeepCopy()
	if matched := findUserAPContainer(userAP, containerName); matched != nil {
		projected.Spec.Capabilities = append(projected.Spec.Capabilities, matched.Capabilities...)
		projected.Spec.Execs = append(projected.Spec.Execs, matched.Execs...)
		projected.Spec.Opens = append(projected.Spec.Opens, matched.Opens...)
		projected.Spec.Syscalls = append(projected.Spec.Syscalls, matched.Syscalls...)
		projected.Spec.Endpoints = append(projected.Spec.Endpoints, matched.Endpoints...)
		if projected.Spec.PolicyByRuleId == nil && len(matched.PolicyByRuleId) > 0 {
			projected.Spec.PolicyByRuleId = make(map[string]v1beta1.RulePolicy, len(matched.PolicyByRuleId))
		}
		for k, v := range matched.PolicyByRuleId {
			if existing, ok := projected.Spec.PolicyByRuleId[k]; ok {
				projected.Spec.PolicyByRuleId[k] = utils.MergePolicies(existing, v)
			} else {
				projected.Spec.PolicyByRuleId[k] = v
			}
		}
	}

	return missingPodContainers(pod, userAPNames(userAP))
}

// mergeNetworkNeighborhood finds the container entry in userNN matching
// containerName and merges its Ingress/Egress into projected.Spec, then
// overlays the user CRD's pod LabelSelector onto projected's embedded
// LabelSelector. Returns missing-from-userNN pod container names.
//
// ported from pkg/objectcache/networkneighborhoodcache/networkneighborhoodcache.go:560-636
// (performMerge, mergeContainer, mergeNetworkNeighbors) applied to a single
// container's rules on a ContainerProfile.
func mergeNetworkNeighborhood(projected *v1beta1.ContainerProfile, userNN *v1beta1.NetworkNeighborhood, pod *corev1.Pod, containerName string) []string {
	// Defensive copy: neighbor slices (DNSNames, Ports, MatchExpressions) and
	// LabelSelector.MatchExpressions would otherwise alias the caller's CRD.
	userNN = userNN.DeepCopy()
	if matched := findUserNNContainer(userNN, containerName); matched != nil {
		projected.Spec.Ingress = mergeNetworkNeighbors(projected.Spec.Ingress, matched.Ingress)
		projected.Spec.Egress = mergeNetworkNeighbors(projected.Spec.Egress, matched.Egress)
	}

	// Merge LabelSelector (ContainerProfileSpec embeds metav1.LabelSelector).
	if userNN.Spec.LabelSelector.MatchLabels != nil {
		if projected.Spec.LabelSelector.MatchLabels == nil {
			projected.Spec.LabelSelector.MatchLabels = make(map[string]string)
		}
		for k, v := range userNN.Spec.LabelSelector.MatchLabels {
			projected.Spec.LabelSelector.MatchLabels[k] = v
		}
	}
	projected.Spec.LabelSelector.MatchExpressions = append(
		projected.Spec.LabelSelector.MatchExpressions,
		userNN.Spec.LabelSelector.MatchExpressions...,
	)

	return missingPodContainers(pod, userNNNames(userNN))
}

func findUserAPContainer(userAP *v1beta1.ApplicationProfile, containerName string) *v1beta1.ApplicationProfileContainer {
	if userAP == nil {
		return nil
	}
	for i := range userAP.Spec.Containers {
		if userAP.Spec.Containers[i].Name == containerName {
			return &userAP.Spec.Containers[i]
		}
	}
	for i := range userAP.Spec.InitContainers {
		if userAP.Spec.InitContainers[i].Name == containerName {
			return &userAP.Spec.InitContainers[i]
		}
	}
	for i := range userAP.Spec.EphemeralContainers {
		if userAP.Spec.EphemeralContainers[i].Name == containerName {
			return &userAP.Spec.EphemeralContainers[i]
		}
	}
	return nil
}

func findUserNNContainer(userNN *v1beta1.NetworkNeighborhood, containerName string) *v1beta1.NetworkNeighborhoodContainer {
	if userNN == nil {
		return nil
	}
	for i := range userNN.Spec.Containers {
		if userNN.Spec.Containers[i].Name == containerName {
			return &userNN.Spec.Containers[i]
		}
	}
	for i := range userNN.Spec.InitContainers {
		if userNN.Spec.InitContainers[i].Name == containerName {
			return &userNN.Spec.InitContainers[i]
		}
	}
	for i := range userNN.Spec.EphemeralContainers {
		if userNN.Spec.EphemeralContainers[i].Name == containerName {
			return &userNN.Spec.EphemeralContainers[i]
		}
	}
	return nil
}

func userAPNames(userAP *v1beta1.ApplicationProfile) map[string]struct{} {
	names := map[string]struct{}{}
	if userAP == nil {
		return names
	}
	for _, c := range userAP.Spec.Containers {
		names[c.Name] = struct{}{}
	}
	for _, c := range userAP.Spec.InitContainers {
		names[c.Name] = struct{}{}
	}
	for _, c := range userAP.Spec.EphemeralContainers {
		names[c.Name] = struct{}{}
	}
	return names
}

func userNNNames(userNN *v1beta1.NetworkNeighborhood) map[string]struct{} {
	names := map[string]struct{}{}
	if userNN == nil {
		return names
	}
	for _, c := range userNN.Spec.Containers {
		names[c.Name] = struct{}{}
	}
	for _, c := range userNN.Spec.InitContainers {
		names[c.Name] = struct{}{}
	}
	for _, c := range userNN.Spec.EphemeralContainers {
		names[c.Name] = struct{}{}
	}
	return names
}

// missingPodContainers returns the set of pod-spec container names that are
// not present in the given set. If pod is nil, returns nil (check skipped).
func missingPodContainers(pod *corev1.Pod, have map[string]struct{}) []string {
	if pod == nil {
		return nil
	}
	var missing []string
	for _, c := range pod.Spec.Containers {
		if _, ok := have[c.Name]; !ok {
			missing = append(missing, c.Name)
		}
	}
	for _, c := range pod.Spec.InitContainers {
		if _, ok := have[c.Name]; !ok {
			missing = append(missing, c.Name)
		}
	}
	for _, c := range pod.Spec.EphemeralContainers {
		if _, ok := have[c.Name]; !ok {
			missing = append(missing, c.Name)
		}
	}
	return missing
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
