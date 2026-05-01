package objectcache

import (
	"context"
	"errors"
	"sync"

	corev1 "k8s.io/api/core/v1"

	"github.com/goradd/maps"
	containercollection "github.com/inspektor-gadget/inspektor-gadget/pkg/container-collection"
	"github.com/kubescape/node-agent/pkg/objectcache"
	"github.com/kubescape/node-agent/pkg/objectcache/callstackcache"
	"github.com/kubescape/node-agent/pkg/watcher"
	"github.com/kubescape/storage/pkg/apis/softwarecomposition/v1beta1"
	"k8s.io/apimachinery/pkg/runtime"
)

// RuleObjectCacheMock is a test double for RuleObjectCache.
//
// Setter partition contract — SetApplicationProfile and SetNetworkNeighborhood
// both write into cpByContainerName entries but own non-overlapping fields:
//
//	SetApplicationProfile  → Architectures, Capabilities, Execs, Opens, Syscalls,
//	                          SeccompProfile, Endpoints, ImageID, ImageTag,
//	                          PolicyByRuleId, IdentifiedCallStacks
//	SetNetworkNeighborhood → LabelSelector, Ingress, Egress
//
// Calling both setters produces a fully-populated ContainerProfile with no
// field conflict. Both setters apply a first-container-wins rule for r.cp
// (backward-compat pointer for single-container tests); the per-container map
// cpByContainerName is authoritative for multi-container tests.
type RuleObjectCacheMock struct {
	profile                 *v1beta1.ApplicationProfile
	podSpec                 *corev1.PodSpec
	podStatus               *corev1.PodStatus
	nn                      *v1beta1.NetworkNeighborhood
	cp                      *v1beta1.ContainerProfile
	cpByContainerName       map[string]*v1beta1.ContainerProfile
	dnsCache                map[string]string
	ContainerIDToSharedData *maps.SafeMap[string, *objectcache.WatchedContainerData]

	projectionSpecMu sync.RWMutex
	projectionSpec   objectcache.RuleProjectionSpec
}

func (r *RuleObjectCacheMock) GetApplicationProfile(string) *v1beta1.ApplicationProfile {
	return r.profile
}

func (r *RuleObjectCacheMock) GetCallStackSearchTree(string) *callstackcache.CallStackSearchTree {
	return nil
}

func (r *RuleObjectCacheMock) SetApplicationProfile(profile *v1beta1.ApplicationProfile) {
	r.profile = profile
	if profile == nil {
		return
	}
	if r.cpByContainerName == nil {
		r.cpByContainerName = make(map[string]*v1beta1.ContainerProfile)
	}
	apply := func(c *v1beta1.ApplicationProfileContainer) {
		cp, ok := r.cpByContainerName[c.Name]
		if !ok {
			cp = &v1beta1.ContainerProfile{}
			r.cpByContainerName[c.Name] = cp
		}
		cp.Spec.Architectures = profile.Spec.Architectures
		cp.Spec.Capabilities = c.Capabilities
		cp.Spec.Execs = c.Execs
		cp.Spec.Opens = c.Opens
		cp.Spec.Syscalls = c.Syscalls
		cp.Spec.SeccompProfile = c.SeccompProfile
		cp.Spec.Endpoints = c.Endpoints
		cp.Spec.ImageID = c.ImageID
		cp.Spec.ImageTag = c.ImageTag
		cp.Spec.PolicyByRuleId = c.PolicyByRuleId
		cp.Spec.IdentifiedCallStacks = c.IdentifiedCallStacks
	}
	for i := range profile.Spec.Containers {
		apply(&profile.Spec.Containers[i])
	}
	for i := range profile.Spec.InitContainers {
		apply(&profile.Spec.InitContainers[i])
	}
	for i := range profile.Spec.EphemeralContainers {
		apply(&profile.Spec.EphemeralContainers[i])
	}
	// r.cp = first container's entry (backward compat for single-container tests).
	switch {
	case len(profile.Spec.Containers) > 0:
		r.cp = r.cpByContainerName[profile.Spec.Containers[0].Name]
	case len(profile.Spec.InitContainers) > 0:
		r.cp = r.cpByContainerName[profile.Spec.InitContainers[0].Name]
	case len(profile.Spec.EphemeralContainers) > 0:
		r.cp = r.cpByContainerName[profile.Spec.EphemeralContainers[0].Name]
	}
}

func (r *RuleObjectCacheMock) GetContainerProfile(containerID string) *v1beta1.ContainerProfile {
	if r.ContainerIDToSharedData != nil && containerID != "" {
		data, ok := r.ContainerIDToSharedData.Load(containerID)
		if !ok {
			return nil
		}
		// Resolve the per-container profile via the registered InstanceID so
		// multi-container tests get the correct container's profile.
		if data != nil && data.InstanceID != nil {
			if cp, found := r.cpByContainerName[data.InstanceID.GetContainerName()]; found {
				return cp
			}
		}
	}
	return r.cp
}

func (r *RuleObjectCacheMock) GetProjectedContainerProfile(containerID string) *objectcache.ProjectedContainerProfile {
	cp := r.GetContainerProfile(containerID)
	if cp == nil {
		return nil
	}
	r.projectionSpecMu.RLock()
	spec := r.projectionSpec
	r.projectionSpecMu.RUnlock()
	// When no spec has been installed (Hash==""), expose all raw data so
	// single-surface unit tests that never call SetProjectionSpec still work.
	// When a spec is installed, only populate surfaces that are InUse, matching
	// production behaviour where unrequested fields are dropped by Apply().
	specInstalled := spec.Hash != ""

	pcp := &objectcache.ProjectedContainerProfile{
		PolicyByRuleId: cp.Spec.PolicyByRuleId,
		SpecHash:       spec.Hash,
	}

	if (!specInstalled || spec.Capabilities.InUse) && len(cp.Spec.Capabilities) > 0 {
		pcp.Capabilities.All = true
		pcp.Capabilities.Values = make(map[string]struct{}, len(cp.Spec.Capabilities))
		for _, c := range cp.Spec.Capabilities {
			pcp.Capabilities.Values[c] = struct{}{}
		}
	}

	if (!specInstalled || spec.Syscalls.InUse) && len(cp.Spec.Syscalls) > 0 {
		pcp.Syscalls.All = true
		pcp.Syscalls.Values = make(map[string]struct{}, len(cp.Spec.Syscalls))
		for _, s := range cp.Spec.Syscalls {
			pcp.Syscalls.Values[s] = struct{}{}
		}
	}

	if (!specInstalled || spec.Execs.InUse) && len(cp.Spec.Execs) > 0 {
		pcp.Execs.All = true
		pcp.Execs.Values = make(map[string]struct{}, len(cp.Spec.Execs))
		for _, e := range cp.Spec.Execs {
			pcp.Execs.Values[e.Path] = struct{}{}
		}
	}

	if (!specInstalled || spec.Opens.InUse) && len(cp.Spec.Opens) > 0 {
		pcp.Opens.All = true
		pcp.Opens.Values = make(map[string]struct{}, len(cp.Spec.Opens))
		for _, o := range cp.Spec.Opens {
			pcp.Opens.Values[o.Path] = struct{}{}
		}
	}

	if (!specInstalled || spec.Endpoints.InUse) && len(cp.Spec.Endpoints) > 0 {
		pcp.Endpoints.All = true
		pcp.Endpoints.Values = make(map[string]struct{}, len(cp.Spec.Endpoints))
		for _, e := range cp.Spec.Endpoints {
			pcp.Endpoints.Values[e.Endpoint] = struct{}{}
		}
	}

	// Egress addresses and domains — All=true: all observed entries are retained.
	if !specInstalled || spec.EgressAddresses.InUse || spec.EgressDomains.InUse {
		for _, n := range cp.Spec.Egress {
			if (!specInstalled || spec.EgressAddresses.InUse) && n.IPAddress != "" {
				if pcp.EgressAddresses.Values == nil {
					pcp.EgressAddresses.All = true
					pcp.EgressAddresses.Values = make(map[string]struct{})
				}
				pcp.EgressAddresses.Values[n.IPAddress] = struct{}{}
			}
			if !specInstalled || spec.EgressDomains.InUse {
				domains := n.DNSNames
				if n.DNS != "" {
					domains = append([]string{n.DNS}, domains...)
				}
				for _, d := range domains {
					if pcp.EgressDomains.Values == nil {
						pcp.EgressDomains.All = true
						pcp.EgressDomains.Values = make(map[string]struct{})
					}
					pcp.EgressDomains.Values[d] = struct{}{}
				}
			}
		}
	}

	// Ingress addresses and domains — All=true: all observed entries are retained.
	if !specInstalled || spec.IngressAddresses.InUse || spec.IngressDomains.InUse {
		for _, n := range cp.Spec.Ingress {
			if (!specInstalled || spec.IngressAddresses.InUse) && n.IPAddress != "" {
				if pcp.IngressAddresses.Values == nil {
					pcp.IngressAddresses.All = true
					pcp.IngressAddresses.Values = make(map[string]struct{})
				}
				pcp.IngressAddresses.Values[n.IPAddress] = struct{}{}
			}
			if !specInstalled || spec.IngressDomains.InUse {
				if n.DNS != "" {
					if pcp.IngressDomains.Values == nil {
						pcp.IngressDomains.All = true
						pcp.IngressDomains.Values = make(map[string]struct{})
					}
					pcp.IngressDomains.Values[n.DNS] = struct{}{}
				}
				for _, d := range n.DNSNames {
					if pcp.IngressDomains.Values == nil {
						pcp.IngressDomains.All = true
						pcp.IngressDomains.Values = make(map[string]struct{})
					}
					pcp.IngressDomains.Values[d] = struct{}{}
				}
			}
		}
	}

	return pcp
}

func (r *RuleObjectCacheMock) SetProjectionSpec(spec objectcache.RuleProjectionSpec) {
	r.projectionSpecMu.Lock()
	r.projectionSpec = spec
	r.projectionSpecMu.Unlock()
}

func (r *RuleObjectCacheMock) SetContainerProfile(cp *v1beta1.ContainerProfile) {
	r.cp = cp
}

func (r *RuleObjectCacheMock) GetContainerProfileState(_ string) *objectcache.ProfileState {
	return &objectcache.ProfileState{Error: errors.New("mock: profile not found")}
}

func (r *RuleObjectCacheMock) Start(_ context.Context) {}

func (r *RuleObjectCacheMock) ContainerProfileCache() objectcache.ContainerProfileCache {
	return r
}

func (r *RuleObjectCacheMock) GetPodSpec(_, _ string) *corev1.PodSpec {
	return r.podSpec
}

func (r *RuleObjectCacheMock) GetPodStatus(_, _ string) *corev1.PodStatus {
	return r.podStatus
}

func (r *RuleObjectCacheMock) SetPodSpec(podSpec *corev1.PodSpec) {
	r.podSpec = podSpec
}

func (r *RuleObjectCacheMock) GetPod(_, _ string) *corev1.Pod {
	return &corev1.Pod{Spec: *r.podSpec, Status: *r.podStatus}
}

func (r *RuleObjectCacheMock) SetPodStatus(podStatus *corev1.PodStatus) {
	r.podStatus = podStatus
}

func (r *RuleObjectCacheMock) GetApiServerIpAddress() string {
	return ""
}

func (r *RuleObjectCacheMock) GetPods() []*corev1.Pod {
	return []*corev1.Pod{{Spec: *r.podSpec, Status: *r.podStatus}}
}

func (r *RuleObjectCacheMock) SetSharedContainerData(containerID string, data *objectcache.WatchedContainerData) {
	r.ContainerIDToSharedData.Set(containerID, data)
}

func (r *RuleObjectCacheMock) GetSharedContainerData(containerID string) *objectcache.WatchedContainerData {
	if data, ok := r.ContainerIDToSharedData.Load(containerID); ok {
		return data
	}
	return nil
}

func (r *RuleObjectCacheMock) DeleteSharedContainerData(containerID string) {
	r.ContainerIDToSharedData.Delete(containerID)
}

func (r *RuleObjectCacheMock) K8sObjectCache() objectcache.K8sObjectCache {
	return r
}

func (r *RuleObjectCacheMock) GetNetworkNeighborhood(string) *v1beta1.NetworkNeighborhood {
	return r.nn
}

func (r *RuleObjectCacheMock) SetNetworkNeighborhood(nn *v1beta1.NetworkNeighborhood) {
	r.nn = nn
	if nn == nil {
		return
	}
	if r.cpByContainerName == nil {
		r.cpByContainerName = make(map[string]*v1beta1.ContainerProfile)
	}
	apply := func(c *v1beta1.NetworkNeighborhoodContainer) {
		cp, ok := r.cpByContainerName[c.Name]
		if !ok {
			cp = &v1beta1.ContainerProfile{}
			r.cpByContainerName[c.Name] = cp
		}
		cp.Spec.LabelSelector = nn.Spec.LabelSelector
		cp.Spec.Ingress = c.Ingress
		cp.Spec.Egress = c.Egress
	}
	for i := range nn.Spec.Containers {
		apply(&nn.Spec.Containers[i])
	}
	for i := range nn.Spec.InitContainers {
		apply(&nn.Spec.InitContainers[i])
	}
	for i := range nn.Spec.EphemeralContainers {
		apply(&nn.Spec.EphemeralContainers[i])
	}
	// r.cp = first container's entry (backward compat for single-container tests).
	switch {
	case len(nn.Spec.Containers) > 0:
		r.cp = r.cpByContainerName[nn.Spec.Containers[0].Name]
	case len(nn.Spec.InitContainers) > 0:
		r.cp = r.cpByContainerName[nn.Spec.InitContainers[0].Name]
	case len(nn.Spec.EphemeralContainers) > 0:
		r.cp = r.cpByContainerName[nn.Spec.EphemeralContainers[0].Name]
	}
}

func (r *RuleObjectCacheMock) DnsCache() objectcache.DnsCache {
	return r
}

func (r *RuleObjectCacheMock) SetDnsCache(dnsCache map[string]string) {
	r.dnsCache = dnsCache
}

func (r *RuleObjectCacheMock) ResolveIpToDomain(ip string) string {
	if domain, ok := r.dnsCache[ip]; ok {
		return domain
	}
	return ""
}

func (r *RuleObjectCacheMock) WatchResources() []watcher.WatchResource {
	return nil
}

func (r *RuleObjectCacheMock) AddHandler(_ context.Context, _ runtime.Object) {
	return
}

func (r *RuleObjectCacheMock) ModifyHandler(_ context.Context, _ runtime.Object) {
	return
}

func (r *RuleObjectCacheMock) DeleteHandler(_ context.Context, _ runtime.Object) {
	return
}

func (r *RuleObjectCacheMock) ContainerCallback(_ containercollection.PubSubEvent) {
	return
}

func (r *RuleObjectCacheMock) GetApplicationProfileState(_ string) *objectcache.ProfileState {
	return nil
}

func (r *RuleObjectCacheMock) GetNetworkNeighborhoodState(_ string) *objectcache.ProfileState {
	return nil
}
