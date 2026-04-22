package objectcache

import (
	"context"

	corev1 "k8s.io/api/core/v1"

	"github.com/goradd/maps"
	containercollection "github.com/inspektor-gadget/inspektor-gadget/pkg/container-collection"
	"github.com/kubescape/node-agent/pkg/objectcache"
	"github.com/kubescape/node-agent/pkg/objectcache/applicationprofilecache/callstackcache"
	"github.com/kubescape/node-agent/pkg/watcher"
	"github.com/kubescape/storage/pkg/apis/softwarecomposition/v1beta1"
	"k8s.io/apimachinery/pkg/runtime"
)

// RuleObjectCacheMock implementation as provided
type RuleObjectCacheMock struct {
	profile                 *v1beta1.ApplicationProfile
	podSpec                 *corev1.PodSpec
	podStatus               *corev1.PodStatus
	nn                      *v1beta1.NetworkNeighborhood
	cp                      *v1beta1.ContainerProfile
	dnsCache                map[string]string
	ContainerIDToSharedData *maps.SafeMap[string, *objectcache.WatchedContainerData]
}

func (r *RuleObjectCacheMock) GetApplicationProfile(string) *v1beta1.ApplicationProfile {
	return r.profile
}

func (r *RuleObjectCacheMock) GetCallStackSearchTree(string) *callstackcache.CallStackSearchTree {
	return nil
}

func (r *RuleObjectCacheMock) SetApplicationProfile(profile *v1beta1.ApplicationProfile) {
	r.profile = profile
	// Also project AP fields into the unified ContainerProfile so tests that
	// exercise GetContainerProfile (via profilehelper) observe the same data.
	// Takes the first available container across Containers/InitContainers/
	// EphemeralContainers.
	if profile == nil {
		return
	}
	var c *v1beta1.ApplicationProfileContainer
	switch {
	case len(profile.Spec.Containers) > 0:
		c = &profile.Spec.Containers[0]
	case len(profile.Spec.InitContainers) > 0:
		c = &profile.Spec.InitContainers[0]
	case len(profile.Spec.EphemeralContainers) > 0:
		c = &profile.Spec.EphemeralContainers[0]
	}
	if c == nil {
		return
	}
	if r.cp == nil {
		r.cp = &v1beta1.ContainerProfile{}
	}
	r.cp.Spec.Architectures = profile.Spec.Architectures
	r.cp.Spec.Capabilities = c.Capabilities
	r.cp.Spec.Execs = c.Execs
	r.cp.Spec.Opens = c.Opens
	r.cp.Spec.Syscalls = c.Syscalls
	r.cp.Spec.SeccompProfile = c.SeccompProfile
	r.cp.Spec.Endpoints = c.Endpoints
	r.cp.Spec.ImageID = c.ImageID
	r.cp.Spec.ImageTag = c.ImageTag
	r.cp.Spec.PolicyByRuleId = c.PolicyByRuleId
	r.cp.Spec.IdentifiedCallStacks = c.IdentifiedCallStacks
}

func (r *RuleObjectCacheMock) ApplicationProfileCache() objectcache.ApplicationProfileCache {
	return r
}

func (r *RuleObjectCacheMock) GetContainerProfile(containerID string) *v1beta1.ContainerProfile {
	// Mirror the legacy helper behaviour: if the test did not register shared
	// data for this container ID, there is no profile to return. This keeps
	// "invalid container ID" tests working after the shim migration.
	if r.ContainerIDToSharedData != nil && containerID != "" {
		if _, ok := r.ContainerIDToSharedData.Load(containerID); !ok {
			return nil
		}
	}
	return r.cp
}

func (r *RuleObjectCacheMock) SetContainerProfile(cp *v1beta1.ContainerProfile) {
	r.cp = cp
}

func (r *RuleObjectCacheMock) GetContainerProfileState(_ string) *objectcache.ProfileState {
	return nil
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

func (r *RuleObjectCacheMock) NetworkNeighborhoodCache() objectcache.NetworkNeighborhoodCache {
	return r
}

func (r *RuleObjectCacheMock) GetNetworkNeighborhood(string) *v1beta1.NetworkNeighborhood {
	return r.nn
}

func (r *RuleObjectCacheMock) SetNetworkNeighborhood(nn *v1beta1.NetworkNeighborhood) {
	r.nn = nn
	// Also project NN fields into the unified ContainerProfile so tests that
	// exercise GetContainerProfile (via profilehelper) observe the same data.
	// Takes the first available container across Containers/InitContainers/
	// EphemeralContainers.
	if nn == nil {
		return
	}
	var c *v1beta1.NetworkNeighborhoodContainer
	switch {
	case len(nn.Spec.Containers) > 0:
		c = &nn.Spec.Containers[0]
	case len(nn.Spec.InitContainers) > 0:
		c = &nn.Spec.InitContainers[0]
	case len(nn.Spec.EphemeralContainers) > 0:
		c = &nn.Spec.EphemeralContainers[0]
	}
	if c == nil {
		return
	}
	if r.cp == nil {
		r.cp = &v1beta1.ContainerProfile{}
	}
	r.cp.Spec.LabelSelector = nn.Spec.LabelSelector
	r.cp.Spec.Ingress = c.Ingress
	r.cp.Spec.Egress = c.Egress
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
