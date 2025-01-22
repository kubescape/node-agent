package ruleengine

import (
	corev1 "k8s.io/api/core/v1"

	"github.com/goradd/maps"
	"github.com/kubescape/node-agent/pkg/objectcache"
	"github.com/kubescape/node-agent/pkg/utils"

	"github.com/kubescape/storage/pkg/apis/softwarecomposition/v1beta1"
)

var _ objectcache.ApplicationProfileCache = (*RuleObjectCacheMock)(nil)
var _ objectcache.K8sObjectCache = (*RuleObjectCacheMock)(nil)
var _ objectcache.NetworkNeighborhoodCache = (*RuleObjectCacheMock)(nil)
var _ objectcache.DnsCache = (*RuleObjectCacheMock)(nil)

type RuleObjectCacheMock struct {
	profile                 *v1beta1.ApplicationProfile
	podSpec                 *corev1.PodSpec
	podStatus               *corev1.PodStatus
	nn                      *v1beta1.NetworkNeighborhood
	dnsCache                map[string]string
	containerIDToSharedData maps.SafeMap[string, *utils.WatchedContainerData]
}

func (r *RuleObjectCacheMock) GetApplicationProfile(string) *v1beta1.ApplicationProfile {
	return r.profile
}

func (r *RuleObjectCacheMock) SetApplicationProfile(profile *v1beta1.ApplicationProfile) {
	r.profile = profile
}

func (r *RuleObjectCacheMock) ApplicationProfileCache() objectcache.ApplicationProfileCache {
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

func (k *RuleObjectCacheMock) SetSharedContainerData(containerID string, data *utils.WatchedContainerData) {
	k.containerIDToSharedData.Set(containerID, data)
}
func (k *RuleObjectCacheMock) GetSharedContainerData(containerID string) *utils.WatchedContainerData {
	if data, ok := k.containerIDToSharedData.Load(containerID); ok {
		return data
	}

	return nil
}
func (k *RuleObjectCacheMock) DeleteSharedContainerData(containerID string) {
	k.containerIDToSharedData.Delete(containerID)
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
}

func (r *RuleObjectCacheMock) DnsCache() objectcache.DnsCache {
	return r
}

func (r *RuleObjectCacheMock) SetDnsCache(dnsCache map[string]string) {
	r.dnsCache = dnsCache
}

func (r *RuleObjectCacheMock) ResolveIpToDomain(ip string) string {
	if _, ok := r.dnsCache[ip]; ok {
		return r.dnsCache[ip]
	}

	return ""
}
