// Package containerprofilecache_integration provides integration/acceptance tests
// for the ContainerProfile cache unification (plan v2 §2.7 + §2.8 step 9).
package containerprofilecache_integration

import (
	"context"
	"sync"

	containercollection "github.com/inspektor-gadget/inspektor-gadget/pkg/container-collection"
	eventtypes "github.com/inspektor-gadget/inspektor-gadget/pkg/types"
	"github.com/kubescape/node-agent/pkg/objectcache"
	"github.com/kubescape/node-agent/pkg/storage"
	"github.com/kubescape/storage/pkg/apis/softwarecomposition/v1beta1"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/types"
)

// makeTestContainer builds a minimal *containercollection.Container for use
// in ContainerCallback events.
func makeTestContainer(id, podName, namespace, containerName string) *containercollection.Container {
	return &containercollection.Container{
		Runtime: containercollection.RuntimeMetadata{
			BasicRuntimeMetadata: eventtypes.BasicRuntimeMetadata{
				ContainerID:   id,
				ContainerName: containerName,
				ContainerPID:  42,
			},
		},
		K8s: containercollection.K8sMetadata{
			BasicK8sMetadata: eventtypes.BasicK8sMetadata{
				Namespace: namespace,
				PodName:   podName,
			},
		},
	}
}

// makeTestPod builds a *corev1.Pod with the provided container statuses.
func makeTestPod(name, namespace, uid string, containerStatuses []corev1.ContainerStatus, initStatuses []corev1.ContainerStatus) *corev1.Pod {
	return &corev1.Pod{
		ObjectMeta: metav1.ObjectMeta{
			Name:      name,
			Namespace: namespace,
			UID:       types.UID(uid),
		},
		Status: corev1.PodStatus{
			ContainerStatuses:     containerStatuses,
			InitContainerStatuses: initStatuses,
		},
	}
}

// stubStorage is a minimal storage.ProfileClient stub with settable responses.
type stubStorage struct {
	mu sync.RWMutex
	cp *v1beta1.ContainerProfile
	ap *v1beta1.ApplicationProfile
	nn *v1beta1.NetworkNeighborhood
}

var _ storage.ProfileClient = (*stubStorage)(nil)

func newFakeStorage(cp *v1beta1.ContainerProfile) *stubStorage {
	return &stubStorage{cp: cp}
}

func (s *stubStorage) GetContainerProfile(_ context.Context, _, _ string) (*v1beta1.ContainerProfile, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.cp, nil
}

func (s *stubStorage) GetApplicationProfile(_ context.Context, _, _ string) (*v1beta1.ApplicationProfile, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.ap, nil
}

func (s *stubStorage) GetNetworkNeighborhood(_ context.Context, _, _ string) (*v1beta1.NetworkNeighborhood, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.nn, nil
}

func (s *stubStorage) ListApplicationProfiles(_ context.Context, _ string, _ int64, _ string) (*v1beta1.ApplicationProfileList, error) {
	return &v1beta1.ApplicationProfileList{}, nil
}

func (s *stubStorage) ListNetworkNeighborhoods(_ context.Context, _ string, _ int64, _ string) (*v1beta1.NetworkNeighborhoodList, error) {
	return &v1beta1.NetworkNeighborhoodList{}, nil
}

// stubK8sCache is a controllable K8sObjectCache stub.
type stubK8sCache struct {
	mu   sync.RWMutex
	pods map[string]*corev1.Pod
	data map[string]*objectcache.WatchedContainerData
}

var _ objectcache.K8sObjectCache = (*stubK8sCache)(nil)

func newFakeK8sCache() *stubK8sCache {
	return &stubK8sCache{
		pods: make(map[string]*corev1.Pod),
		data: make(map[string]*objectcache.WatchedContainerData),
	}
}

func (k *stubK8sCache) setPod(namespace, podName string, pod *corev1.Pod) {
	k.mu.Lock()
	defer k.mu.Unlock()
	k.pods[namespace+"/"+podName] = pod
}

func (k *stubK8sCache) GetPod(namespace, podName string) *corev1.Pod {
	k.mu.RLock()
	defer k.mu.RUnlock()
	return k.pods[namespace+"/"+podName]
}

func (k *stubK8sCache) GetPodSpec(_, _ string) *corev1.PodSpec     { return nil }
func (k *stubK8sCache) GetPodStatus(_, _ string) *corev1.PodStatus { return nil }
func (k *stubK8sCache) GetApiServerIpAddress() string              { return "" }
func (k *stubK8sCache) GetPods() []*corev1.Pod                     { return nil }

func (k *stubK8sCache) SetSharedContainerData(id string, d *objectcache.WatchedContainerData) {
	k.mu.Lock()
	defer k.mu.Unlock()
	k.data[id] = d
}

func (k *stubK8sCache) GetSharedContainerData(id string) *objectcache.WatchedContainerData {
	k.mu.RLock()
	defer k.mu.RUnlock()
	return k.data[id]
}

func (k *stubK8sCache) DeleteSharedContainerData(id string) {
	k.mu.Lock()
	defer k.mu.Unlock()
	delete(k.data, id)
}
