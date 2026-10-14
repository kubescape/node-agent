package containerprofilecache

import (
	"context"
	"testing"
	"time"

	iidhelpers "github.com/kubescape/k8s-interface/instanceidhandler/v1/helpers"
	"github.com/kubescape/node-agent/pkg/config"
	"github.com/kubescape/node-agent/pkg/objectcache"
	"github.com/kubescape/storage/pkg/apis/softwarecomposition/v1beta1"
	"github.com/stretchr/testify/require"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/types"
)

type podGenerationCache struct {
	objectcache.K8sObjectCacheMock
	pod *corev1.Pod
}

func (c *podGenerationCache) GetPod(string, string) *corev1.Pod { return c.pod }

func TestProfilePopulationSharedPodGeneration(t *testing.T) {
	for _, tc := range []struct {
		name, cachedUID      string
		cachedPod, wantEntry bool
	}{
		{"same generation", "fetched-api-uid", true, true},
		{"replacement informer Pod", "replacement-api-uid", true, false},
		{"missing informer UID", "", true, false},
		{"informer lag", "", false, true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			k8s := &podGenerationCache{}
			if tc.cachedPod {
				k8s.pod = &corev1.Pod{ObjectMeta: metav1.ObjectMeta{UID: types.UID(tc.cachedUID)}}
			}
			client := &fakeProfileClient{cp: &v1beta1.ContainerProfile{Name: "profile", Namespace: "default", Annotations: map[string]string{
				iidhelpers.CompletionMetadataKey: iidhelpers.Full,
				iidhelpers.StatusMetadataKey:     iidhelpers.Completed,
			}}}
			cache := NewContainerProfileCache(config.Config{ProfilesCacheRefreshRate: time.Second}, client, k8s, nil)
			primeSharedData(t, &k8s.K8sObjectCacheMock, "container", "wlid://cluster-test/namespace-default/deployment-original")
			k8s.GetSharedContainerData("container").PodUID = "fetched-api-uid"
			container := eventContainer("container")
			container.K8s.PodUID = "static-runtime-uid"
			require.NoError(t, cache.addContainer(container, context.Background()))
			entry, exists := cache.entries.Load("container")
			require.Equal(t, tc.wantEntry, exists)
			if tc.wantEntry {
				require.Equal(t, "fetched-api-uid", entry.PodUID, "retain API provenance even without an informer Pod")
			} else {
				require.True(t, cache.pending.Has("container"), "mismatched cache generation must remain pending")
			}
		})
	}
}
