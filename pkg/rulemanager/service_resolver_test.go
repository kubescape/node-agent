package rulemanager

import (
	"errors"
	"sync"
	"testing"
	"time"

	igtypes "github.com/inspektor-gadget/inspektor-gadget/pkg/types"
	"github.com/kubescape/k8s-interface/k8sinterface"
	"github.com/kubescape/k8s-interface/workloadinterface"
	"github.com/kubescape/node-agent/pkg/k8sclient"
	"github.com/kubescape/node-agent/pkg/utils"
	"github.com/picatz/xcel"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

type mockServiceK8sClient struct {
	k8sclient.K8sClientMock
	mu       sync.Mutex
	services map[string]k8sinterface.IWorkload
	getCalls int
}

func (m *mockServiceK8sClient) GetWorkload(namespace, kind, name string) (k8sinterface.IWorkload, error) {
	if kind != "Service" {
		return m.K8sClientMock.GetWorkload(namespace, kind, name)
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	m.getCalls++
	key := namespace + "/" + name
	if svc, ok := m.services[key]; ok {
		return svc, nil
	}
	return nil, errors.New("service not found")
}

func (m *mockServiceK8sClient) CallCount() int {
	m.mu.Lock()
	defer m.mu.Unlock()
	return m.getCalls
}

func (m *mockServiceK8sClient) SetService(key string, svc k8sinterface.IWorkload) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.services[key] = svc
}

func (m *mockServiceK8sClient) DeleteService(key string) {
	m.mu.Lock()
	defer m.mu.Unlock()
	delete(m.services, key)
}

func TestInitServicePeerLabelResolver(t *testing.T) {
	defer utils.SetServicePeerLabels(nil)

	svcWorkload := workloadinterface.NewWorkloadObj(map[string]any{
		"apiVersion": "v1",
		"kind":       "Service",
		"metadata": map[string]any{
			"name":      "my-svc",
			"namespace": "prod",
			"labels": map[string]any{
				"helm.sh/chart": "my-chart-1.0.0",
			},
		},
		"spec": map[string]any{
			"selector": map[string]any{
				"app":  "backend",
				"tier": "api",
			},
		},
	})

	k8sDefaultSvc := workloadinterface.NewWorkloadObj(map[string]any{
		"apiVersion": "v1",
		"kind":       "Service",
		"metadata": map[string]any{
			"name":      "kubernetes",
			"namespace": "default",
			"labels": map[string]any{
				"component": "apiserver",
				"provider":  "kubernetes",
			},
		},
		"spec": map[string]any{},
	})

	mockClient := &mockServiceK8sClient{
		services: map[string]k8sinterface.IWorkload{
			"prod/my-svc":        svcWorkload,
			"default/kubernetes": k8sDefaultSvc,
		},
	}

	// 1. Initialize resolver with mock client
	InitServicePeerLabelResolver(mockClient)

	// Verify standard service returns selector labels, not metadata labels
	labels := utils.ServicePeerLabels("prod", "my-svc")
	assert.Equal(t, map[string]string{"app": "backend", "tier": "api"}, labels)

	// Verify default/kubernetes service returns metadata labels
	k8sLabels := utils.ServicePeerLabels("default", "kubernetes")
	assert.Equal(t, map[string]string{"component": "apiserver", "provider": "kubernetes"}, k8sLabels)

	// Verify non-existent service returns nil
	notFoundLabels := utils.ServicePeerLabels("prod", "unknown-svc")
	assert.Nil(t, notFoundLabels)

	// 2. Verify integration with CEL dstPodLabels getter
	dstLabelsField, ok := utils.CelFields["dstPodLabels"]
	require.True(t, ok)

	event := &mockNetworkEvent{
		endpoint: igtypes.L4Endpoint{
			L3Endpoint: igtypes.L3Endpoint{
				Namespace: "prod",
				Name:      "my-svc",
				Kind:      igtypes.EndpointKindService,
				PodLabels: map[string]string{"helm.sh/chart": "my-chart-1.0.0"}, // metadata label from kubeipresolver
			},
		},
	}
	wrapped, _ := xcel.NewObject[utils.CelEvent](event)

	val, err := dstLabelsField.GetFrom(wrapped)
	require.NoError(t, err)
	assert.Equal(t, map[string]string{"app": "backend", "tier": "api"}, val)

	// 3. Clear resolver on nil client
	InitServicePeerLabelResolver(nil)
	assert.Nil(t, utils.ServicePeerLabels("prod", "my-svc"))

	// Verify fallback to empty map when resolver is nil
	val, err = dstLabelsField.GetFrom(wrapped)
	require.NoError(t, err)
	assert.Equal(t, map[string]string{}, val)
}

func TestServicePeerLabelResolver_CachingAndRefresh(t *testing.T) {
	defer utils.SetServicePeerLabels(nil)

	svcWorkload := workloadinterface.NewWorkloadObj(map[string]any{
		"apiVersion": "v1",
		"kind":       "Service",
		"metadata": map[string]any{
			"name":      "cached-svc",
			"namespace": "test-ns",
		},
		"spec": map[string]any{
			"selector": map[string]any{
				"app": "cached-v1",
			},
		},
	})

	mockClient := &mockServiceK8sClient{
		services: map[string]k8sinterface.IWorkload{
			"test-ns/cached-svc": svcWorkload,
		},
	}

	// Initialize resolver with short TTL (50ms) for testing expiration and bounded size (2)
	ttl := 50 * time.Millisecond
	InitServicePeerLabelResolverWithCache(mockClient, 2, ttl)

	// 1. Initial lookup populates cache
	labels1 := utils.ServicePeerLabels("test-ns", "cached-svc")
	assert.Equal(t, map[string]string{"app": "cached-v1"}, labels1)
	assert.Equal(t, 1, mockClient.CallCount(), "First call should query GetWorkload")

	// 2. Subsequent lookups within TTL hit cache without calling GetWorkload
	for i := 0; i < 5; i++ {
		labelsCached := utils.ServicePeerLabels("test-ns", "cached-svc")
		assert.Equal(t, map[string]string{"app": "cached-v1"}, labelsCached)
	}
	assert.Equal(t, 1, mockClient.CallCount(), "Subsequent calls within TTL must hit cache")

	// 3. Negative caching for non-existent service
	notFound1 := utils.ServicePeerLabels("test-ns", "non-existent")
	assert.Nil(t, notFound1)
	assert.Equal(t, 2, mockClient.CallCount())

	notFound2 := utils.ServicePeerLabels("test-ns", "non-existent")
	assert.Nil(t, notFound2)
	assert.Equal(t, 2, mockClient.CallCount(), "Negative result should be cached within TTL")

	// 4. Update service selector and wait for TTL expiry
	updatedSvc := workloadinterface.NewWorkloadObj(map[string]any{
		"apiVersion": "v1",
		"kind":       "Service",
		"metadata": map[string]any{
			"name":      "cached-svc",
			"namespace": "test-ns",
		},
		"spec": map[string]any{
			"selector": map[string]any{
				"app": "cached-v2",
			},
		},
	})
	mockClient.SetService("test-ns/cached-svc", updatedSvc)

	time.Sleep(ttl + 20*time.Millisecond)

	// Lookup after TTL expiry refreshes from API
	labelsUpdated := utils.ServicePeerLabels("test-ns", "cached-svc")
	assert.Equal(t, map[string]string{"app": "cached-v2"}, labelsUpdated)
	assert.Equal(t, 3, mockClient.CallCount(), "Call after TTL expiry must refresh from GetWorkload")

	// 5. Delete service and wait for TTL expiry
	mockClient.DeleteService("test-ns/cached-svc")
	time.Sleep(ttl + 20*time.Millisecond)

	labelsDeleted := utils.ServicePeerLabels("test-ns", "cached-svc")
	assert.Nil(t, labelsDeleted)
	assert.Equal(t, 4, mockClient.CallCount(), "Call after deletion and TTL expiry must reflect deletion")

	// 6. LRU eviction with bounded capacity
	mockClient.SetService("test-ns/svc-a", svcWorkload)
	mockClient.SetService("test-ns/svc-b", svcWorkload)
	mockClient.SetService("test-ns/svc-c", svcWorkload)

	callsBefore := mockClient.CallCount()
	utils.ServicePeerLabels("test-ns", "svc-a") // in cache: [svc-a]
	utils.ServicePeerLabels("test-ns", "svc-b") // in cache: [svc-b, svc-a]
	utils.ServicePeerLabels("test-ns", "svc-c") // capacity 2 -> evicts svc-a; in cache: [svc-c, svc-b]
	assert.Equal(t, callsBefore+3, mockClient.CallCount())

	// svc-b should still be cached
	utils.ServicePeerLabels("test-ns", "svc-b")
	assert.Equal(t, callsBefore+3, mockClient.CallCount(), "svc-b should still be cached")

	// svc-a was evicted, so accessing it calls GetWorkload again
	utils.ServicePeerLabels("test-ns", "svc-a")
	assert.Equal(t, callsBefore+4, mockClient.CallCount(), "svc-a was evicted and should re-query")
}

type mockNetworkEvent struct {
	utils.CelEventImpl
	endpoint igtypes.L4Endpoint
}

func (m *mockNetworkEvent) GetDstEndpoint() igtypes.L4Endpoint {
	return m.endpoint
}
