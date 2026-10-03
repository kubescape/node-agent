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
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	"k8s.io/apimachinery/pkg/runtime/schema"
)

type mockServiceK8sClient struct {
	k8sclient.K8sClientMock
	mu       sync.Mutex
	services map[string]k8sinterface.IWorkload
	errs     map[string]error
	getCalls int
	delay    time.Duration
}

func (m *mockServiceK8sClient) GetWorkload(namespace, kind, name string) (k8sinterface.IWorkload, error) {
	if kind != "Service" {
		return m.K8sClientMock.GetWorkload(namespace, kind, name)
	}
	m.mu.Lock()
	m.getCalls++
	delay := m.delay
	key := namespace + "/" + name
	if customErr, hasErr := m.errs[key]; hasErr {
		m.mu.Unlock()
		if delay > 0 {
			time.Sleep(delay)
		}
		return nil, customErr
	}
	svc, ok := m.services[key]
	m.mu.Unlock()

	if delay > 0 {
		time.Sleep(delay)
	}

	if ok {
		return svc, nil
	}
	return nil, apierrors.NewNotFound(schema.GroupResource{Resource: "services"}, name)
}

func (m *mockServiceK8sClient) CallCount() int {
	m.mu.Lock()
	defer m.mu.Unlock()
	return m.getCalls
}

func (m *mockServiceK8sClient) SetService(key string, svc k8sinterface.IWorkload) {
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.services == nil {
		m.services = make(map[string]k8sinterface.IWorkload)
	}
	delete(m.errs, key)
	m.services[key] = svc
}

func (m *mockServiceK8sClient) SetError(key string, err error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.errs == nil {
		m.errs = make(map[string]error)
	}
	m.errs[key] = err
}

func (m *mockServiceK8sClient) DeleteService(key string) {
	m.mu.Lock()
	defer m.mu.Unlock()
	delete(m.services, key)
	delete(m.errs, key)
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

	// 3. Negative caching for confirmed NotFound
	notFound1 := utils.ServicePeerLabels("test-ns", "non-existent")
	assert.Nil(t, notFound1)
	assert.Equal(t, 2, mockClient.CallCount())

	notFound2 := utils.ServicePeerLabels("test-ns", "non-existent")
	assert.Nil(t, notFound2)
	assert.Equal(t, 2, mockClient.CallCount(), "NotFound should be negatively cached within TTL")

	// 4. Update service selector and wait for TTL expiry using assert.Eventually
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

	assert.Eventually(t, func() bool {
		labels := utils.ServicePeerLabels("test-ns", "cached-svc")
		return labels != nil && labels["app"] == "cached-v2"
	}, 1*time.Second, 10*time.Millisecond, "Service selector should refresh after TTL expires")

	// 5. Delete service and wait for TTL expiry
	mockClient.DeleteService("test-ns/cached-svc")

	assert.Eventually(t, func() bool {
		return utils.ServicePeerLabels("test-ns", "cached-svc") == nil
	}, 1*time.Second, 10*time.Millisecond, "Deleted service should resolve to nil after TTL expires")

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

func TestServicePeerLabelResolver_ConcurrentMisses(t *testing.T) {
	defer utils.SetServicePeerLabels(nil)

	svcWorkload := workloadinterface.NewWorkloadObj(map[string]any{
		"apiVersion": "v1",
		"kind":       "Service",
		"metadata": map[string]any{
			"name":      "concurrent-svc",
			"namespace": "concur-ns",
		},
		"spec": map[string]any{
			"selector": map[string]any{
				"app": "concurrent",
			},
		},
	})

	mockClient := &mockServiceK8sClient{
		services: map[string]k8sinterface.IWorkload{
			"concur-ns/concurrent-svc": svcWorkload,
		},
		delay: 20 * time.Millisecond, // simulate API latency to ensure concurrence
	}

	InitServicePeerLabelResolverWithCache(mockClient, 100, 1*time.Minute)

	const workers = 10
	var wg sync.WaitGroup
	wg.Add(workers)

	results := make([]map[string]string, workers)
	for i := 0; i < workers; i++ {
		go func(idx int) {
			defer wg.Done()
			results[idx] = utils.ServicePeerLabels("concur-ns", "concurrent-svc")
		}(i)
	}

	wg.Wait()

	for i := 0; i < workers; i++ {
		assert.Equal(t, map[string]string{"app": "concurrent"}, results[i])
	}
	assert.Equal(t, 1, mockClient.CallCount(), "Singleflight must coalesce concurrent requests into exactly 1 API call")
}

func TestServicePeerLabelResolver_TransientFailureThenSuccess(t *testing.T) {
	defer utils.SetServicePeerLabels(nil)

	svcWorkload := workloadinterface.NewWorkloadObj(map[string]any{
		"apiVersion": "v1",
		"kind":       "Service",
		"metadata": map[string]any{
			"name":      "flaky-svc",
			"namespace": "flaky-ns",
		},
		"spec": map[string]any{
			"selector": map[string]any{
				"app": "recovered",
			},
		},
	})

	mockClient := &mockServiceK8sClient{}
	// Transient error: timeout / network failure (NOT NotFound)
	mockClient.SetError("flaky-ns/flaky-svc", errors.New("i/o timeout: transient api server failure"))

	InitServicePeerLabelResolverWithCache(mockClient, 100, 1*time.Minute)

	// 1. Transient failure should return nil
	res1 := utils.ServicePeerLabels("flaky-ns", "flaky-svc")
	assert.Nil(t, res1)
	assert.Equal(t, 1, mockClient.CallCount())

	// 2. Immediately recover: set the valid workload (simulating transient issue resolved)
	mockClient.SetService("flaky-ns/flaky-svc", svcWorkload)

	// 3. The very next call must NOT be blocked by a negative cache; it must re-fetch and succeed
	res2 := utils.ServicePeerLabels("flaky-ns", "flaky-svc")
	assert.Equal(t, map[string]string{"app": "recovered"}, res2)
	assert.Equal(t, 2, mockClient.CallCount(), "Transient failure must not be negatively cached")
}

type mockNetworkEvent struct {
	utils.CelEventImpl
	endpoint igtypes.L4Endpoint
}

func (m *mockNetworkEvent) GetDstEndpoint() igtypes.L4Endpoint {
	return m.endpoint
}
