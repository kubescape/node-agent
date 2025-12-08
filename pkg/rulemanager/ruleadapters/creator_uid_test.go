package ruleadapters

import (
	"testing"

	"github.com/kubescape/node-agent/pkg/objectcache"
	"github.com/stretchr/testify/assert"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/types"
	"k8s.io/utils/pointer"
)

// Mock implementations for testing
type mockObjectCache struct {
	k8sCache objectcache.K8sObjectCache
}

func (m *mockObjectCache) K8sObjectCache() objectcache.K8sObjectCache {
	return m.k8sCache
}

func (m *mockObjectCache) ApplicationProfileCache() objectcache.ApplicationProfileCache {
	return nil
}

func (m *mockObjectCache) NetworkNeighborhoodCache() objectcache.NetworkNeighborhoodCache {
	return nil
}

func (m *mockObjectCache) DnsCache() objectcache.DnsCache {
	return nil
}

type mockK8sObjectCache struct {
	pods       map[string]*corev1.Pod
	sharedData map[string]*objectcache.WatchedContainerData
}

func (m *mockK8sObjectCache) GetPod(namespace, podName string) *corev1.Pod {
	key := namespace + "/" + podName
	return m.pods[key]
}

func (m *mockK8sObjectCache) GetPodSpec(namespace, podName string) *corev1.PodSpec {
	if pod := m.GetPod(namespace, podName); pod != nil {
		return &pod.Spec
	}
	return nil
}

func (m *mockK8sObjectCache) GetPodStatus(namespace, podName string) *corev1.PodStatus {
	if pod := m.GetPod(namespace, podName); pod != nil {
		return &pod.Status
	}
	return nil
}

func (m *mockK8sObjectCache) GetPods() []*corev1.Pod {
	pods := make([]*corev1.Pod, 0, len(m.pods))
	for _, pod := range m.pods {
		pods = append(pods, pod)
	}
	return pods
}

func (m *mockK8sObjectCache) GetApiServerIpAddress() string {
	return "10.0.0.1"
}

func (m *mockK8sObjectCache) SetSharedContainerData(containerID string, data *objectcache.WatchedContainerData) {
	if m.sharedData == nil {
		m.sharedData = make(map[string]*objectcache.WatchedContainerData)
	}
	m.sharedData[containerID] = data
}

func (m *mockK8sObjectCache) GetSharedContainerData(containerID string) *objectcache.WatchedContainerData {
	if m.sharedData == nil {
		return nil
	}
	return m.sharedData[containerID]
}

func (m *mockK8sObjectCache) DeleteSharedContainerData(containerID string) {
	if m.sharedData != nil {
		delete(m.sharedData, containerID)
	}
}

// Test helper functions
func createTestPod(namespace, name, uid string, ownerRefs []metav1.OwnerReference) *corev1.Pod {
	return &corev1.Pod{
		ObjectMeta: metav1.ObjectMeta{
			Name:            name,
			Namespace:       namespace,
			UID:             types.UID(uid),
			OwnerReferences: ownerRefs,
		},
	}
}

func TestExtractPodAndOwnerUIDs_Success(t *testing.T) {
	// Setup
	pod := createTestPod(
		"default", "nginx-pod", "pod-uid-123",
		[]metav1.OwnerReference{
			{
				APIVersion: "apps/v1",
				Kind:       "ReplicaSet",
				Name:       "nginx-rs",
				UID:        "rs-uid-456",
				Controller: pointer.Bool(true),
			},
		},
	)

	mockCache := &mockObjectCache{
		k8sCache: &mockK8sObjectCache{
			pods: map[string]*corev1.Pod{
				"default/nginx-pod": pod,
			},
		},
	}

	creator := &RuleFailureCreator{}

	// Execute
	podUID, ownerUID, ownerKind, ownerName := creator.extractPodAndOwnerUIDs(
		mockCache, "default", "nginx-pod")

	// Assert
	assert.Equal(t, "pod-uid-123", podUID, "Pod UID should match")
	assert.Equal(t, "rs-uid-456", ownerUID, "Owner UID should match")
	assert.Equal(t, "ReplicaSet", ownerKind, "Owner Kind should match")
	assert.Equal(t, "nginx-rs", ownerName, "Owner Name should match")
}

func TestExtractPodAndOwnerUIDs_PodNotFound(t *testing.T) {
	// Setup - empty cache
	mockCache := &mockObjectCache{
		k8sCache: &mockK8sObjectCache{
			pods: map[string]*corev1.Pod{},
		},
	}

	creator := &RuleFailureCreator{}

	// Execute
	podUID, ownerUID, ownerKind, ownerName := creator.extractPodAndOwnerUIDs(
		mockCache, "default", "non-existent-pod")

	// Assert - all should be empty
	assert.Equal(t, "", podUID, "Pod UID should be empty when pod not found")
	assert.Equal(t, "", ownerUID, "Owner UID should be empty when pod not found")
	assert.Equal(t, "", ownerKind, "Owner Kind should be empty when pod not found")
	assert.Equal(t, "", ownerName, "Owner Name should be empty when pod not found")
}

func TestExtractPodAndOwnerUIDs_PodWithoutOwner(t *testing.T) {
	// Setup - pod with no owner references
	pod := createTestPod("default", "standalone-pod", "pod-uid-789", nil)

	mockCache := &mockObjectCache{
		k8sCache: &mockK8sObjectCache{
			pods: map[string]*corev1.Pod{
				"default/standalone-pod": pod,
			},
		},
	}

	creator := &RuleFailureCreator{}

	// Execute
	podUID, ownerUID, ownerKind, ownerName := creator.extractPodAndOwnerUIDs(
		mockCache, "default", "standalone-pod")

	// Assert - only pod UID should be present
	assert.Equal(t, "pod-uid-789", podUID, "Pod UID should be present")
	assert.Equal(t, "", ownerUID, "Owner UID should be empty for standalone pod")
	assert.Equal(t, "", ownerKind, "Owner Kind should be empty for standalone pod")
	assert.Equal(t, "", ownerName, "Owner Name should be empty for standalone pod")
}

func TestExtractPodAndOwnerUIDs_MultipleOwners_WithController(t *testing.T) {
	// Setup - pod with multiple owners, one is controller
	pod := createTestPod(
		"default", "multi-owner-pod", "pod-uid-999",
		[]metav1.OwnerReference{
			{
				APIVersion: "v1",
				Kind:       "ConfigMap",
				Name:       "config-owner",
				UID:        "config-uid-111",
				Controller: pointer.Bool(false),
			},
			{
				APIVersion: "apps/v1",
				Kind:       "ReplicaSet",
				Name:       "nginx-rs",
				UID:        "rs-uid-222",
				Controller: pointer.Bool(true), // This one should be selected
			},
			{
				APIVersion: "v1",
				Kind:       "Service",
				Name:       "service-owner",
				UID:        "svc-uid-333",
				Controller: pointer.Bool(false),
			},
		},
	)

	mockCache := &mockObjectCache{
		k8sCache: &mockK8sObjectCache{
			pods: map[string]*corev1.Pod{
				"default/multi-owner-pod": pod,
			},
		},
	}

	creator := &RuleFailureCreator{}

	// Execute
	podUID, ownerUID, ownerKind, ownerName := creator.extractPodAndOwnerUIDs(
		mockCache, "default", "multi-owner-pod")

	// Assert - should select the controller owner
	assert.Equal(t, "pod-uid-999", podUID, "Pod UID should match")
	assert.Equal(t, "rs-uid-222", ownerUID, "Should select controller owner UID")
	assert.Equal(t, "ReplicaSet", ownerKind, "Should select controller owner kind")
	assert.Equal(t, "nginx-rs", ownerName, "Should select controller owner name")
}

func TestExtractPodAndOwnerUIDs_MultipleOwners_NoController(t *testing.T) {
	// Setup - pod with multiple owners, none is controller
	pod := createTestPod(
		"default", "multi-owner-no-controller", "pod-uid-888",
		[]metav1.OwnerReference{
			{
				APIVersion: "v1",
				Kind:       "ConfigMap",
				Name:       "config-owner",
				UID:        "config-uid-111",
				Controller: pointer.Bool(false),
			},
			{
				APIVersion: "v1",
				Kind:       "Service",
				Name:       "service-owner",
				UID:        "svc-uid-222",
				Controller: pointer.Bool(false),
			},
		},
	)

	mockCache := &mockObjectCache{
		k8sCache: &mockK8sObjectCache{
			pods: map[string]*corev1.Pod{
				"default/multi-owner-no-controller": pod,
			},
		},
	}

	creator := &RuleFailureCreator{}

	// Execute
	podUID, ownerUID, ownerKind, ownerName := creator.extractPodAndOwnerUIDs(
		mockCache, "default", "multi-owner-no-controller")

	// Assert - should use first owner when no controller
	assert.Equal(t, "pod-uid-888", podUID, "Pod UID should match")
	assert.Equal(t, "config-uid-111", ownerUID, "Should use first owner UID")
	assert.Equal(t, "ConfigMap", ownerKind, "Should use first owner kind")
	assert.Equal(t, "config-owner", ownerName, "Should use first owner name")
}

func TestExtractPodAndOwnerUIDs_EmptyNamespace(t *testing.T) {
	mockCache := &mockObjectCache{
		k8sCache: &mockK8sObjectCache{
			pods: map[string]*corev1.Pod{},
		},
	}

	creator := &RuleFailureCreator{}

	// Execute with empty namespace
	podUID, ownerUID, ownerKind, ownerName := creator.extractPodAndOwnerUIDs(
		mockCache, "", "some-pod")

	// Assert - all should be empty due to validation
	assert.Equal(t, "", podUID)
	assert.Equal(t, "", ownerUID)
	assert.Equal(t, "", ownerKind)
	assert.Equal(t, "", ownerName)
}

func TestExtractPodAndOwnerUIDs_EmptyPodName(t *testing.T) {
	mockCache := &mockObjectCache{
		k8sCache: &mockK8sObjectCache{
			pods: map[string]*corev1.Pod{},
		},
	}

	creator := &RuleFailureCreator{}

	// Execute with empty pod name
	podUID, ownerUID, ownerKind, ownerName := creator.extractPodAndOwnerUIDs(
		mockCache, "default", "")

	// Assert - all should be empty due to validation
	assert.Equal(t, "", podUID)
	assert.Equal(t, "", ownerUID)
	assert.Equal(t, "", ownerKind)
	assert.Equal(t, "", ownerName)
}

func TestExtractPodAndOwnerUIDs_DifferentOwnerTypes(t *testing.T) {
	tests := []struct {
		name         string
		ownerKind    string
		ownerName    string
		ownerUID     string
		expectedKind string
		expectedName string
		expectedUID  string
	}{
		{
			name:         "StatefulSet owner",
			ownerKind:    "StatefulSet",
			ownerName:    "stateful-app",
			ownerUID:     "ss-uid-123",
			expectedKind: "StatefulSet",
			expectedName: "stateful-app",
			expectedUID:  "ss-uid-123",
		},
		{
			name:         "DaemonSet owner",
			ownerKind:    "DaemonSet",
			ownerName:    "node-exporter",
			ownerUID:     "ds-uid-456",
			expectedKind: "DaemonSet",
			expectedName: "node-exporter",
			expectedUID:  "ds-uid-456",
		},
		{
			name:         "Job owner",
			ownerKind:    "Job",
			ownerName:    "batch-job",
			ownerUID:     "job-uid-789",
			expectedKind: "Job",
			expectedName: "batch-job",
			expectedUID:  "job-uid-789",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			pod := createTestPod(
				"default", "test-pod", "pod-uid-test",
				[]metav1.OwnerReference{
					{
						APIVersion: "apps/v1",
						Kind:       tt.ownerKind,
						Name:       tt.ownerName,
						UID:        types.UID(tt.ownerUID),
						Controller: pointer.Bool(true),
					},
				},
			)

			mockCache := &mockObjectCache{
				k8sCache: &mockK8sObjectCache{
					pods: map[string]*corev1.Pod{
						"default/test-pod": pod,
					},
				},
			}

			creator := &RuleFailureCreator{}

			// Execute
			_, ownerUID, ownerKind, ownerName := creator.extractPodAndOwnerUIDs(
				mockCache, "default", "test-pod")

			// Assert
			assert.Equal(t, tt.expectedUID, ownerUID, "Owner UID mismatch")
			assert.Equal(t, tt.expectedKind, ownerKind, "Owner Kind mismatch")
			assert.Equal(t, tt.expectedName, ownerName, "Owner Name mismatch")
		})
	}
}
