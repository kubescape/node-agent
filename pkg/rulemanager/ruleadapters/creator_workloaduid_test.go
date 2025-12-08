package ruleadapters

import (
	"testing"

	apitypes "github.com/armosec/armoapi-go/armotypes"
	igtypes "github.com/inspektor-gadget/inspektor-gadget/pkg/types"
	"github.com/kubescape/node-agent/pkg/objectcache"
	"github.com/kubescape/node-agent/pkg/rulemanager/types"
	"github.com/kubescape/node-agent/pkg/utils"
	"github.com/stretchr/testify/assert"
	corev1 "k8s.io/api/core/v1"
)

// mockEnrichEvent is a minimal mock for testing
type mockEnrichEvent struct{}

func (m *mockEnrichEvent) GetEventType() utils.EventType   { return utils.ExecveEventType }
func (m *mockEnrichEvent) GetNamespace() string            { return "default" }
func (m *mockEnrichEvent) GetPod() string                  { return "test-pod" }
func (m *mockEnrichEvent) GetContainerID() string          { return "container-123" }
func (m *mockEnrichEvent) GetContainer() string            { return "test-container" }
func (m *mockEnrichEvent) GetContainerImage() string       { return "" }
func (m *mockEnrichEvent) GetContainerImageDigest() string { return "" }
func (m *mockEnrichEvent) GetComm() string                 { return "" }
func (m *mockEnrichEvent) GetError() int64                 { return 0 }
func (m *mockEnrichEvent) GetExtra() interface{}           { return nil }
func (m *mockEnrichEvent) GetGid() *uint32                 { return nil }
func (m *mockEnrichEvent) GetHostNetwork() bool            { return false }
func (m *mockEnrichEvent) GetMountNsID() uint64            { return 0 }
func (m *mockEnrichEvent) GetPcomm() string                { return "" }
func (m *mockEnrichEvent) GetPID() uint32                  { return 0 }
func (m *mockEnrichEvent) GetPID64() uint64                { return 0 }
func (m *mockEnrichEvent) GetPodLabels() map[string]string { return nil }
func (m *mockEnrichEvent) GetPpid() uint32                 { return 0 }
func (m *mockEnrichEvent) GetUid() *uint32                 { return nil }
func (m *mockEnrichEvent) GetTimestamp() igtypes.Time      { return igtypes.Time(0) }
func (m *mockEnrichEvent) HasDroppedEvents() bool          { return false }
func (m *mockEnrichEvent) Release()                        {}
func (m *mockEnrichEvent) SetExtra(extra interface{})      {}

// TestSetRuntimeAlertK8sDetails_WithWorkloadUID tests that WorkloadUID is populated from WatchedContainerData
func TestSetRuntimeAlertK8sDetails_WithWorkloadUID(t *testing.T) {
	creator := &RuleFailureCreator{}

	// Create a mock pod with UID
	pod := createTestPod("default", "test-pod", "pod-uid-12345", nil)

	// Set up shared container data with WorkloadUID
	workloadUID := "deployment-uid-67890"
	sharedData := &objectcache.WatchedContainerData{
		ContainerID: "container-123",
		WorkloadUID: workloadUID,
		Wlid:        "wlid://cluster-test/namespace-default/deployment-nginx",
	}

	// Create mock K8s cache with pod and shared data
	k8sCache := &mockK8sObjectCache{
		pods: map[string]*corev1.Pod{
			"default/test-pod": pod,
		},
	}
	k8sCache.SetSharedContainerData("container-123", sharedData)

	// Create object cache
	objCache := &mockObjectCache{
		k8sCache: k8sCache,
	}

	// Create a mock rule failure with TriggerEvent
	ruleFailure := &types.GenericRuleFailure{
		TriggerEvent: &mockEnrichEvent{},
		RuntimeAlertK8sDetails: apitypes.RuntimeAlertK8sDetails{
			ContainerID: "container-123",
			Namespace:   "default",
			PodName:     "test-pod",
		},
	}

	// Call the function
	creator.setRuntimeAlertK8sDetails(ruleFailure, objCache)

	// Verify WorkloadUID is set from WatchedContainerData
	k8sDetails := ruleFailure.GetRuntimeAlertK8sDetails()
	assert.Equal(t, workloadUID, k8sDetails.WorkloadUID, "WorkloadUID should be set from WatchedContainerData")
	assert.Equal(t, "pod-uid-12345", k8sDetails.PodUID, "PodUID should be set from pod cache")
}

// TestSetRuntimeAlertK8sDetails_WithoutSharedData tests fallback when WatchedContainerData is not available
func TestSetRuntimeAlertK8sDetails_WithoutSharedData(t *testing.T) {
	creator := &RuleFailureCreator{}

	// Create a mock pod with UID
	pod := createTestPod("default", "test-pod", "pod-uid-12345", nil)

	// Create mock K8s cache with pod but NO shared container data
	k8sCache := &mockK8sObjectCache{
		pods: map[string]*corev1.Pod{
			"default/test-pod": pod,
		},
	}

	// Create object cache
	objCache := &mockObjectCache{
		k8sCache: k8sCache,
	}

	// Create a mock rule failure with TriggerEvent
	ruleFailure := &types.GenericRuleFailure{
		TriggerEvent: &mockEnrichEvent{},
		RuntimeAlertK8sDetails: apitypes.RuntimeAlertK8sDetails{
			ContainerID: "container-123",
			Namespace:   "default",
			PodName:     "test-pod",
		},
	}

	// Call the function
	creator.setRuntimeAlertK8sDetails(ruleFailure, objCache)

	// Verify PodUID is still set, but WorkloadUID is empty
	k8sDetails := ruleFailure.GetRuntimeAlertK8sDetails()
	assert.Equal(t, "pod-uid-12345", k8sDetails.PodUID, "PodUID should be set from pod cache")
	assert.Empty(t, k8sDetails.WorkloadUID, "WorkloadUID should be empty when shared data is not available")
}

// TestSetRuntimeAlertK8sDetails_EmptyWorkloadUID tests when WorkloadUID is empty in shared data
func TestSetRuntimeAlertK8sDetails_EmptyWorkloadUID(t *testing.T) {
	creator := &RuleFailureCreator{}

	// Create a mock pod with UID
	pod := createTestPod("default", "test-pod", "pod-uid-12345", nil)

	// Set up shared container data with EMPTY WorkloadUID
	sharedData := &objectcache.WatchedContainerData{
		ContainerID: "container-123",
		WorkloadUID: "", // Empty!
		Wlid:        "wlid://cluster-test/namespace-default/deployment-nginx",
	}

	// Create mock K8s cache with pod and shared data
	k8sCache := &mockK8sObjectCache{
		pods: map[string]*corev1.Pod{
			"default/test-pod": pod,
		},
	}
	k8sCache.SetSharedContainerData("container-123", sharedData)

	// Create object cache
	objCache := &mockObjectCache{
		k8sCache: k8sCache,
	}

	// Create a mock rule failure with TriggerEvent
	ruleFailure := &types.GenericRuleFailure{
		TriggerEvent: &mockEnrichEvent{},
		RuntimeAlertK8sDetails: apitypes.RuntimeAlertK8sDetails{
			ContainerID: "container-123",
			Namespace:   "default",
			PodName:     "test-pod",
		},
	}

	// Call the function
	creator.setRuntimeAlertK8sDetails(ruleFailure, objCache)

	// Verify WorkloadUID is empty
	k8sDetails := ruleFailure.GetRuntimeAlertK8sDetails()
	assert.Equal(t, "pod-uid-12345", k8sDetails.PodUID, "PodUID should be set from pod cache")
	assert.Empty(t, k8sDetails.WorkloadUID, "WorkloadUID should be empty when not set in shared data")
}
