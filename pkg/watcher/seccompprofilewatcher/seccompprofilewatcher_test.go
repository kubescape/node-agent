package seccompprofilewatcher

import (
	"testing"

	"github.com/kubescape/node-agent/pkg/config"
	"github.com/kubescape/node-agent/pkg/seccompmanager"
	v1beta1api "github.com/kubescape/storage/pkg/apis/softwarecomposition/v1beta1"
	"github.com/stretchr/testify/assert"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
)

func TestNewSeccompProfileWatcherWithBackend_StorageBackend(t *testing.T) {
	watcher := NewSeccompProfileWatcherWithBackend(nil, seccompmanager.NewSeccompManagerMock(), config.SeccompBackendStorage)

	assert.NotNil(t, watcher)
	assert.Equal(t, "spdx.softwarecomposition.kubescape.io", watcher.groupVersionResource.Group)
	assert.Equal(t, "v1beta1", watcher.groupVersionResource.Version)
	assert.Equal(t, "seccompprofiles", watcher.groupVersionResource.Resource)
	assert.Equal(t, config.SeccompBackendStorage, watcher.backend)
}

func TestNewSeccompProfileWatcherWithBackend_CRDBackend(t *testing.T) {
	watcher := NewSeccompProfileWatcherWithBackend(nil, seccompmanager.NewSeccompManagerMock(), config.SeccompBackendCRD)

	assert.NotNil(t, watcher)
	assert.Equal(t, "kubescape.io", watcher.groupVersionResource.Group)
	assert.Equal(t, "v1beta1", watcher.groupVersionResource.Version)
	assert.Equal(t, "seccompprofiles", watcher.groupVersionResource.Resource)
	assert.Equal(t, config.SeccompBackendCRD, watcher.backend)
}

func TestNewSeccompProfileWatcherWithBackend_InvalidBackend(t *testing.T) {
	// Invalid backend should default to storage
	watcher := NewSeccompProfileWatcherWithBackend(nil, seccompmanager.NewSeccompManagerMock(), "invalid")

	assert.NotNil(t, watcher)
	assert.Equal(t, "spdx.softwarecomposition.kubescape.io", watcher.groupVersionResource.Group)
	assert.Equal(t, "v1beta1", watcher.groupVersionResource.Version)
	assert.Equal(t, "seccompprofiles", watcher.groupVersionResource.Resource)
	// Backend is stored as-is (the config validation catches invalid values at load time)
	assert.Equal(t, "invalid", watcher.backend)
}

func TestNewSeccompProfileWatcherWithBackend_EmptyBackend(t *testing.T) {
	// Empty backend should default to storage
	watcher := NewSeccompProfileWatcherWithBackend(nil, seccompmanager.NewSeccompManagerMock(), "")

	assert.NotNil(t, watcher)
	assert.Equal(t, "spdx.softwarecomposition.kubescape.io", watcher.groupVersionResource.Group)
	assert.Equal(t, "v1beta1", watcher.groupVersionResource.Version)
	assert.Equal(t, "seccompprofiles", watcher.groupVersionResource.Resource)
}

func TestNewSeccompProfileWatcher_DefaultsToStorage(t *testing.T) {
	watcher := NewSeccompProfileWatcher(nil, seccompmanager.NewSeccompManagerMock())

	assert.NotNil(t, watcher)
	assert.Equal(t, "spdx.softwarecomposition.kubescape.io", watcher.groupVersionResource.Group)
	assert.Equal(t, config.SeccompBackendStorage, watcher.backend)
}

func TestConvertToSeccompProfile_TypedObject(t *testing.T) {
	watcher := NewSeccompProfileWatcherWithBackend(nil, seccompmanager.NewSeccompManagerMock(), config.SeccompBackendStorage)

	typedProfile := &v1beta1api.SeccompProfile{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "test-profile",
			Namespace: "test-namespace",
		},
		Spec: v1beta1api.SeccompProfileSpec{
			Containers: []v1beta1api.SingleSeccompProfile{
				{
					Name: "container1",
					Path: "/path/to/profile",
				},
			},
		},
	}

	result, ok := watcher.convertToSeccompProfile(typedProfile)

	assert.True(t, ok)
	assert.NotNil(t, result)
	assert.Equal(t, "test-profile", result.Name)
	assert.Equal(t, "test-namespace", result.Namespace)
	assert.Len(t, result.Spec.Containers, 1)
	assert.Equal(t, "container1", result.Spec.Containers[0].Name)
}

func TestConvertToSeccompProfile_ValidUnstructuredObject(t *testing.T) {
	watcher := NewSeccompProfileWatcherWithBackend(nil, seccompmanager.NewSeccompManagerMock(), config.SeccompBackendCRD)

	unstructuredProfile := &unstructured.Unstructured{
		Object: map[string]interface{}{
			"apiVersion": "kubescape.io/v1beta1",
			"kind":       "SeccompProfile",
			"metadata": map[string]interface{}{
				"name":      "test-profile",
				"namespace": "test-namespace",
			},
			"spec": map[string]interface{}{
				"containers": []interface{}{
					map[string]interface{}{
						"name": "container1",
						"path": "/path/to/profile",
						"spec": map[string]interface{}{
							"defaultAction": "SCMP_ACT_ERRNO",
						},
					},
				},
			},
		},
	}

	result, ok := watcher.convertToSeccompProfile(unstructuredProfile)

	assert.True(t, ok)
	assert.NotNil(t, result)
	assert.Equal(t, "test-profile", result.Name)
	assert.Equal(t, "test-namespace", result.Namespace)
	assert.Len(t, result.Spec.Containers, 1)
	assert.Equal(t, "container1", result.Spec.Containers[0].Name)
}

func TestConvertToSeccompProfile_MalformedUnstructuredObject(t *testing.T) {
	watcher := NewSeccompProfileWatcherWithBackend(nil, seccompmanager.NewSeccompManagerMock(), config.SeccompBackendCRD)

	// Create a malformed unstructured object where spec.containers has invalid type
	malformedProfile := &unstructured.Unstructured{
		Object: map[string]interface{}{
			"apiVersion": "kubescape.io/v1beta1",
			"kind":       "SeccompProfile",
			"metadata": map[string]interface{}{
				"name":      "test-profile",
				"namespace": "test-namespace",
			},
			"spec": map[string]interface{}{
				// containers should be an array, but we give it a string
				"containers": "invalid-type",
			},
		},
	}

	result, ok := watcher.convertToSeccompProfile(malformedProfile)

	assert.False(t, ok)
	assert.Nil(t, result)
}

func TestConvertToSeccompProfile_NilObject(t *testing.T) {
	watcher := NewSeccompProfileWatcherWithBackend(nil, seccompmanager.NewSeccompManagerMock(), config.SeccompBackendStorage)

	// Test with nil which should return false
	// Note: We can't directly pass unsupported types since convertToSeccompProfile expects runtime.Object
	result, ok := watcher.convertToSeccompProfile(nil)

	assert.False(t, ok)
	assert.Nil(t, result)
}

func TestConvertToSeccompProfile_EmptyUnstructuredObject(t *testing.T) {
	watcher := NewSeccompProfileWatcherWithBackend(nil, seccompmanager.NewSeccompManagerMock(), config.SeccompBackendCRD)

	// Empty unstructured object should still convert (with empty fields)
	emptyProfile := &unstructured.Unstructured{
		Object: map[string]interface{}{
			"metadata": map[string]interface{}{
				"name":      "empty-profile",
				"namespace": "test-namespace",
			},
		},
	}

	result, ok := watcher.convertToSeccompProfile(emptyProfile)

	assert.True(t, ok)
	assert.NotNil(t, result)
	assert.Equal(t, "empty-profile", result.Name)
	assert.Equal(t, "test-namespace", result.Namespace)
	assert.Empty(t, result.Spec.Containers)
}

func TestWatchResources_StorageBackend(t *testing.T) {
	watcher := NewSeccompProfileWatcherWithBackend(nil, seccompmanager.NewSeccompManagerMock(), config.SeccompBackendStorage)

	resources := watcher.WatchResources()

	assert.Len(t, resources, 1)
	gvr := resources[0].GroupVersionResource()
	assert.Equal(t, "spdx.softwarecomposition.kubescape.io", gvr.Group)
	assert.Equal(t, "v1beta1", gvr.Version)
	assert.Equal(t, "seccompprofiles", gvr.Resource)
}

func TestWatchResources_CRDBackend(t *testing.T) {
	watcher := NewSeccompProfileWatcherWithBackend(nil, seccompmanager.NewSeccompManagerMock(), config.SeccompBackendCRD)

	resources := watcher.WatchResources()

	assert.Len(t, resources, 1)
	gvr := resources[0].GroupVersionResource()
	assert.Equal(t, "kubescape.io", gvr.Group)
	assert.Equal(t, "v1beta1", gvr.Version)
	assert.Equal(t, "seccompprofiles", gvr.Resource)
}

