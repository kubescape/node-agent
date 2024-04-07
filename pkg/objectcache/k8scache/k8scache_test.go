package k8scache

import (
	"context"
	"fmt"
	"node-agent/mocks"
	"node-agent/pkg/watcher"
	"testing"

	"github.com/kubescape/k8s-interface/k8sinterface"
	"github.com/stretchr/testify/assert"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	"k8s.io/apimachinery/pkg/runtime/schema"
)

func TestUnstructuredToPod(t *testing.T) {

	tests := []struct {
		obj  *unstructured.Unstructured
		name string
	}{
		{
			name: "nginx pod",
			obj:  mocks.GetUnstructured(mocks.TestKindPod, mocks.TestNginx),
		},
		{
			name: "collection pod",
			obj:  mocks.GetUnstructured(mocks.TestKindPod, mocks.TestCollection),
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			p, err := unstructuredToPod(tt.obj)
			assert.NoError(t, err)
			assert.Equal(t, tt.obj.GetName(), p.GetName())
			assert.Equal(t, tt.obj.GetLabels(), p.GetLabels())
		})
	}
}
func TestPodSpecKey(t *testing.T) {
	tests := []struct {
		name      string
		namespace string
		podName   string
		expected  string
	}{
		{
			name:      "Test with valid namespace and podName",
			namespace: "default",
			podName:   "pod-1",
			expected:  "default/pod-1",
		},
		{
			name:      "Test with empty namespace",
			namespace: "",
			podName:   "pod-1",
			expected:  "/pod-1",
		},
		{
			name:      "Test with empty podName",
			namespace: "default",
			podName:   "",
			expected:  "default/",
		},
		{
			name:      "Test with empty namespace and podName",
			namespace: "",
			podName:   "",
			expected:  "/",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := podKey(tt.namespace, tt.podName)
			assert.Equal(t, tt.expected, result)
		})
	}
}
func TestK8sObjectCacheImpl_WatchResources(t *testing.T) {
	k := &K8sObjectCacheImpl{
		nodeName: "test-node",
	}

	expected := []watcher.WatchResource{
		watcher.NewWatchResource(schema.GroupVersionResource{
			Group:    "",
			Version:  "v1",
			Resource: "pods",
		},
			metav1.ListOptions{
				FieldSelector: "spec.nodeName=" + k.nodeName,
			},
		),
	}

	result := k.WatchResources()

	assert.Equal(t, expected, result)
}

func TestK8sObjectCacheImpl_GetPodSpec(t *testing.T) {

	type args struct {
		namespace string
		podName   string
		wantNil   bool
	}
	tests := []struct {
		name string
		obj  []*unstructured.Unstructured
		args []args
	}{
		{
			name: "Test with valid namespace and podName",
			obj: []*unstructured.Unstructured{
				mocks.GetUnstructured(mocks.TestKindPod, mocks.TestNginx),
				mocks.GetUnstructured(mocks.TestKindPod, mocks.TestCollection),
			},
			args: []args{
				{
					namespace: "",
					podName:   "nginx-77b4fdf86c-hp4x5",
					wantNil:   false,
				},
				{
					namespace: "",
					podName:   "collection-94c495554-z8s5k",
					wantNil:   false,
				},
				{
					namespace: "default",
					podName:   "collection-94c495554-z8s5k",
					wantNil:   true,
				},
			},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			k := &K8sObjectCacheImpl{}

			// Test ADD
			{
				for _, obj := range tt.obj {
					k.AddHandler(context.Background(), obj)
				}

				for i, arg := range tt.args {
					spec := k.GetPodSpec(arg.namespace, arg.podName)
					if arg.wantNil {
						assert.Nil(t, spec)
						continue
					}
					p, _ := unstructuredToPod(tt.obj[i])
					assert.NotNil(t, spec)
					assert.Equal(t, p.Spec, *spec)
				}
			}

			// Test MODIFY
			{
				for _, obj := range tt.obj {
					o := obj.DeepCopy()
					o.Object["spec"] = map[string]interface{}{}
					k.ModifyHandler(context.Background(), o)
				}

				for i, arg := range tt.args {
					spec := k.GetPodSpec(arg.namespace, arg.podName)
					if arg.wantNil {
						assert.Nil(t, spec)
						continue
					}
					o := tt.obj[i].DeepCopy()
					o.Object["spec"] = map[string]interface{}{}

					p, _ := unstructuredToPod(o)
					assert.NotNil(t, spec)
					assert.Equal(t, p.Spec, *spec)
				}
			}

			// Test DELETE
			{
				for _, obj := range tt.obj {
					k.DeleteHandler(context.Background(), obj)
				}

				for _, arg := range tt.args {
					spec := k.GetPodSpec(arg.namespace, arg.podName)
					assert.Nil(t, spec)
				}
			}

		})
	}
}
func TestK8sObjectCacheImpl_GetApiServerIpAddress(t *testing.T) {
	k := &K8sObjectCacheImpl{
		apiServerIpAddress: "127.0.0.1",
	}

	result := k.GetApiServerIpAddress()

	assert.Equal(t, "127.0.0.1", result)
}

func TestK8sObjectCacheImpl_setApiServerIpAddress(t *testing.T) {

	tests := []struct {
		name               string
		apiServerIpAddress string
		service            corev1.Service
		wantErr            bool
	}{
		{
			name: "Test with valid service",
			service: corev1.Service{
				ObjectMeta: metav1.ObjectMeta{
					Name:      "kubernetes",
					Namespace: "default",
				},
				Spec: corev1.ServiceSpec{
					ClusterIP: "63.56.12.45",
				},
			},
			apiServerIpAddress: "63.56.12.45",
			wantErr:            false,
		},
		{
			name: "Test with valid service",
			service: corev1.Service{
				ObjectMeta: metav1.ObjectMeta{
					Name:      "kubernetes",
					Namespace: "blabla",
				},
				Spec: corev1.ServiceSpec{
					ClusterIP: "63.56.12.45",
				},
			},
			apiServerIpAddress: "",
			wantErr:            true,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			k := &K8sObjectCacheImpl{
				k8sClient: k8sinterface.NewKubernetesApiMock(),
			}
			k.k8sClient.GetKubernetesClient().CoreV1().Services(tt.service.GetNamespace()).Create(context.Background(), &tt.service, metav1.CreateOptions{})
			if err := k.setApiServerIpAddress(); (err != nil) != tt.wantErr {
				t.Errorf("K8sObjectCacheImpl.setApiServerIpAddress() error = %v, wantErr %v", err, tt.wantErr)
			}
			assert.Equal(t, tt.apiServerIpAddress, k.GetApiServerIpAddress())
		})
	}
}

func Test_IsCached(t *testing.T) {
	k, _ := NewK8sObjectCache("", k8sinterface.NewKubernetesApiMock())

	// Add some test data to the cache
	k.podSpec.Set("namespace1/pod1", &corev1.PodSpec{})

	tests := []struct {
		kind      string
		namespace string
		name      string
		expected  bool
	}{
		{
			kind:      "Pod",
			namespace: "namespace1",
			name:      "pod1",
			expected:  true,
		},
		{
			kind:      "Pod",
			namespace: "namespace1",
			name:      "pod2",
			expected:  false,
		},
	}

	for _, tt := range tests {
		t.Run(fmt.Sprintf("kind=%s, namespace=%s, name=%s", tt.kind, tt.namespace, tt.name), func(t *testing.T) {
			actual := k.IsCached(tt.kind, tt.namespace, tt.name)
			assert.Equal(t, tt.expected, actual)
		})
	}
}
