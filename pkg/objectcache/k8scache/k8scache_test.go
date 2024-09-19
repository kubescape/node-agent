package k8scache

import (
	"context"
	"testing"

	"github.com/kubescape/k8s-interface/k8sinterface"
	"github.com/kubescape/node-agent/mocks"
	"github.com/kubescape/node-agent/pkg/watcher"
	"github.com/stretchr/testify/assert"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime/schema"
)

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
		obj  []*corev1.Pod
		args []args
	}{
		{
			name: "Test with valid namespace and podName",
			obj: []*corev1.Pod{
				mocks.GetRuntime(mocks.TestKindPod, mocks.TestNginx).(*corev1.Pod),
				mocks.GetRuntime(mocks.TestKindPod, mocks.TestCollection).(*corev1.Pod),
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
					assert.NotNil(t, spec)
					assert.Equal(t, tt.obj[i].Spec, *spec)
				}
			}

			// Test MODIFY
			{
				for _, obj := range tt.obj {
					o := obj.DeepCopy()
					o.Spec = corev1.PodSpec{}
					k.ModifyHandler(context.Background(), o)
				}

				for i, arg := range tt.args {
					spec := k.GetPodSpec(arg.namespace, arg.podName)
					if arg.wantNil {
						assert.Nil(t, spec)
						continue
					}
					o := tt.obj[i].DeepCopy()
					o.Spec = corev1.PodSpec{}

					assert.NotNil(t, spec)
					assert.Equal(t, o.Spec, *spec)
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
