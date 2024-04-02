package networkneighborscache

import (
	"context"
	"fmt"
	"node-agent/mocks"
	"node-agent/pkg/objectcache"
	"node-agent/pkg/watcher"
	"testing"

	"github.com/kubescape/storage/pkg/apis/softwarecomposition/v1beta1"
	corev1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/runtime/schema"
	dynamicfake "k8s.io/client-go/dynamic/fake"

	"k8s.io/client-go/kubernetes/scheme"

	helpersv1 "github.com/kubescape/k8s-interface/instanceidhandler/v1/helpers"
	"github.com/kubescape/k8s-interface/k8sinterface"
	"github.com/stretchr/testify/assert"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
)

func init() {
	v1beta1.AddToScheme(scheme.Scheme)
	corev1.AddToScheme(scheme.Scheme)
}

func Test_AddHandlers(t *testing.T) {

	tests := []struct {
		f      func(nn *NetworkNeighborsCacheImp, ctx context.Context, obj *unstructured.Unstructured)
		obj    *unstructured.Unstructured
		name   string
		length int
	}{
		{
			name:   "add network neighbors",
			obj:    mocks.GetUnstructured(mocks.TestKindNN, mocks.TestNginx),
			f:      (*NetworkNeighborsCacheImp).AddHandler,
			length: 1,
		},
		{
			name:   "add pod",
			obj:    mocks.GetUnstructured(mocks.TestKindPod, mocks.TestCollection),
			f:      (*NetworkNeighborsCacheImp).AddHandler,
			length: 1,
		},
		{
			name:   "modify network neighbors",
			obj:    mocks.GetUnstructured(mocks.TestKindNN, mocks.TestNginx),
			f:      (*NetworkNeighborsCacheImp).ModifyHandler,
			length: 1,
		},
		{
			name:   "modify pod",
			obj:    mocks.GetUnstructured(mocks.TestKindPod, mocks.TestCollection),
			f:      (*NetworkNeighborsCacheImp).ModifyHandler,
			length: 1,
		},
		{
			name:   "delete network neighbors",
			obj:    mocks.GetUnstructured(mocks.TestKindNN, mocks.TestNginx),
			f:      (*NetworkNeighborsCacheImp).DeleteHandler,
			length: 0,
		},
		{
			name:   "delete pod",
			obj:    mocks.GetUnstructured(mocks.TestKindPod, mocks.TestCollection),
			f:      (*NetworkNeighborsCacheImp).DeleteHandler,
			length: 0,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			tt.obj.SetNamespace("default")

			k8sClient := k8sinterface.NewKubernetesApiMock()
			nn := NewNetworkNeighborsCache("", k8sClient)

			tt.f(nn, context.Background(), tt.obj)

			switch mocks.TestKinds(tt.obj.GetKind()) {
			case mocks.TestKindNN:
				assert.Equal(t, tt.length, nn.allNeighbors.Cardinality())
			case mocks.TestKindPod:
				assert.Equal(t, tt.length, nn.podToSlug.Len())
			}
		})
	}
}

func Test_addNetworkNeighbor(t *testing.T) {

	// add single network neighbors
	tests := []struct {
		obj            *unstructured.Unstructured
		name           string
		annotations    map[string]string
		preCreatedPods []*unstructured.Unstructured // pre created pods
		preCreatedAP   []*unstructured.Unstructured // pre created network neighborss
		shouldAdd      bool
		shouldAddToPod bool
	}{
		{
			name:      "add single network neighbors nginx",
			obj:       mocks.GetUnstructured(mocks.TestKindNN, mocks.TestNginx),
			shouldAdd: true,
		},
		{
			name: "add network neighbors with complete annotation",
			obj:  mocks.GetUnstructured(mocks.TestKindNN, mocks.TestCollection),
			annotations: map[string]string{
				helpersv1.CompletionMetadataKey: helpersv1.Complete,
			},
			shouldAdd: true,
		},
		{
			name: "ignore single network neighbors with incomplete annotation",
			obj:  mocks.GetUnstructured(mocks.TestKindNN, mocks.TestCollection),
			annotations: map[string]string{
				helpersv1.CompletionMetadataKey: helpersv1.Ready,
			},
			shouldAdd: false,
		},
		{
			name:           "add network neighbors to pod",
			obj:            mocks.GetUnstructured(mocks.TestKindNN, mocks.TestCollection),
			preCreatedPods: []*unstructured.Unstructured{mocks.GetUnstructured(mocks.TestKindPod, mocks.TestCollection)},
			annotations: map[string]string{
				helpersv1.CompletionMetadataKey: helpersv1.Complete,
			},
			shouldAdd:      true,
			shouldAddToPod: true,
		},
		{
			name:           "add network neighbors without pod",
			obj:            mocks.GetUnstructured(mocks.TestKindNN, mocks.TestCollection),
			preCreatedPods: []*unstructured.Unstructured{mocks.GetUnstructured(mocks.TestKindPod, mocks.TestNginx)},
			annotations: map[string]string{
				helpersv1.CompletionMetadataKey: helpersv1.Complete,
			},
			shouldAdd:      true,
			shouldAddToPod: false,
		},
	}
	for i, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if len(tt.annotations) != 0 {
				tt.obj.SetAnnotations(tt.annotations)
			}
			namespace := fmt.Sprintf("default-%d", i)
			k8sClient := k8sinterface.NewKubernetesApiMock()

			var runtimeObjs []runtime.Object
			tt.obj.SetNamespace(namespace)
			runtimeObjs = append(runtimeObjs, &corev1.Namespace{ObjectMeta: metav1.ObjectMeta{Name: namespace}})

			for i := range tt.preCreatedPods {
				tt.preCreatedPods[i].SetNamespace(namespace)
				runtimeObjs = append(runtimeObjs, mocks.UnstructuredToRuntime(tt.preCreatedPods[i]))
			}
			for i := range tt.preCreatedAP {
				tt.preCreatedAP[i].SetNamespace(namespace)
				runtimeObjs = append(runtimeObjs, mocks.UnstructuredToRuntime(tt.preCreatedAP[i]))
			}

			runtimeObjs = append(runtimeObjs, mocks.UnstructuredToRuntime(tt.obj))

			k8sClient.DynamicClient = dynamicfake.NewSimpleDynamicClient(scheme.Scheme, runtimeObjs...)

			nn := NewNetworkNeighborsCache("", k8sClient)

			for i := range tt.preCreatedPods {
				nn.addPod(tt.preCreatedPods[i])
			}
			for i := range tt.preCreatedAP {
				nn.addNetworkNeighbor(context.Background(), tt.preCreatedAP[i])
			}

			nn.addNetworkNeighbor(context.Background(), tt.obj)

			// test if the network neighbors is added to the cache
			apName := objectcache.UnstructuredUniqueName(tt.obj)
			if tt.shouldAdd {
				assert.Equal(t, 1, nn.allNeighbors.Cardinality())
				assert.True(t, nn.slugToNetworkNeighbor.Has(apName))
			} else {
				assert.Equal(t, 0, nn.allNeighbors.Cardinality())
				assert.False(t, nn.slugToNetworkNeighbor.Has(apName))
			}

			if tt.shouldAddToPod {
				assert.True(t, nn.slugToPods.Has(apName))
				for i := range tt.preCreatedPods {
					assert.NotNil(t, nn.GetNetworkNeighbors(namespace, tt.preCreatedPods[i].GetName()))
				}
			} else {
				assert.False(t, nn.slugToPods.Has(apName))
				for i := range tt.preCreatedPods {
					assert.Nil(t, nn.GetNetworkNeighbors(namespace, tt.preCreatedPods[i].GetName()))
				}
			}
		})
	}
}

// func Test_deleteNetworkNeighbors(t *testing.T) {

// 	tests := []struct {
// 		obj          *unstructured.Unstructured
// 		name         string
// 		slug         string
// 		slugs        []string
// 		shouldDelete bool
// 	}{
// 		{
// 			name:         "delete network neighbors nginx",
// 			obj:          mocks.GetUnstructured(mocks.TestKindNN, mocks.TestNginx),
// 			slug:         "/replicaset-nginx-77b4fdf86c",
// 			slugs:        []string{"/replicaset-nginx-77b4fdf86c"},
// 			shouldDelete: true,
// 		},
// 		{
// 			name:         "delete network neighbors from many",
// 			obj:          mocks.GetUnstructured(mocks.TestKindNN, mocks.TestNginx),
// 			slug:         "/replicaset-nginx-77b4fdf86c",
// 			slugs:        []string{"/replicaset-nginx-11111", "/replicaset-nginx-77b4fdf86c", "/replicaset-nginx-22222"},
// 			shouldDelete: true,
// 		},
// 		{
// 			name:         "ignore delete network neighbors nginx",
// 			obj:          mocks.GetUnstructured(mocks.TestKindNN, mocks.TestCollection),
// 			slug:         "/replicaset-nginx-77b4fdf86c",
// 			slugs:        []string{"/replicaset-nginx-77b4fdf86c"},
// 			shouldDelete: false,
// 		},
// 	}
// 	for _, tt := range tests {
// 		t.Run(tt.name, func(t *testing.T) {
// 			nn := NewNetworkNeighborsCache("", nil)

// 			nn.allNeighbors.Append(tt.slugs...)
// 			for _, i := range tt.slugs {
// 				nn.slugToNetworkNeighbor.Set(i, &v1beta1.NetworkNeighbors{})
// 				nn.slugToPods.Set(i, nil)
// 			}

// 			nn.deleteNetworkNeighbors(tt.obj)

// 			if tt.shouldDelete {
// 				assert.Equal(t, len(tt.slugs)-1, nn.allNeighbors.Cardinality())
// 				assert.False(t, nn.slugToNetworkNeighbor.Has(tt.slug))
// 				assert.False(t, nn.slugToPods.Has(tt.slug))
// 			} else {
// 				assert.Equal(t, len(tt.slugs), nn.allNeighbors.Cardinality())
// 				assert.True(t, nn.slugToNetworkNeighbor.Has(tt.slug))
// 				assert.True(t, nn.slugToPods.Has(tt.slug))
// 			}
// 		})
// 	}
// }

// func Test_deletePod(t *testing.T) {

// 	tests := []struct {
// 		obj          *unstructured.Unstructured
// 		name         string
// 		podName      string
// 		slug         string
// 		otherSlugs   []string
// 		shouldDelete bool
// 	}{
// 		{
// 			name:         "delete pod",
// 			obj:          mocks.GetUnstructured(mocks.TestKindPod, mocks.TestNginx),
// 			podName:      "/nginx-77b4fdf86c-hp4x5",
// 			shouldDelete: true,
// 		},
// 		{
// 			name:         "pod not deleted",
// 			obj:          mocks.GetUnstructured(mocks.TestKindPod, mocks.TestNginx),
// 			podName:      "blabla",
// 			shouldDelete: false,
// 		},
// 		{
// 			name:         "delete pod with slug",
// 			obj:          mocks.GetUnstructured(mocks.TestKindPod, mocks.TestNginx),
// 			podName:      "/nginx-77b4fdf86c-hp4x5",
// 			slug:         "/replicaset-nginx-77b4fdf86c",
// 			otherSlugs:   []string{"1111111", "222222"},
// 			shouldDelete: true,
// 		},
// 		{
// 			name:         "delete pod with slug",
// 			obj:          mocks.GetUnstructured(mocks.TestKindPod, mocks.TestNginx),
// 			podName:      "/nginx-77b4fdf86c-hp4x5",
// 			slug:         "/replicaset-nginx-77b4fdf86c",
// 			shouldDelete: true,
// 		},
// 	}
// 	for _, tt := range tests {
// 		t.Run(tt.name, func(t *testing.T) {
// 			nn := NewNetworkNeighborsCache("", nil)
// 			for _, i := range tt.otherSlugs {
// 				nn.slugToPods.Set(i, mapset.NewSet[string]())
// 				nn.slugToNetworkNeighbor.Set(i, &v1beta1.NetworkNeighbors{})
// 			}
// 			if tt.slug != "" {
// 				nn.slugToPods.Set(tt.slug, mapset.NewSet[string](tt.podName))
// 				nn.slugToNetworkNeighbor.Set(tt.slug, &v1beta1.NetworkNeighbors{})
// 			}

// 			nn.podToSlug.Set(tt.podName, tt.slug)

// 			nn.deletePod(tt.obj)

// 			if tt.shouldDelete {
// 				assert.False(t, nn.podToSlug.Has(tt.podName))
// 			} else {
// 				assert.True(t, nn.podToSlug.Has(tt.podName))
// 			}

// 			if tt.slug != "" {
// 				assert.False(t, nn.slugToPods.Has(tt.slug))
// 				assert.Equal(t, len(tt.otherSlugs), nn.slugToPods.Len())
// 				assert.Equal(t, len(tt.otherSlugs), nn.slugToNetworkNeighbor.Len())

// 				if len(tt.otherSlugs) == 0 {
// 					assert.False(t, nn.slugToPods.Has(tt.slug))
// 					assert.False(t, nn.slugToNetworkNeighbor.Has(tt.slug))
// 				}
// 			}
// 		})
// 	}
// }
// func Test_GetNetworkNeighbors(t *testing.T) {
// 	type args struct {
// 		name      string
// 		namespace string
// 		slug      string
// 	}
// 	tests := []struct {
// 		get      args
// 		name     string
// 		pods     []args
// 		expected bool
// 	}{
// 		{
// 			name: "network neighbors found",
// 			pods: []args{
// 				{
// 					name:      "nginx",
// 					namespace: "default",
// 					slug:      "default/replicaset-nginx-1234",
// 				},
// 				{
// 					name:      "collection",
// 					namespace: "default",
// 					slug:      "default/replicaset-collection-1234",
// 				},
// 			},
// 			get: args{
// 				name:      "nginx",
// 				namespace: "default",
// 			},
// 			expected: true,
// 		},
// 		{
// 			name: "network neighbors not found",
// 			pods: []args{
// 				{
// 					name:      "nginx",
// 					namespace: "default",
// 					slug:      "default/replicaset-nginx-1234",
// 				},
// 				{
// 					name:      "collection",
// 					namespace: "default",
// 					slug:      "default/replicaset-collection-1234",
// 				},
// 			},
// 			get: args{
// 				name:      "nginx",
// 				namespace: "collection",
// 			},
// 			expected: false,
// 		},
// 		{
// 			name: "pod exists but network neighbors is not",
// 			pods: []args{
// 				{
// 					name:      "nginx",
// 					namespace: "default",
// 					slug:      "default/replicaset-nginx-1234",
// 				},
// 				{
// 					name:      "collection",
// 					namespace: "default",
// 					slug:      "",
// 				},
// 			},
// 			get: args{
// 				name:      "collection",
// 				namespace: "default",
// 			},
// 			expected: false,
// 		},
// 	}
// 	for _, tt := range tests {
// 		t.Run(tt.name, func(t *testing.T) {
// 			nn := NewNetworkNeighborsCache("", k8sinterface.NewKubernetesApiMock())

// 			for _, c := range tt.pods {
// 				n := objectcache.UniqueName(c.namespace, c.name)
// 				nn.podToSlug.Set(n, c.slug)
// 				if c.slug != "" {
// 					nn.slugToNetworkNeighbor.Set(c.slug, &v1beta1.NetworkNeighbors{})
// 				}
// 			}

// 			p := nn.GetNetworkNeighbors(tt.get.namespace, tt.get.name)
// 			if tt.expected {
// 				assert.NotNil(t, p)
// 			} else {
// 				assert.Nil(t, p)
// 			}
// 		})
// 	}
// }
// func Test_addNetworkNeighbor_existing(t *testing.T) {

// 	// add single network neighbors
// 	tests := []struct {
// 		obj1         *unstructured.Unstructured
// 		obj2         *unstructured.Unstructured
// 		annotations1 map[string]string
// 		annotations2 map[string]string
// 		name         string
// 		storeInCache bool
// 	}{
// 		{
// 			name:         "network neighbors already exists",
// 			obj1:         mocks.GetUnstructured(mocks.TestKindNN, mocks.TestNginx),
// 			obj2:         mocks.GetUnstructured(mocks.TestKindNN, mocks.TestNginx),
// 			storeInCache: true,
// 		},
// 		{
// 			name: "remove network neighbors",
// 			obj1: mocks.GetUnstructured(mocks.TestKindNN, mocks.TestNginx),
// 			obj2: mocks.GetUnstructured(mocks.TestKindNN, mocks.TestNginx),
// 			annotations1: map[string]string{
// 				helpersv1.CompletionMetadataKey: helpersv1.Complete,
// 			},
// 			annotations2: map[string]string{
// 				helpersv1.CompletionMetadataKey: helpersv1.Ready,
// 			},
// 			storeInCache: false,
// 		},
// 	}
// 	for i, tt := range tests {
// 		t.Run(tt.name, func(t *testing.T) {
// 			if len(tt.annotations1) != 0 {
// 				tt.obj1.SetAnnotations(tt.annotations1)
// 			}
// 			if len(tt.annotations2) != 0 {
// 				tt.obj2.SetAnnotations(tt.annotations2)
// 			}
// 			namespace := fmt.Sprintf("default-%d", i)
// 			k8sClient := k8sinterface.NewKubernetesApiMock()

// 			var runtimeObjs []runtime.Object
// 			runtimeObjs = append(runtimeObjs, &corev1.Namespace{ObjectMeta: metav1.ObjectMeta{Name: namespace}})

// 			runtimeObjs = append(runtimeObjs, mocks.UnstructuredToRuntime(tt.obj1))

// 			k8sClient.DynamicClient = dynamicfake.NewSimpleDynamicClient(scheme.Scheme, runtimeObjs...)

// 			nn := NewNetworkNeighborsCache("", k8sClient)

// 			nn.addNetworkNeighbor(context.Background(), tt.obj1)
// 			nn.addNetworkNeighbor(context.Background(), tt.obj2)

// 			// test if the network neighbors is added to the cache
// 			apName := objectcache.UnstructuredUniqueName(tt.obj1)
// 			if tt.storeInCache {
// 				assert.Equal(t, 1, nn.allNeighbors.Cardinality())
// 				assert.True(t, nn.slugToNetworkNeighbor.Has(apName))
// 			} else {
// 				assert.Equal(t, 0, nn.allNeighbors.Cardinality())
// 				assert.False(t, nn.slugToNetworkNeighbor.Has(apName))
// 			}
// 		})
// 	}
// }

func Test_unstructuredToNetworkNeighbors(t *testing.T) {

	tests := []struct {
		obj  *unstructured.Unstructured
		name string
	}{
		{
			name: "nginx network neighbors",
			obj:  mocks.GetUnstructured(mocks.TestKindNN, mocks.TestNginx),
		},
		{
			name: "collection network neighbors",
			obj:  mocks.GetUnstructured(mocks.TestKindNN, mocks.TestCollection),
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			p, err := unstructuredToNetworkNeighbors(tt.obj)
			assert.NoError(t, err)
			assert.Equal(t, tt.obj.GetName(), p.GetName())
			assert.Equal(t, tt.obj.GetLabels(), p.GetLabels())
			assert.Equal(t, tt.obj.GetAnnotations(), p.GetAnnotations())
		})
	}
}

func Test_getNetworkNeighbors(t *testing.T) {
	type args struct {
		name string
	}
	tests := []struct {
		name    string
		obj     *unstructured.Unstructured
		args    args
		wantErr bool
	}{
		{
			name: "nginx network neighbors",
			obj:  mocks.GetUnstructured(mocks.TestKindNN, mocks.TestNginx),
			args: args{
				name: "deployment-nginx",
			},
			wantErr: false,
		},
		{
			name: "collection network neighbors",
			obj:  mocks.GetUnstructured(mocks.TestKindNN, mocks.TestCollection),
			args: args{
				name: "deployment-collection",
			},
			wantErr: false,
		},
		{
			name: "collection network neighbors",
			obj:  mocks.GetUnstructured(mocks.TestKindNN, mocks.TestCollection),
			args: args{
				name: "deployment-nginx",
			},
			wantErr: true,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			k8sClient := k8sinterface.NewKubernetesApiMock()
			k8sClient.DynamicClient = dynamicfake.NewSimpleDynamicClient(scheme.Scheme, mocks.UnstructuredToRuntime(tt.obj))

			nn := &NetworkNeighborsCacheImp{
				k8sClient: k8sClient,
			}

			a, err := nn.getNetworkNeighbors("", tt.args.name)
			if tt.wantErr {
				assert.Error(t, err)
				return
			}
			assert.NoError(t, err)
			assert.Equal(t, tt.obj.GetName(), a.GetName())
			assert.Equal(t, tt.obj.GetLabels(), a.GetLabels())
		})
	}
}

func Test_WatchResources(t *testing.T) {
	nn := NewNetworkNeighborsCache("test-node", nil)

	expectedPodWatchResource := watcher.NewWatchResource(schema.GroupVersionResource{
		Group:    "",
		Version:  "v1",
		Resource: "pods",
	},
		metav1.ListOptions{
			FieldSelector: "spec.nodeName=test-node",
		},
	)

	expectedAPWatchResource := watcher.NewWatchResource(groupVersionResource, metav1.ListOptions{})

	watchResources := nn.WatchResources()
	assert.Equal(t, 2, len(watchResources))
	assert.Equal(t, expectedPodWatchResource, watchResources[0])
	assert.Equal(t, expectedAPWatchResource, watchResources[1])
}

func Test_IsCached(t *testing.T) {
	np := NewNetworkNeighborsCache("", nil)

	// Add some test data to the cache
	np.podToSlug.Set("namespace1/pod1", "")
	np.allNeighbors.Add("namespace2/networkNeighbors1")

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
		{
			kind:      "NetworkNeighbors",
			namespace: "namespace2",
			name:      "networkNeighbors1",
			expected:  true,
		},
		{
			kind:      "NetworkNeighbors",
			namespace: "namespace2",
			name:      "networkNeighbors2",
			expected:  false,
		},
		{
			kind:      "InvalidKind",
			namespace: "namespace1",
			name:      "pod1",
			expected:  false,
		},
	}

	for _, tt := range tests {
		t.Run(fmt.Sprintf("kind=%s, namespace=%s, name=%s", tt.kind, tt.namespace, tt.name), func(t *testing.T) {
			actual := np.IsCached(tt.kind, tt.namespace, tt.name)
			assert.Equal(t, tt.expected, actual)
		})
	}
}
