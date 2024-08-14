package networkneighborhoodcache

import (
	"context"
	"fmt"
	"slices"
	"testing"

	"github.com/kubescape/node-agent/mocks"
	"github.com/kubescape/node-agent/pkg/objectcache"
	"github.com/kubescape/node-agent/pkg/watcher"

	mapset "github.com/deckarep/golang-set/v2"
	"github.com/kubescape/storage/pkg/apis/softwarecomposition/v1beta1"
	corev1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/runtime/schema"
	dynamicfake "k8s.io/client-go/dynamic/fake"

	"k8s.io/client-go/kubernetes/scheme"

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
		f      func(ap *NetworkNeighborhoodCacheImpl, ctx context.Context, obj *unstructured.Unstructured)
		obj    *unstructured.Unstructured
		name   string
		slug   string
		length int
	}{
		{
			name:   "add network neighborhood",
			obj:    mocks.GetUnstructured(mocks.TestKindNN, mocks.TestNginx),
			f:      (*NetworkNeighborhoodCacheImpl).AddHandler,
			slug:   "default/replicaset-nginx-77b4fdf86c",
			length: 1,
		},
		{
			name:   "add pod",
			obj:    mocks.GetUnstructured(mocks.TestKindPod, mocks.TestCollection),
			f:      (*NetworkNeighborhoodCacheImpl).AddHandler,
			slug:   "default/replicaset-collection-94c495554",
			length: 6,
		},
		{
			name:   "modify network neighborhood",
			obj:    mocks.GetUnstructured(mocks.TestKindNN, mocks.TestNginx),
			f:      (*NetworkNeighborhoodCacheImpl).ModifyHandler,
			length: 1,
		},
		{
			name:   "modify pod",
			obj:    mocks.GetUnstructured(mocks.TestKindPod, mocks.TestCollection),
			f:      (*NetworkNeighborhoodCacheImpl).ModifyHandler,
			slug:   "default/replicaset-collection-94c495554",
			length: 6,
		},
		{
			name:   "delete network neighborhood",
			obj:    mocks.GetUnstructured(mocks.TestKindNN, mocks.TestNginx),
			f:      (*NetworkNeighborhoodCacheImpl).DeleteHandler,
			slug:   "default/replicaset-nginx-77b4fdf86c",
			length: 0,
		},
		{
			name:   "delete pod",
			obj:    mocks.GetUnstructured(mocks.TestKindPod, mocks.TestCollection),
			f:      (*NetworkNeighborhoodCacheImpl).DeleteHandler,
			slug:   "default/replicaset-collection-94c495554",
			length: 0,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			tt.obj.SetNamespace("default")
			k8sClient := k8sinterface.NewKubernetesApiMock()
			nn := NewNetworkNeighborhoodCache("", k8sClient)
			nn.slugToContainers.Set(tt.slug, mapset.NewSet[string]())

			tt.f(nn, context.Background(), tt.obj)

			switch mocks.TestKinds(tt.obj.GetKind()) {
			case mocks.TestKindNN:
				assert.Equal(t, tt.length, nn.allNetworkNeighborhoods.Cardinality())
			case mocks.TestKindPod:
				assert.Equal(t, tt.length, nn.slugToContainers.Get(tt.slug).Cardinality())
			}
		})
	}
}

func Test_addNetworkNeighborhood(t *testing.T) {

	// add single network neighborhood
	tests := []struct {
		obj            *unstructured.Unstructured
		name           string
		annotations    map[string]string
		preCreatedPods []*unstructured.Unstructured // pre created pods
		preCreatedAP   []*unstructured.Unstructured // pre created network neighborhoods
		shouldAdd      bool
		shouldAddToPod bool
	}{
		{
			name: "add single network neighborhood nginx",
			obj:  mocks.GetUnstructured(mocks.TestKindNN, mocks.TestNginx),
			annotations: map[string]string{
				"kubescape.io/status":     "completed",
				"kubescape.io/completion": "complete",
			},
			shouldAdd: true,
		},
		{
			name: "add network neighborhood with partial annotation",
			obj:  mocks.GetUnstructured(mocks.TestKindNN, mocks.TestCollection),
			annotations: map[string]string{
				"kubescape.io/status":     "completed",
				"kubescape.io/completion": "partial",
			},
			shouldAdd: true,
		},
		{
			name: "ignore single network neighborhood with incomplete annotation",
			obj:  mocks.GetUnstructured(mocks.TestKindNN, mocks.TestCollection),
			annotations: map[string]string{
				"kubescape.io/status":     "ready",
				"kubescape.io/completion": "complete",
			},
			shouldAdd: false,
		},
		{
			name:           "add network neighborhood to pod",
			obj:            mocks.GetUnstructured(mocks.TestKindNN, mocks.TestCollection),
			preCreatedPods: []*unstructured.Unstructured{mocks.GetUnstructured(mocks.TestKindPod, mocks.TestCollection)},
			annotations: map[string]string{
				"kubescape.io/status":     "completed",
				"kubescape.io/completion": "complete",
			},
			shouldAdd:      true,
			shouldAddToPod: true,
		},
		{
			name:           "add network neighborhood without pod",
			obj:            mocks.GetUnstructured(mocks.TestKindNN, mocks.TestCollection),
			preCreatedPods: []*unstructured.Unstructured{mocks.GetUnstructured(mocks.TestKindPod, mocks.TestNginx)},
			annotations: map[string]string{
				"kubescape.io/status":     "completed",
				"kubescape.io/completion": "complete",
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

			nn := NewNetworkNeighborhoodCache("", k8sClient)

			for i := range tt.preCreatedPods {
				nn.addPod(tt.preCreatedPods[i])
			}
			for i := range tt.preCreatedAP {
				nn.addNetworkNeighborhood(context.Background(), tt.preCreatedAP[i])
			}

			nn.addNetworkNeighborhood(context.Background(), tt.obj)

			// test if the network neighborhood is added to the cache
			apName := objectcache.UnstructuredUniqueName(tt.obj)
			if tt.shouldAdd {
				assert.Equal(t, 1, nn.allNetworkNeighborhoods.Cardinality())
			} else {
				assert.Equal(t, 0, nn.allNetworkNeighborhoods.Cardinality())
			}

			if tt.shouldAddToPod {
				assert.True(t, nn.slugToContainers.Has(apName))
				assert.True(t, nn.slugToNetworkNeighborhood.Has(apName))
				for i := range tt.preCreatedPods {
					p, _ := objectcache.UnstructuredToPod(tt.preCreatedPods[i])
					for _, c := range objectcache.ListContainersIDs(p) {
						assert.NotNil(t, nn.GetNetworkNeighborhood(c))
					}
				}
			} else {
				assert.False(t, nn.slugToContainers.Has(apName))
				assert.False(t, nn.slugToNetworkNeighborhood.Has(apName))
				for i := range tt.preCreatedPods {
					p, _ := objectcache.UnstructuredToPod(tt.preCreatedPods[i])
					for _, c := range objectcache.ListContainersIDs(p) {
						assert.Nil(t, nn.GetNetworkNeighborhood(c))
					}
				}
			}
		})
	}
}
func Test_deleteNetworkNeighborhood(t *testing.T) {

	tests := []struct {
		obj          *unstructured.Unstructured
		name         string
		slug         string
		slugs        []string
		shouldDelete bool
	}{
		{
			name:         "delete network neighborhood nginx",
			obj:          mocks.GetUnstructured(mocks.TestKindNN, mocks.TestNginx),
			slug:         "/replicaset-nginx-77b4fdf86c",
			slugs:        []string{"/replicaset-nginx-77b4fdf86c"},
			shouldDelete: true,
		},
		{
			name:         "delete network neighborhood from many",
			obj:          mocks.GetUnstructured(mocks.TestKindNN, mocks.TestNginx),
			slug:         "/replicaset-nginx-77b4fdf86c",
			slugs:        []string{"/replicaset-nginx-11111", "/replicaset-nginx-77b4fdf86c", "/replicaset-nginx-22222"},
			shouldDelete: true,
		},
		{
			name:         "ignore delete network neighborhood nginx",
			obj:          mocks.GetUnstructured(mocks.TestKindNN, mocks.TestCollection),
			slug:         "/replicaset-nginx-77b4fdf86c",
			slugs:        []string{"/replicaset-nginx-77b4fdf86c"},
			shouldDelete: false,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			nn := NewNetworkNeighborhoodCache("", nil)

			nn.allNetworkNeighborhoods.Append(tt.slugs...)
			for _, i := range tt.slugs {
				nn.slugToNetworkNeighborhood.Set(i, &v1beta1.NetworkNeighborhood{})
				nn.slugToContainers.Set(i, nil)
			}

			nn.deleteNetworkNeighborhood(tt.obj)

			if tt.shouldDelete {
				assert.Equal(t, len(tt.slugs)-1, nn.allNetworkNeighborhoods.Cardinality())
				assert.False(t, nn.slugToNetworkNeighborhood.Has(tt.slug))
				assert.True(t, nn.slugToContainers.Has(tt.slug)) // this field should not be deleted
			} else {
				assert.Equal(t, len(tt.slugs), nn.allNetworkNeighborhoods.Cardinality())
				assert.True(t, nn.slugToNetworkNeighborhood.Has(tt.slug))
				assert.True(t, nn.slugToContainers.Has(tt.slug))
			}
		})
	}
}

func Test_deletePod(t *testing.T) {

	tests := []struct {
		obj          *unstructured.Unstructured
		name         string
		containers   []string
		slug         string
		otherSlugs   []string
		shouldDelete bool
	}{
		{
			name:         "delete pod",
			obj:          mocks.GetUnstructured(mocks.TestKindPod, mocks.TestNginx),
			containers:   []string{"b0416f7a782e62badf28e03fc9b82305cd02e9749dc24435d8592fab66349c78"},
			shouldDelete: true,
		},
		{
			name:         "pod not deleted",
			obj:          mocks.GetUnstructured(mocks.TestKindPod, mocks.TestNginx),
			containers:   []string{"blabla"},
			shouldDelete: false,
		},
		{
			name:         "delete pod with slug",
			obj:          mocks.GetUnstructured(mocks.TestKindPod, mocks.TestNginx),
			containers:   []string{"b0416f7a782e62badf28e03fc9b82305cd02e9749dc24435d8592fab66349c78"},
			slug:         "/replicaset-nginx-77b4fdf86c",
			otherSlugs:   []string{"1111111", "222222"},
			shouldDelete: true,
		},
		{
			name:         "delete pod with slug",
			obj:          mocks.GetUnstructured(mocks.TestKindPod, mocks.TestNginx),
			containers:   []string{"b0416f7a782e62badf28e03fc9b82305cd02e9749dc24435d8592fab66349c78"},
			slug:         "/replicaset-nginx-77b4fdf86c",
			shouldDelete: true,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			nn := NewNetworkNeighborhoodCache("", nil)
			for _, i := range tt.otherSlugs {
				nn.slugToContainers.Set(i, mapset.NewSet[string]())
				nn.slugToNetworkNeighborhood.Set(i, &v1beta1.NetworkNeighborhood{})
			}
			if tt.slug != "" {
				nn.slugToContainers.Set(tt.slug, mapset.NewSet[string](tt.containers...))
				nn.slugToNetworkNeighborhood.Set(tt.slug, &v1beta1.NetworkNeighborhood{})
			}

			for i := range tt.containers {
				nn.containerToSlug.Set(tt.containers[i], tt.slug)
			}
			nn.deletePod(tt.obj)

			for i := range tt.containers {
				if tt.shouldDelete {
					assert.False(t, nn.containerToSlug.Has(tt.containers[i]))
				} else {
					assert.True(t, nn.containerToSlug.Has(tt.containers[i]))
				}
			}

			if tt.slug != "" {
				assert.False(t, nn.slugToContainers.Has(tt.slug))
				assert.Equal(t, len(tt.otherSlugs), nn.slugToContainers.Len())
				assert.Equal(t, len(tt.otherSlugs), nn.slugToNetworkNeighborhood.Len())

				if len(tt.otherSlugs) == 0 {
					assert.False(t, nn.slugToContainers.Has(tt.slug))
					assert.False(t, nn.slugToNetworkNeighborhood.Has(tt.slug))
				}
			}
		})
	}
}
func Test_GetNetworkNeighborhood(t *testing.T) {
	type args struct {
		containerID                  string
		slug                         string
		setSlugToNetworkNeighborhood bool
	}
	tests := []struct {
		get      args
		name     string
		pods     []args
		expected bool
	}{
		{
			name: "network neighborhood found",
			pods: []args{
				{
					containerID:                  "1234",
					slug:                         "default/replicaset-nginx-1234",
					setSlugToNetworkNeighborhood: true,
				},
				{
					containerID:                  "9876",
					slug:                         "default/replicaset-collection-1234",
					setSlugToNetworkNeighborhood: true,
				},
			},
			get: args{
				containerID: "1234",
			},
			expected: true,
		},
		{
			name: "network neighborhood not found",
			pods: []args{
				{
					containerID:                  "1234",
					slug:                         "default/replicaset-nginx-1234",
					setSlugToNetworkNeighborhood: true,
				},
				{
					containerID:                  "9876",
					slug:                         "default/replicaset-collection-1234",
					setSlugToNetworkNeighborhood: true,
				},
			},
			get: args{
				containerID: "6789",
			},
			expected: false,
		},
		{
			name: "pod exists but network neighborhood is not",
			pods: []args{
				{
					containerID:                  "1234",
					slug:                         "default/replicaset-nginx-1234",
					setSlugToNetworkNeighborhood: true,
				},
				{
					containerID:                  "9876",
					slug:                         "default/collection",
					setSlugToNetworkNeighborhood: false,
				},
			},
			get: args{
				containerID: "9876",
			},
			expected: false,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			nn := NewNetworkNeighborhoodCache("", k8sinterface.NewKubernetesApiMock())

			for _, c := range tt.pods {
				nn.containerToSlug.Set(c.containerID, c.slug)
				if c.setSlugToNetworkNeighborhood {
					nn.slugToNetworkNeighborhood.Set(c.slug, &v1beta1.NetworkNeighborhood{})
				}
			}

			p := nn.GetNetworkNeighborhood(tt.get.containerID)
			if tt.expected {
				assert.NotNil(t, p)
			} else {
				assert.Nil(t, p)
			}
		})
	}
}
func Test_addNetworkNeighborhood_existing(t *testing.T) {
	type podToSlug struct {
		podName string
		slug    string
	}
	// add single network neighborhood
	tests := []struct {
		obj1         *unstructured.Unstructured
		obj2         *unstructured.Unstructured
		annotations1 map[string]string
		annotations2 map[string]string
		name         string
		pods         []podToSlug
		storeInCache bool
	}{
		{
			name: "network neighborhood already exists",
			obj1: mocks.GetUnstructured(mocks.TestKindNN, mocks.TestNginx),
			obj2: mocks.GetUnstructured(mocks.TestKindNN, mocks.TestNginx),
			pods: []podToSlug{
				{
					podName: "nginx-77b4fdf86c",
					slug:    "/replicaset-nginx-77b4fdf86c",
				},
			},
			storeInCache: true,
		},
		{
			name: "remove network neighborhood",
			obj1: mocks.GetUnstructured(mocks.TestKindNN, mocks.TestNginx),
			obj2: mocks.GetUnstructured(mocks.TestKindNN, mocks.TestNginx),
			pods: []podToSlug{
				{
					podName: "nginx-77b4fdf86c",
					slug:    "/replicaset-nginx-77b4fdf86c",
				},
			},
			annotations1: map[string]string{
				"kubescape.io/status": "completed",
			},
			annotations2: map[string]string{
				"kubescape.io/status": "ready",
			},
			storeInCache: false,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if len(tt.annotations1) != 0 {
				tt.obj1.SetAnnotations(tt.annotations1)
			}
			if len(tt.annotations2) != 0 {
				tt.obj2.SetAnnotations(tt.annotations2)
			}
			k8sClient := k8sinterface.NewKubernetesApiMock()

			var runtimeObjs []runtime.Object

			runtimeObjs = append(runtimeObjs, mocks.UnstructuredToRuntime(tt.obj1))

			k8sClient.DynamicClient = dynamicfake.NewSimpleDynamicClient(scheme.Scheme, runtimeObjs...)

			nn := NewNetworkNeighborhoodCache("", k8sClient)

			// add pods
			for i := range tt.pods {
				nn.containerToSlug.Set(tt.pods[i].podName, tt.pods[i].slug)
				nn.slugToContainers.Set(tt.pods[i].slug, mapset.NewSet(tt.pods[i].podName))
			}

			nn.addNetworkNeighborhood(context.Background(), tt.obj1)
			nn.addNetworkNeighborhood(context.Background(), tt.obj2)

			// test if the network neighborhood is added to the cache
			if tt.storeInCache {
				assert.Equal(t, 1, nn.allNetworkNeighborhoods.Cardinality())
			} else {
				assert.Equal(t, 0, nn.allNetworkNeighborhoods.Cardinality())
			}
		})
	}
}

func Test_unstructuredToNetworkNeighborhood(t *testing.T) {

	tests := []struct {
		obj  *unstructured.Unstructured
		name string
	}{
		{
			name: "nginx network neighborhood",
			obj:  mocks.GetUnstructured(mocks.TestKindNN, mocks.TestNginx),
		},
		{
			name: "collection network neighborhood",
			obj:  mocks.GetUnstructured(mocks.TestKindNN, mocks.TestCollection),
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			p, err := unstructuredToNetworkNeighborhood(tt.obj)
			assert.NoError(t, err)
			assert.Equal(t, tt.obj.GetName(), p.GetName())
			assert.Equal(t, tt.obj.GetLabels(), p.GetLabels())
			assert.Equal(t, tt.obj.GetAnnotations(), p.GetAnnotations())
		})
	}
}

func Test_getNetworkNeighborhood(t *testing.T) {
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
			name: "nginx network neighborhood",
			obj:  mocks.GetUnstructured(mocks.TestKindNN, mocks.TestNginx),
			args: args{
				name: "replicaset-nginx-77b4fdf86c",
			},
			wantErr: false,
		},
		{
			name: "collection network neighborhood",
			obj:  mocks.GetUnstructured(mocks.TestKindNN, mocks.TestCollection),
			args: args{
				name: "replicaset-collection-94c495554",
			},
			wantErr: false,
		},
		{
			name: "collection network neighborhood",
			obj:  mocks.GetUnstructured(mocks.TestKindNN, mocks.TestCollection),
			args: args{
				name: "replicaset-nginx-77b4fdf86c",
			},
			wantErr: true,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			k8sClient := k8sinterface.NewKubernetesApiMock()
			k8sClient.DynamicClient = dynamicfake.NewSimpleDynamicClient(scheme.Scheme, mocks.UnstructuredToRuntime(tt.obj))

			nn := &NetworkNeighborhoodCacheImpl{
				k8sClient: k8sClient,
			}

			a, err := nn.getNetworkNeighborhood("", tt.args.name)
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
	nn := NewNetworkNeighborhoodCache("test-node", nil)

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
func TestGetSlug(t *testing.T) {
	tests := []struct {
		name      string
		obj       *unstructured.Unstructured
		expected  string
		expectErr bool
	}{
		{
			name:      "Test with valid object",
			obj:       mocks.GetUnstructured(mocks.TestKindPod, mocks.TestCollection),
			expected:  "replicaset-collection-94c495554",
			expectErr: false,
		},
		{
			name: "Test with invalid object",
			obj: &unstructured.Unstructured{
				Object: map[string]interface{}{
					"kind": "Unknown",
					"metadata": map[string]interface{}{
						"name": "unknown-1",
					},
				},
			},
			expected:  "",
			expectErr: true,
		},
		{
			name: "Test with object without instanceIDs",
			obj: &unstructured.Unstructured{
				Object: map[string]interface{}{
					"apiVersion": "v1",
					"kind":       "Pod",
					"metadata": map[string]interface{}{
						"name": "unknown-1",
					},
				},
			},
			expected:  "",
			expectErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			tt.obj.SetNamespace("default")
			result, err := getSlug(tt.obj)
			if tt.expectErr {
				assert.Error(t, err)
			} else {
				assert.NoError(t, err)
				assert.Equal(t, tt.expected, result)
			}
		})
	}
}

func Test_addPod(t *testing.T) {

	// add single network neighborhood
	tests := []struct {
		obj                     *unstructured.Unstructured
		name                    string
		addedContainers         []string
		ignoredContainers       []string
		preCreatedNNAnnotations map[string]string
		preCreatedNN            *unstructured.Unstructured // pre created network neighborhoods
		shouldAddToNN           bool
	}{
		{
			name:         "add pod with partial network neighborhood",
			obj:          mocks.GetUnstructured(mocks.TestKindPod, mocks.TestCollection),
			preCreatedNN: mocks.GetUnstructured(mocks.TestKindNN, mocks.TestCollection),
			preCreatedNNAnnotations: map[string]string{
				"kubescape.io/status":     "completed",
				"kubescape.io/completion": "partial",
			},
			shouldAddToNN: false,
			ignoredContainers: []string{
				"2c8cb9f14afc39390c49b53cc21da12c903460ee041839dd705881475ae92c0e",
				"5924eafa8ec13fd5793b0ef8591576f1a3ea9068b6b7a0c45d82829c33779927",
				"6565eafa8ec13fd5793b0ef8591576f1a3ea9068b6b7a0c45d82829c33779234",
				"725fee5efd1881b37157fded3061f2b049f6637e37ee1dcef534273d187b56d4",
				"baacccdd158dd7140c436207c7b3d12d15bd6a4313d59dbf471d835d7f2f8dee",
				"d6926a10223d03aea3da4aef78dbef02efb4c2cebf57cdb3da0ca1fcb4263383",
			},
		},
		{
			name:         "add pod with network neighborhood",
			obj:          mocks.GetUnstructured(mocks.TestKindPod, mocks.TestCollection),
			preCreatedNN: mocks.GetUnstructured(mocks.TestKindNN, mocks.TestCollection),
			preCreatedNNAnnotations: map[string]string{
				"kubescape.io/status":     "completed",
				"kubescape.io/completion": "complete",
			},
			shouldAddToNN: true,
			addedContainers: []string{
				"2c8cb9f14afc39390c49b53cc21da12c903460ee041839dd705881475ae92c0e",
				"5924eafa8ec13fd5793b0ef8591576f1a3ea9068b6b7a0c45d82829c33779927",
				"6565eafa8ec13fd5793b0ef8591576f1a3ea9068b6b7a0c45d82829c33779234",
				"725fee5efd1881b37157fded3061f2b049f6637e37ee1dcef534273d187b56d4",
				"baacccdd158dd7140c436207c7b3d12d15bd6a4313d59dbf471d835d7f2f8dee",
				"d6926a10223d03aea3da4aef78dbef02efb4c2cebf57cdb3da0ca1fcb4263383",
			},
		},
	}
	for i, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if len(tt.preCreatedNNAnnotations) != 0 {
				tt.preCreatedNN.SetAnnotations(tt.preCreatedNNAnnotations)
			}
			namespace := fmt.Sprintf("default-%d", i)
			k8sClient := k8sinterface.NewKubernetesApiMock()

			var runtimeObjs []runtime.Object
			tt.obj.SetNamespace(namespace)
			runtimeObjs = append(runtimeObjs, &corev1.Namespace{ObjectMeta: metav1.ObjectMeta{Name: namespace}})

			tt.preCreatedNN.SetNamespace(namespace)
			runtimeObjs = append(runtimeObjs, mocks.UnstructuredToRuntime(tt.preCreatedNN))
			runtimeObjs = append(runtimeObjs, mocks.UnstructuredToRuntime(tt.obj))

			k8sClient.DynamicClient = dynamicfake.NewSimpleDynamicClient(scheme.Scheme, runtimeObjs...)

			nn := NewNetworkNeighborhoodCache("", k8sClient)

			nn.addNetworkNeighborhood(context.Background(), tt.preCreatedNN)

			nn.addPod(tt.obj)

			// test if the network neighborhood is added to the cache
			assert.Equal(t, 1, nn.allNetworkNeighborhoods.Cardinality())
			assert.True(t, nn.slugToContainers.Has(objectcache.UnstructuredUniqueName(tt.preCreatedNN)))

			c := nn.containerToSlug.Keys()
			slices.Sort(c)
			slices.Sort(tt.addedContainers)

			if tt.shouldAddToNN {
				assert.Equal(t, tt.addedContainers, c)
				for i := range tt.addedContainers {
					assert.NotNil(t, nn.GetNetworkNeighborhood(tt.addedContainers[i]))
				}
			} else {
				assert.Equal(t, tt.addedContainers, c)
				for i := range tt.ignoredContainers {
					assert.Nil(t, nn.GetNetworkNeighborhood(tt.ignoredContainers[i]))
				}
			}
		})
	}
}
