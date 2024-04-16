package applicationprofilecache

import (
	"context"
	"fmt"
	"node-agent/mocks"
	"node-agent/pkg/objectcache"
	"node-agent/pkg/watcher"
	"slices"
	"testing"

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
		f      func(ap *ApplicationProfileCacheImpl, ctx context.Context, obj *unstructured.Unstructured)
		obj    *unstructured.Unstructured
		name   string
		length int
	}{
		{
			name:   "add application profile",
			obj:    mocks.GetUnstructured(mocks.TestKindAP, mocks.TestNginx),
			f:      (*ApplicationProfileCacheImpl).AddHandler,
			length: 1,
		},
		{
			name:   "add pod",
			obj:    mocks.GetUnstructured(mocks.TestKindPod, mocks.TestCollection),
			f:      (*ApplicationProfileCacheImpl).AddHandler,
			length: 6,
		},
		{
			name:   "modify application profile",
			obj:    mocks.GetUnstructured(mocks.TestKindAP, mocks.TestNginx),
			f:      (*ApplicationProfileCacheImpl).ModifyHandler,
			length: 1,
		},
		{
			name:   "modify pod",
			obj:    mocks.GetUnstructured(mocks.TestKindPod, mocks.TestCollection),
			f:      (*ApplicationProfileCacheImpl).ModifyHandler,
			length: 6,
		},
		{
			name:   "delete application profile",
			obj:    mocks.GetUnstructured(mocks.TestKindAP, mocks.TestNginx),
			f:      (*ApplicationProfileCacheImpl).DeleteHandler,
			length: 0,
		},
		{
			name:   "delete pod",
			obj:    mocks.GetUnstructured(mocks.TestKindPod, mocks.TestCollection),
			f:      (*ApplicationProfileCacheImpl).DeleteHandler,
			length: 0,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			tt.obj.SetNamespace("default")

			k8sClient := k8sinterface.NewKubernetesApiMock()
			ap := NewApplicationProfileCache("", k8sClient)

			tt.f(ap, context.Background(), tt.obj)

			switch mocks.TestKinds(tt.obj.GetKind()) {
			case mocks.TestKindAP:
				assert.Equal(t, tt.length, ap.allProfiles.Cardinality())
			case mocks.TestKindPod:
				assert.Equal(t, tt.length, ap.containerToSlug.Len())
			}
		})
	}
}

func Test_addApplicationProfile(t *testing.T) {

	// add single application profile
	tests := []struct {
		obj            *unstructured.Unstructured
		name           string
		annotations    map[string]string
		preCreatedPods []*unstructured.Unstructured // pre created pods
		preCreatedAP   []*unstructured.Unstructured // pre created application profiles
		shouldAdd      bool
		shouldAddToPod bool
	}{
		{
			name: "add single application profile nginx",
			obj:  mocks.GetUnstructured(mocks.TestKindAP, mocks.TestNginx),
			annotations: map[string]string{
				"kubescape.io/status":     "completed",
				"kubescape.io/completion": "complete",
			},
			shouldAdd: true,
		},
		{
			name: "add application profile with partial annotation",
			obj:  mocks.GetUnstructured(mocks.TestKindAP, mocks.TestCollection),
			annotations: map[string]string{
				"kubescape.io/status":     "completed",
				"kubescape.io/completion": "partial",
			},
			shouldAdd: true,
		},
		{
			name: "ignore single application profile with incomplete annotation",
			obj:  mocks.GetUnstructured(mocks.TestKindAP, mocks.TestCollection),
			annotations: map[string]string{
				"kubescape.io/status":     "ready",
				"kubescape.io/completion": "complete",
			},
			shouldAdd: false,
		},
		{
			name:           "add application profile to pod",
			obj:            mocks.GetUnstructured(mocks.TestKindAP, mocks.TestCollection),
			preCreatedPods: []*unstructured.Unstructured{mocks.GetUnstructured(mocks.TestKindPod, mocks.TestCollection)},
			annotations: map[string]string{
				"kubescape.io/status":     "completed",
				"kubescape.io/completion": "complete",
			},
			shouldAdd:      true,
			shouldAddToPod: true,
		},
		{
			name:           "add application profile without pod",
			obj:            mocks.GetUnstructured(mocks.TestKindAP, mocks.TestCollection),
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

			ap := NewApplicationProfileCache("", k8sClient)

			for i := range tt.preCreatedPods {
				ap.addPod(tt.preCreatedPods[i])
			}
			for i := range tt.preCreatedAP {
				ap.addApplicationProfile(context.Background(), tt.preCreatedAP[i])
			}

			ap.addApplicationProfile(context.Background(), tt.obj)

			// test if the application profile is added to the cache
			apName := objectcache.UnstructuredUniqueName(tt.obj)
			if tt.shouldAdd {
				assert.Equal(t, 1, ap.allProfiles.Cardinality())
			} else {
				assert.Equal(t, 0, ap.allProfiles.Cardinality())
			}

			if tt.shouldAddToPod {
				assert.True(t, ap.slugToContainers.Has(apName))
				assert.True(t, ap.slugToAppProfile.Has(apName))
				for i := range tt.preCreatedPods {
					p, _ := objectcache.UnstructuredToPod(tt.preCreatedPods[i])
					for _, c := range objectcache.ListContainersIDs(p) {
						assert.NotNil(t, ap.GetApplicationProfile(c))
					}
				}
			} else {
				assert.False(t, ap.slugToContainers.Has(apName))
				assert.False(t, ap.slugToAppProfile.Has(apName))
				for i := range tt.preCreatedPods {
					p, _ := objectcache.UnstructuredToPod(tt.preCreatedPods[i])
					for _, c := range objectcache.ListContainersIDs(p) {
						assert.Nil(t, ap.GetApplicationProfile(c))
					}
				}
			}
		})
	}
}
func Test_deleteApplicationProfile(t *testing.T) {

	tests := []struct {
		obj          *unstructured.Unstructured
		name         string
		slug         string
		slugs        []string
		shouldDelete bool
	}{
		{
			name:         "delete application profile nginx",
			obj:          mocks.GetUnstructured(mocks.TestKindAP, mocks.TestNginx),
			slug:         "/replicaset-nginx-77b4fdf86c",
			slugs:        []string{"/replicaset-nginx-77b4fdf86c"},
			shouldDelete: true,
		},
		{
			name:         "delete application profile from many",
			obj:          mocks.GetUnstructured(mocks.TestKindAP, mocks.TestNginx),
			slug:         "/replicaset-nginx-77b4fdf86c",
			slugs:        []string{"/replicaset-nginx-11111", "/replicaset-nginx-77b4fdf86c", "/replicaset-nginx-22222"},
			shouldDelete: true,
		},
		{
			name:         "ignore delete application profile nginx",
			obj:          mocks.GetUnstructured(mocks.TestKindAP, mocks.TestCollection),
			slug:         "/replicaset-nginx-77b4fdf86c",
			slugs:        []string{"/replicaset-nginx-77b4fdf86c"},
			shouldDelete: false,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ap := NewApplicationProfileCache("", nil)

			ap.allProfiles.Append(tt.slugs...)
			for _, i := range tt.slugs {
				ap.slugToAppProfile.Set(i, &v1beta1.ApplicationProfile{})
				ap.slugToContainers.Set(i, nil)
			}

			ap.deleteApplicationProfile(tt.obj)

			if tt.shouldDelete {
				assert.Equal(t, len(tt.slugs)-1, ap.allProfiles.Cardinality())
				assert.False(t, ap.slugToAppProfile.Has(tt.slug))
				assert.True(t, ap.slugToContainers.Has(tt.slug)) // this field should not be deleted
			} else {
				assert.Equal(t, len(tt.slugs), ap.allProfiles.Cardinality())
				assert.True(t, ap.slugToAppProfile.Has(tt.slug))
				assert.True(t, ap.slugToContainers.Has(tt.slug))
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
			containers:   []string{"containerd://b0416f7a782e62badf28e03fc9b82305cd02e9749dc24435d8592fab66349c78"},
			shouldDelete: true,
		},
		{
			name:         "pod not deleted",
			obj:          mocks.GetUnstructured(mocks.TestKindPod, mocks.TestNginx),
			containers:   []string{"containerd://blabla"},
			shouldDelete: false,
		},
		{
			name:         "delete pod with slug",
			obj:          mocks.GetUnstructured(mocks.TestKindPod, mocks.TestNginx),
			containers:   []string{"containerd://b0416f7a782e62badf28e03fc9b82305cd02e9749dc24435d8592fab66349c78"},
			slug:         "/replicaset-nginx-77b4fdf86c",
			otherSlugs:   []string{"1111111", "222222"},
			shouldDelete: true,
		},
		{
			name:         "delete pod with slug",
			obj:          mocks.GetUnstructured(mocks.TestKindPod, mocks.TestNginx),
			containers:   []string{"containerd://b0416f7a782e62badf28e03fc9b82305cd02e9749dc24435d8592fab66349c78"},
			slug:         "/replicaset-nginx-77b4fdf86c",
			shouldDelete: true,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ap := NewApplicationProfileCache("", nil)
			for _, i := range tt.otherSlugs {
				ap.slugToContainers.Set(i, mapset.NewSet[string]())
				ap.slugToAppProfile.Set(i, &v1beta1.ApplicationProfile{})
			}
			if tt.slug != "" {
				ap.slugToContainers.Set(tt.slug, mapset.NewSet[string](tt.containers...))
				ap.slugToAppProfile.Set(tt.slug, &v1beta1.ApplicationProfile{})
			}

			for i := range tt.containers {
				ap.containerToSlug.Set(tt.containers[i], tt.slug)
			}
			ap.deletePod(tt.obj)

			for i := range tt.containers {
				if tt.shouldDelete {
					assert.False(t, ap.containerToSlug.Has(tt.containers[i]))
				} else {
					assert.True(t, ap.containerToSlug.Has(tt.containers[i]))
				}
			}

			if tt.slug != "" {
				assert.False(t, ap.slugToContainers.Has(tt.slug))
				assert.Equal(t, len(tt.otherSlugs), ap.slugToContainers.Len())
				assert.Equal(t, len(tt.otherSlugs), ap.slugToAppProfile.Len())

				if len(tt.otherSlugs) == 0 {
					assert.False(t, ap.slugToContainers.Has(tt.slug))
					assert.False(t, ap.slugToAppProfile.Has(tt.slug))
				}
			}
		})
	}
}
func Test_GetApplicationProfile(t *testing.T) {
	type args struct {
		containerID         string
		slug                string
		setSlugToAppProfile bool
	}
	tests := []struct {
		get      args
		name     string
		pods     []args
		expected bool
	}{
		{
			name: "application profile found",
			pods: []args{
				{
					containerID:         "1234",
					slug:                "default/replicaset-nginx-1234",
					setSlugToAppProfile: true,
				},
				{
					containerID:         "9876",
					slug:                "default/replicaset-collection-1234",
					setSlugToAppProfile: true,
				},
			},
			get: args{
				containerID: "1234",
			},
			expected: true,
		},
		{
			name: "application profile not found",
			pods: []args{
				{
					containerID:         "1234",
					slug:                "default/replicaset-nginx-1234",
					setSlugToAppProfile: true,
				},
				{
					containerID:         "9876",
					slug:                "default/replicaset-collection-1234",
					setSlugToAppProfile: true,
				},
			},
			get: args{
				containerID: "6789",
			},
			expected: false,
		},
		{
			name: "pod exists but application profile is not",
			pods: []args{
				{
					containerID:         "1234",
					slug:                "default/replicaset-nginx-1234",
					setSlugToAppProfile: true,
				},
				{
					containerID:         "9876",
					slug:                "default/collection",
					setSlugToAppProfile: false,
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
			ap := NewApplicationProfileCache("", k8sinterface.NewKubernetesApiMock())

			for _, c := range tt.pods {
				ap.containerToSlug.Set(c.containerID, c.slug)
				if c.setSlugToAppProfile {
					ap.slugToAppProfile.Set(c.slug, &v1beta1.ApplicationProfile{})
				}
			}

			p := ap.GetApplicationProfile(tt.get.containerID)
			if tt.expected {
				assert.NotNil(t, p)
			} else {
				assert.Nil(t, p)
			}
		})
	}
}
func Test_addApplicationProfile_existing(t *testing.T) {
	type podToSlug struct {
		podName string
		slug    string
	}
	// add single application profile
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
			name: "application profile already exists",
			obj1: mocks.GetUnstructured(mocks.TestKindAP, mocks.TestNginx),
			obj2: mocks.GetUnstructured(mocks.TestKindAP, mocks.TestNginx),
			pods: []podToSlug{
				{
					podName: "nginx-77b4fdf86c",
					slug:    "/replicaset-nginx-77b4fdf86c",
				},
			},
			storeInCache: true,
		},
		{
			name: "remove application profile",
			obj1: mocks.GetUnstructured(mocks.TestKindAP, mocks.TestNginx),
			obj2: mocks.GetUnstructured(mocks.TestKindAP, mocks.TestNginx),
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

			ap := NewApplicationProfileCache("", k8sClient)

			// add pods
			for i := range tt.pods {
				ap.containerToSlug.Set(tt.pods[i].podName, tt.pods[i].slug)
				ap.slugToContainers.Set(tt.pods[i].slug, mapset.NewSet(tt.pods[i].podName))
			}

			ap.addApplicationProfile(context.Background(), tt.obj1)
			ap.addApplicationProfile(context.Background(), tt.obj2)

			// test if the application profile is added to the cache
			if tt.storeInCache {
				assert.Equal(t, 1, ap.allProfiles.Cardinality())
			} else {
				assert.Equal(t, 0, ap.allProfiles.Cardinality())
			}
		})
	}
}

func Test_unstructuredToApplicationProfile(t *testing.T) {

	tests := []struct {
		obj  *unstructured.Unstructured
		name string
	}{
		{
			name: "nginx application profile",
			obj:  mocks.GetUnstructured(mocks.TestKindAP, mocks.TestNginx),
		},
		{
			name: "collection application profile",
			obj:  mocks.GetUnstructured(mocks.TestKindAP, mocks.TestCollection),
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			p, err := unstructuredToApplicationProfile(tt.obj)
			assert.NoError(t, err)
			assert.Equal(t, tt.obj.GetName(), p.GetName())
			assert.Equal(t, tt.obj.GetLabels(), p.GetLabels())
			assert.Equal(t, tt.obj.GetAnnotations(), p.GetAnnotations())
		})
	}
}

func Test_getApplicationProfile(t *testing.T) {
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
			name: "nginx application profile",
			obj:  mocks.GetUnstructured(mocks.TestKindAP, mocks.TestNginx),
			args: args{
				name: "replicaset-nginx-77b4fdf86c",
			},
			wantErr: false,
		},
		{
			name: "collection application profile",
			obj:  mocks.GetUnstructured(mocks.TestKindAP, mocks.TestCollection),
			args: args{
				name: "replicaset-collection-94c495554",
			},
			wantErr: false,
		},
		{
			name: "collection application profile",
			obj:  mocks.GetUnstructured(mocks.TestKindAP, mocks.TestCollection),
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

			ap := &ApplicationProfileCacheImpl{
				k8sClient: k8sClient,
			}

			a, err := ap.getApplicationProfile("", tt.args.name)
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
	ap := NewApplicationProfileCache("test-node", nil)

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

	watchResources := ap.WatchResources()
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

	// add single application profile
	tests := []struct {
		obj                     *unstructured.Unstructured
		name                    string
		addedContainers         []string
		ignoredContainers       []string
		preCreatedAPAnnotations map[string]string
		preCreatedAP            *unstructured.Unstructured // pre created application profiles
		shouldAddToProfile      bool
	}{
		{
			name:         "add pod with partial application profile",
			obj:          mocks.GetUnstructured(mocks.TestKindPod, mocks.TestCollection),
			preCreatedAP: mocks.GetUnstructured(mocks.TestKindAP, mocks.TestCollection),
			preCreatedAPAnnotations: map[string]string{
				"kubescape.io/status":     "completed",
				"kubescape.io/completion": "partial",
			},
			shouldAddToProfile: false,
			ignoredContainers: []string{
				"containerd://2c8cb9f14afc39390c49b53cc21da12c903460ee041839dd705881475ae92c0e",
				"containerd://5924eafa8ec13fd5793b0ef8591576f1a3ea9068b6b7a0c45d82829c33779927",
				"containerd://6565eafa8ec13fd5793b0ef8591576f1a3ea9068b6b7a0c45d82829c33779234",
				"containerd://725fee5efd1881b37157fded3061f2b049f6637e37ee1dcef534273d187b56d4",
				"containerd://baacccdd158dd7140c436207c7b3d12d15bd6a4313d59dbf471d835d7f2f8dee",
				"containerd://d6926a10223d03aea3da4aef78dbef02efb4c2cebf57cdb3da0ca1fcb4263383",
			},
		},
		{
			name:         "add pod with application profile",
			obj:          mocks.GetUnstructured(mocks.TestKindPod, mocks.TestCollection),
			preCreatedAP: mocks.GetUnstructured(mocks.TestKindAP, mocks.TestCollection),
			preCreatedAPAnnotations: map[string]string{
				"kubescape.io/status":     "completed",
				"kubescape.io/completion": "complete",
			},
			shouldAddToProfile: true,
			addedContainers: []string{
				"containerd://2c8cb9f14afc39390c49b53cc21da12c903460ee041839dd705881475ae92c0e",
				"containerd://5924eafa8ec13fd5793b0ef8591576f1a3ea9068b6b7a0c45d82829c33779927",
				"containerd://6565eafa8ec13fd5793b0ef8591576f1a3ea9068b6b7a0c45d82829c33779234",
				"containerd://725fee5efd1881b37157fded3061f2b049f6637e37ee1dcef534273d187b56d4",
				"containerd://baacccdd158dd7140c436207c7b3d12d15bd6a4313d59dbf471d835d7f2f8dee",
				"containerd://d6926a10223d03aea3da4aef78dbef02efb4c2cebf57cdb3da0ca1fcb4263383",
			},
		},
	}
	for i, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if len(tt.preCreatedAPAnnotations) != 0 {
				tt.preCreatedAP.SetAnnotations(tt.preCreatedAPAnnotations)
			}
			namespace := fmt.Sprintf("default-%d", i)
			k8sClient := k8sinterface.NewKubernetesApiMock()

			var runtimeObjs []runtime.Object
			tt.obj.SetNamespace(namespace)
			runtimeObjs = append(runtimeObjs, &corev1.Namespace{ObjectMeta: metav1.ObjectMeta{Name: namespace}})

			tt.preCreatedAP.SetNamespace(namespace)
			runtimeObjs = append(runtimeObjs, mocks.UnstructuredToRuntime(tt.preCreatedAP))
			runtimeObjs = append(runtimeObjs, mocks.UnstructuredToRuntime(tt.obj))

			k8sClient.DynamicClient = dynamicfake.NewSimpleDynamicClient(scheme.Scheme, runtimeObjs...)

			ap := NewApplicationProfileCache("", k8sClient)

			ap.addApplicationProfile(context.Background(), tt.preCreatedAP)

			ap.addPod(tt.obj)

			// test if the application profile is added to the cache
			assert.Equal(t, 1, ap.allProfiles.Cardinality())
			assert.True(t, ap.slugToContainers.Has(objectcache.UnstructuredUniqueName(tt.preCreatedAP)))

			c := ap.containerToSlug.Keys()
			slices.Sort(c)
			slices.Sort(tt.addedContainers)

			if tt.shouldAddToProfile {
				assert.Equal(t, tt.addedContainers, c)
				for i := range tt.addedContainers {
					assert.NotNil(t, ap.GetApplicationProfile(tt.addedContainers[i]))
				}
			} else {
				assert.Equal(t, tt.addedContainers, c)
				for i := range tt.ignoredContainers {
					assert.Nil(t, ap.GetApplicationProfile(tt.ignoredContainers[i]))
				}
			}
		})
	}
}
