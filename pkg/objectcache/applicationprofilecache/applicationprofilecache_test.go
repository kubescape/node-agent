package applicationprofilecache

import (
	"context"
	"fmt"
	"github.com/kubescape/node-agent/mocks"
	"github.com/kubescape/node-agent/pkg/objectcache"
	"github.com/kubescape/node-agent/pkg/watcher"
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
			length: 1,
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
			length: 1,
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
				assert.Equal(t, tt.length, ap.podToSlug.Len())
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
			name:      "add single application profile nginx",
			obj:       mocks.GetUnstructured(mocks.TestKindAP, mocks.TestNginx),
			shouldAdd: true,
		},
		{
			name: "add application profile with complete annotation",
			obj:  mocks.GetUnstructured(mocks.TestKindAP, mocks.TestCollection),
			annotations: map[string]string{
				"kubescape.io/status": "completed",
			},
			shouldAdd: true,
		},
		{
			name: "ignore single application profile with incomplete annotation",
			obj:  mocks.GetUnstructured(mocks.TestKindAP, mocks.TestCollection),
			annotations: map[string]string{
				"kubescape.io/status": "ready",
			},
			shouldAdd: false,
		},
		{
			name:           "add application profile to pod",
			obj:            mocks.GetUnstructured(mocks.TestKindAP, mocks.TestCollection),
			preCreatedPods: []*unstructured.Unstructured{mocks.GetUnstructured(mocks.TestKindPod, mocks.TestCollection)},
			annotations: map[string]string{
				"kubescape.io/status": "completed",
			},
			shouldAdd:      true,
			shouldAddToPod: true,
		},
		{
			name:           "add application profile without pod",
			obj:            mocks.GetUnstructured(mocks.TestKindAP, mocks.TestCollection),
			preCreatedPods: []*unstructured.Unstructured{mocks.GetUnstructured(mocks.TestKindPod, mocks.TestNginx)},
			annotations: map[string]string{
				"kubescape.io/status": "completed",
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
				assert.True(t, ap.slugToPods.Has(apName))
				assert.True(t, ap.slugToAppProfile.Has(apName))
				for i := range tt.preCreatedPods {
					assert.NotNil(t, ap.GetApplicationProfile(namespace, tt.preCreatedPods[i].GetName()))
				}
			} else {
				assert.False(t, ap.slugToPods.Has(apName))
				assert.False(t, ap.slugToAppProfile.Has(apName))
				for i := range tt.preCreatedPods {
					assert.Nil(t, ap.GetApplicationProfile(namespace, tt.preCreatedPods[i].GetName()))
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
				ap.slugToPods.Set(i, nil)
			}

			ap.deleteApplicationProfile(tt.obj)

			if tt.shouldDelete {
				assert.Equal(t, len(tt.slugs)-1, ap.allProfiles.Cardinality())
				assert.False(t, ap.slugToAppProfile.Has(tt.slug))
				assert.True(t, ap.slugToPods.Has(tt.slug)) // this field should not be deleted
			} else {
				assert.Equal(t, len(tt.slugs), ap.allProfiles.Cardinality())
				assert.True(t, ap.slugToAppProfile.Has(tt.slug))
				assert.True(t, ap.slugToPods.Has(tt.slug))
			}
		})
	}
}

func Test_deletePod(t *testing.T) {

	tests := []struct {
		obj          *unstructured.Unstructured
		name         string
		podName      string
		slug         string
		otherSlugs   []string
		shouldDelete bool
	}{
		{
			name:         "delete pod",
			obj:          mocks.GetUnstructured(mocks.TestKindPod, mocks.TestNginx),
			podName:      "/nginx-77b4fdf86c-hp4x5",
			shouldDelete: true,
		},
		{
			name:         "pod not deleted",
			obj:          mocks.GetUnstructured(mocks.TestKindPod, mocks.TestNginx),
			podName:      "blabla",
			shouldDelete: false,
		},
		{
			name:         "delete pod with slug",
			obj:          mocks.GetUnstructured(mocks.TestKindPod, mocks.TestNginx),
			podName:      "/nginx-77b4fdf86c-hp4x5",
			slug:         "/replicaset-nginx-77b4fdf86c",
			otherSlugs:   []string{"1111111", "222222"},
			shouldDelete: true,
		},
		{
			name:         "delete pod with slug",
			obj:          mocks.GetUnstructured(mocks.TestKindPod, mocks.TestNginx),
			podName:      "/nginx-77b4fdf86c-hp4x5",
			slug:         "/replicaset-nginx-77b4fdf86c",
			shouldDelete: true,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ap := NewApplicationProfileCache("", nil)
			for _, i := range tt.otherSlugs {
				ap.slugToPods.Set(i, mapset.NewSet[string]())
				ap.slugToAppProfile.Set(i, &v1beta1.ApplicationProfile{})
			}
			if tt.slug != "" {
				ap.slugToPods.Set(tt.slug, mapset.NewSet[string](tt.podName))
				ap.slugToAppProfile.Set(tt.slug, &v1beta1.ApplicationProfile{})
			}

			ap.podToSlug.Set(tt.podName, tt.slug)

			ap.deletePod(tt.obj)

			if tt.shouldDelete {
				assert.False(t, ap.podToSlug.Has(tt.podName))
			} else {
				assert.True(t, ap.podToSlug.Has(tt.podName))
			}

			if tt.slug != "" {
				assert.False(t, ap.slugToPods.Has(tt.slug))
				assert.Equal(t, len(tt.otherSlugs), ap.slugToPods.Len())
				assert.Equal(t, len(tt.otherSlugs), ap.slugToAppProfile.Len())

				if len(tt.otherSlugs) == 0 {
					assert.False(t, ap.slugToPods.Has(tt.slug))
					assert.False(t, ap.slugToAppProfile.Has(tt.slug))
				}
			}
		})
	}
}
func Test_GetApplicationProfile(t *testing.T) {
	type args struct {
		name      string
		namespace string
		slug      string
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
					name:      "nginx",
					namespace: "default",
					slug:      "default/replicaset-nginx-1234",
				},
				{
					name:      "collection",
					namespace: "default",
					slug:      "default/replicaset-collection-1234",
				},
			},
			get: args{
				name:      "nginx",
				namespace: "default",
			},
			expected: true,
		},
		{
			name: "application profile not found",
			pods: []args{
				{
					name:      "nginx",
					namespace: "default",
					slug:      "default/replicaset-nginx-1234",
				},
				{
					name:      "collection",
					namespace: "default",
					slug:      "default/replicaset-collection-1234",
				},
			},
			get: args{
				name:      "nginx",
				namespace: "collection",
			},
			expected: false,
		},
		{
			name: "pod exists but application profile is not",
			pods: []args{
				{
					name:      "nginx",
					namespace: "default",
					slug:      "default/replicaset-nginx-1234",
				},
				{
					name:      "collection",
					namespace: "default",
					slug:      "",
				},
			},
			get: args{
				name:      "collection",
				namespace: "default",
			},
			expected: false,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ap := NewApplicationProfileCache("", k8sinterface.NewKubernetesApiMock())

			for _, c := range tt.pods {
				n := objectcache.UniqueName(c.namespace, c.name)
				ap.podToSlug.Set(n, c.slug)
				if c.slug != "" {
					ap.slugToAppProfile.Set(c.slug, &v1beta1.ApplicationProfile{})
				}
			}

			p := ap.GetApplicationProfile(tt.get.namespace, tt.get.name)
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
				ap.podToSlug.Set(tt.pods[i].podName, tt.pods[i].slug)
				ap.slugToPods.Set(tt.pods[i].slug, mapset.NewSet(tt.pods[i].podName))
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
func Test_IsCached(t *testing.T) {
	ap := NewApplicationProfileCache("", nil)

	// Add some test data to the cache
	ap.podToSlug.Set("namespace1/pod1", "")
	ap.allProfiles.Add("namespace2/applicationprofile1")

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
			kind:      "ApplicationProfile",
			namespace: "namespace2",
			name:      "applicationprofile1",
			expected:  true,
		},
		{
			kind:      "ApplicationProfile",
			namespace: "namespace2",
			name:      "applicationprofile2",
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
			actual := ap.IsCached(tt.kind, tt.namespace, tt.name)
			assert.Equal(t, tt.expected, actual)
		})
	}
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
