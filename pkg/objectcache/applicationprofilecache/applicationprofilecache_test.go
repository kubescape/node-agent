package applicationprofilecache

import (
	"context"
	"fmt"
	"slices"
	"testing"
	"time"

	mapset "github.com/deckarep/golang-set/v2"
	"github.com/kubescape/node-agent/mocks"
	"github.com/kubescape/node-agent/pkg/objectcache"
	"github.com/kubescape/node-agent/pkg/watcher"
	"github.com/kubescape/storage/pkg/apis/softwarecomposition/v1beta1"
	"github.com/kubescape/storage/pkg/generated/clientset/versioned/fake"
	"github.com/stretchr/testify/assert"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/runtime/schema"
	"k8s.io/client-go/kubernetes/scheme"
)

func init() {
	v1beta1.AddToScheme(scheme.Scheme)
	corev1.AddToScheme(scheme.Scheme)
}

func Test_AddHandlers(t *testing.T) {

	tests := []struct {
		f      func(ap *ApplicationProfileCacheImpl, ctx context.Context, obj runtime.Object)
		obj    runtime.Object
		name   string
		slug   string
		length int
	}{
		{
			name:   "add application profile",
			obj:    mocks.GetRuntime(mocks.TestKindAP, mocks.TestNginx),
			f:      (*ApplicationProfileCacheImpl).AddHandler,
			slug:   "default/replicaset-nginx-77b4fdf86c",
			length: 1,
		},
		{
			name:   "add pod",
			obj:    mocks.GetRuntime(mocks.TestKindPod, mocks.TestCollection),
			f:      (*ApplicationProfileCacheImpl).AddHandler,
			slug:   "default/replicaset-collection-94c495554",
			length: 6,
		},
		{
			name:   "modify application profile",
			obj:    mocks.GetRuntime(mocks.TestKindAP, mocks.TestNginx),
			f:      (*ApplicationProfileCacheImpl).ModifyHandler,
			length: 1,
		},
		{
			name:   "modify pod",
			obj:    mocks.GetRuntime(mocks.TestKindPod, mocks.TestCollection),
			f:      (*ApplicationProfileCacheImpl).ModifyHandler,
			slug:   "default/replicaset-collection-94c495554",
			length: 6,
		},
		{
			name:   "delete application profile",
			obj:    mocks.GetRuntime(mocks.TestKindAP, mocks.TestNginx),
			f:      (*ApplicationProfileCacheImpl).DeleteHandler,
			slug:   "default/replicaset-nginx-77b4fdf86c",
			length: 0,
		},
		{
			name:   "delete pod",
			obj:    mocks.GetRuntime(mocks.TestKindPod, mocks.TestCollection),
			f:      (*ApplicationProfileCacheImpl).DeleteHandler,
			slug:   "default/replicaset-collection-94c495554",
			length: 0,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			tt.obj.(metav1.Object).SetNamespace("default")
			storageClient := fake.NewSimpleClientset().SpdxV1beta1()
			ap := NewApplicationProfileCache("", storageClient, 0)
			ap.slugToContainers.Set(tt.slug, mapset.NewSet[string]())

			tt.f(ap, context.Background(), tt.obj)

			switch mocks.TestKinds(tt.obj.GetObjectKind().GroupVersionKind().Kind) {
			case mocks.TestKindAP:
				assert.Equal(t, tt.length, ap.allProfiles.Cardinality())
			case mocks.TestKindPod:
				assert.Equal(t, tt.length, ap.slugToContainers.Get(tt.slug).Cardinality())
			}
		})
	}
}

func Test_addApplicationProfile(t *testing.T) {

	// add single application profile
	tests := []struct {
		obj            runtime.Object
		name           string
		annotations    map[string]string
		preCreatedPods []runtime.Object // pre created pods
		preCreatedAP   []runtime.Object // pre created application profiles
		shouldAdd      bool
		shouldAddToPod bool
	}{
		{
			name: "add single application profile nginx",
			obj:  mocks.GetRuntime(mocks.TestKindAP, mocks.TestNginx),
			annotations: map[string]string{
				"kubescape.io/status":     "completed",
				"kubescape.io/completion": "complete",
			},
			shouldAdd: true,
		},
		{
			name: "add application profile with partial annotation",
			obj:  mocks.GetRuntime(mocks.TestKindAP, mocks.TestCollection),
			annotations: map[string]string{
				"kubescape.io/status":     "completed",
				"kubescape.io/completion": "partial",
			},
			shouldAdd: true,
		},
		{
			name: "ignore single application profile with incomplete annotation",
			obj:  mocks.GetRuntime(mocks.TestKindAP, mocks.TestCollection),
			annotations: map[string]string{
				"kubescape.io/status":     "ready",
				"kubescape.io/completion": "complete",
			},
			shouldAdd: false,
		},
		{
			name:           "add application profile to pod",
			obj:            mocks.GetRuntime(mocks.TestKindAP, mocks.TestCollection),
			preCreatedPods: []runtime.Object{mocks.GetRuntime(mocks.TestKindPod, mocks.TestCollection)},
			annotations: map[string]string{
				"kubescape.io/status":     "completed",
				"kubescape.io/completion": "complete",
			},
			shouldAdd:      true,
			shouldAddToPod: true,
		},
		{
			name:           "add application profile without pod",
			obj:            mocks.GetRuntime(mocks.TestKindAP, mocks.TestCollection),
			preCreatedPods: []runtime.Object{mocks.GetRuntime(mocks.TestKindPod, mocks.TestNginx)},
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
				tt.obj.(metav1.Object).SetAnnotations(tt.annotations)
			}
			namespace := fmt.Sprintf("default-%d", i)

			var runtimeObjs []runtime.Object

			for i := range tt.preCreatedPods {
				tt.preCreatedPods[i].(metav1.Object).SetNamespace(namespace)
			}
			for i := range tt.preCreatedAP {
				tt.preCreatedAP[i].(metav1.Object).SetNamespace(namespace)
				runtimeObjs = append(runtimeObjs, tt.preCreatedAP[i])
			}

			tt.obj.(metav1.Object).SetNamespace(namespace)
			runtimeObjs = append(runtimeObjs, tt.obj)

			storageClient := fake.NewSimpleClientset(runtimeObjs...).SpdxV1beta1()

			ap := NewApplicationProfileCache("", storageClient, 0)

			for i := range tt.preCreatedPods {
				ap.addPod(tt.preCreatedPods[i])
			}
			for i := range tt.preCreatedAP {
				ap.addApplicationProfile(tt.preCreatedAP[i])
			}

			ap.addApplicationProfile(tt.obj)
			time.Sleep(1 * time.Second) // add is async

			// test if the application profile is added to the cache
			apName := objectcache.MetaUniqueName(tt.obj.(metav1.Object))
			if tt.shouldAdd {
				assert.Equal(t, 1, ap.allProfiles.Cardinality())
			} else {
				assert.Equal(t, 0, ap.allProfiles.Cardinality())
			}

			if tt.shouldAddToPod {
				assert.True(t, ap.slugToContainers.Has(apName))
				assert.True(t, ap.slugToAppProfile.Has(apName))
				for i := range tt.preCreatedPods {
					p := tt.preCreatedPods[i].(*corev1.Pod)
					for _, c := range objectcache.ListContainersIDs(p) {
						assert.NotNil(t, ap.GetApplicationProfile(c))
					}
				}
			} else {
				assert.False(t, ap.slugToContainers.Has(apName))
				assert.False(t, ap.slugToAppProfile.Has(apName))
				for i := range tt.preCreatedPods {
					p := tt.preCreatedPods[i].(*corev1.Pod)
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
		obj          runtime.Object
		name         string
		slug         string
		slugs        []string
		shouldDelete bool
	}{
		{
			name:         "delete application profile nginx",
			obj:          mocks.GetRuntime(mocks.TestKindAP, mocks.TestNginx),
			slug:         "/replicaset-nginx-77b4fdf86c",
			slugs:        []string{"/replicaset-nginx-77b4fdf86c"},
			shouldDelete: true,
		},
		{
			name:         "delete application profile from many",
			obj:          mocks.GetRuntime(mocks.TestKindAP, mocks.TestNginx),
			slug:         "/replicaset-nginx-77b4fdf86c",
			slugs:        []string{"/replicaset-nginx-11111", "/replicaset-nginx-77b4fdf86c", "/replicaset-nginx-22222"},
			shouldDelete: true,
		},
		{
			name:         "ignore delete application profile nginx",
			obj:          mocks.GetRuntime(mocks.TestKindAP, mocks.TestCollection),
			slug:         "/replicaset-nginx-77b4fdf86c",
			slugs:        []string{"/replicaset-nginx-77b4fdf86c"},
			shouldDelete: false,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ap := NewApplicationProfileCache("", nil, 0)

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
		obj          runtime.Object
		name         string
		containers   []string
		slug         string
		otherSlugs   []string
		shouldDelete bool
	}{
		{
			name:         "delete pod",
			obj:          mocks.GetRuntime(mocks.TestKindPod, mocks.TestNginx),
			containers:   []string{"b0416f7a782e62badf28e03fc9b82305cd02e9749dc24435d8592fab66349c78"},
			shouldDelete: true,
		},
		{
			name:         "pod not deleted",
			obj:          mocks.GetRuntime(mocks.TestKindPod, mocks.TestNginx),
			containers:   []string{"blabla"},
			shouldDelete: false,
		},
		{
			name:         "delete pod with slug",
			obj:          mocks.GetRuntime(mocks.TestKindPod, mocks.TestNginx),
			containers:   []string{"b0416f7a782e62badf28e03fc9b82305cd02e9749dc24435d8592fab66349c78"},
			slug:         "/replicaset-nginx-77b4fdf86c",
			otherSlugs:   []string{"1111111", "222222"},
			shouldDelete: true,
		},
		{
			name:         "delete pod with slug",
			obj:          mocks.GetRuntime(mocks.TestKindPod, mocks.TestNginx),
			containers:   []string{"b0416f7a782e62badf28e03fc9b82305cd02e9749dc24435d8592fab66349c78"},
			slug:         "/replicaset-nginx-77b4fdf86c",
			shouldDelete: true,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ap := NewApplicationProfileCache("", nil, 0)
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
			ap := NewApplicationProfileCache("", fake.NewSimpleClientset().SpdxV1beta1(), 0)

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
		obj1         runtime.Object
		obj2         runtime.Object
		annotations1 map[string]string
		annotations2 map[string]string
		name         string
		pods         []podToSlug
		storeInCache bool
	}{
		{
			name: "application profile already exists",
			obj1: mocks.GetRuntime(mocks.TestKindAP, mocks.TestNginx),
			obj2: mocks.GetRuntime(mocks.TestKindAP, mocks.TestNginx),
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
			obj1: mocks.GetRuntime(mocks.TestKindAP, mocks.TestNginx),
			obj2: mocks.GetRuntime(mocks.TestKindAP, mocks.TestNginx),
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
				tt.obj1.(metav1.Object).SetAnnotations(tt.annotations1)
			}
			if len(tt.annotations2) != 0 {
				tt.obj2.(metav1.Object).SetAnnotations(tt.annotations2)
			}

			var runtimeObjs []runtime.Object

			runtimeObjs = append(runtimeObjs, tt.obj1)

			storageClient := fake.NewSimpleClientset(runtimeObjs...).SpdxV1beta1()

			ap := NewApplicationProfileCache("", storageClient, 0)

			// add pods
			for i := range tt.pods {
				ap.containerToSlug.Set(tt.pods[i].podName, tt.pods[i].slug)
				ap.slugToContainers.Set(tt.pods[i].slug, mapset.NewSet(tt.pods[i].podName))
			}

			ap.addApplicationProfile(tt.obj1)
			time.Sleep(1 * time.Second) // add is async
			ap.addApplicationProfile(tt.obj2)

			// test if the application profile is added to the cache
			if tt.storeInCache {
				assert.Equal(t, 1, ap.allProfiles.Cardinality())
			} else {
				assert.Equal(t, 0, ap.allProfiles.Cardinality())
			}
		})
	}
}

func Test_getApplicationProfile(t *testing.T) {
	type args struct {
		name string
	}
	tests := []struct {
		name    string
		obj     runtime.Object
		args    args
		wantErr bool
	}{
		{
			name: "nginx application profile",
			obj:  mocks.GetRuntime(mocks.TestKindAP, mocks.TestNginx),
			args: args{
				name: "replicaset-nginx-77b4fdf86c",
			},
			wantErr: false,
		},
		{
			name: "collection application profile",
			obj:  mocks.GetRuntime(mocks.TestKindAP, mocks.TestCollection),
			args: args{
				name: "replicaset-collection-94c495554",
			},
			wantErr: false,
		},
		{
			name: "collection application profile",
			obj:  mocks.GetRuntime(mocks.TestKindAP, mocks.TestCollection),
			args: args{
				name: "replicaset-nginx-77b4fdf86c",
			},
			wantErr: true,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			storageClient := fake.NewSimpleClientset(tt.obj).SpdxV1beta1()

			ap := &ApplicationProfileCacheImpl{
				storageClient: storageClient,
			}

			a, err := ap.getApplicationProfile("", tt.args.name)
			if tt.wantErr {
				assert.Error(t, err)
				return
			}
			assert.NoError(t, err)
			assert.Equal(t, tt.obj.(metav1.Object).GetName(), a.GetName())
			assert.Equal(t, tt.obj.(metav1.Object).GetLabels(), a.GetLabels())
		})
	}
}

func Test_WatchResources(t *testing.T) {
	ap := NewApplicationProfileCache("test-node", nil, 0)

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
		obj       runtime.Object
		expected  string
		expectErr bool
	}{
		{
			name:      "Test with valid object",
			obj:       mocks.GetRuntime(mocks.TestKindPod, mocks.TestCollection),
			expected:  "replicaset-collection-94c495554",
			expectErr: false,
		},
		{
			name: "Test with object without instanceIDs",
			obj: &corev1.Pod{
				ObjectMeta: metav1.ObjectMeta{
					Name: "unknown-1",
				},
			},
			expected:  "",
			expectErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			tt.obj.(metav1.Object).SetNamespace("default")
			result, err := getSlug(tt.obj.(*corev1.Pod))
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
		obj                     runtime.Object
		name                    string
		addedContainers         []string
		ignoredContainers       []string
		preCreatedAPAnnotations map[string]string
		preCreatedAP            runtime.Object // pre created application profiles
		shouldAddToProfile      bool
	}{
		{
			name:         "add pod with partial application profile",
			obj:          mocks.GetRuntime(mocks.TestKindPod, mocks.TestCollection),
			preCreatedAP: mocks.GetRuntime(mocks.TestKindAP, mocks.TestCollection),
			preCreatedAPAnnotations: map[string]string{
				"kubescape.io/status":     "completed",
				"kubescape.io/completion": "partial",
			},
			shouldAddToProfile: false,
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
			name:         "add pod with application profile",
			obj:          mocks.GetRuntime(mocks.TestKindPod, mocks.TestCollection),
			preCreatedAP: mocks.GetRuntime(mocks.TestKindAP, mocks.TestCollection),
			preCreatedAPAnnotations: map[string]string{
				"kubescape.io/status":     "completed",
				"kubescape.io/completion": "complete",
			},
			shouldAddToProfile: true,
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
			if len(tt.preCreatedAPAnnotations) != 0 {
				tt.preCreatedAP.(metav1.Object).SetAnnotations(tt.preCreatedAPAnnotations)
			}
			namespace := fmt.Sprintf("default-%d", i)

			var runtimeObjs []runtime.Object

			tt.preCreatedAP.(metav1.Object).SetNamespace(namespace)
			runtimeObjs = append(runtimeObjs, tt.preCreatedAP)

			storageClient := fake.NewSimpleClientset(runtimeObjs...).SpdxV1beta1()

			ap := NewApplicationProfileCache("", storageClient, 0)

			ap.addApplicationProfile(tt.preCreatedAP)
			time.Sleep(1 * time.Second) // add is async

			tt.obj.(metav1.Object).SetNamespace(namespace)
			ap.addPod(tt.obj)

			// test if the application profile is added to the cache
			assert.Equal(t, 1, ap.allProfiles.Cardinality())
			assert.True(t, ap.slugToContainers.Has(objectcache.MetaUniqueName(tt.preCreatedAP.(metav1.Object))))

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

func Test_MergeApplicationProfiles(t *testing.T) {
	tests := []struct {
		name           string
		normalProfile  *v1beta1.ApplicationProfile
		userProfile    *v1beta1.ApplicationProfile
		expectedMerged *v1beta1.ApplicationProfile
	}{
		{
			name: "merge profiles with different containers",
			normalProfile: &v1beta1.ApplicationProfile{
				ObjectMeta: metav1.ObjectMeta{
					Name:      "test-profile",
					Namespace: "default",
				},
				Spec: v1beta1.ApplicationProfileSpec{
					Containers: []v1beta1.ApplicationProfileContainer{
						{
							Name: "container1",
							Capabilities: []string{
								"NET_ADMIN",
							},
							Syscalls: []string{
								"open",
								"read",
							},
						},
					},
				},
			},
			userProfile: &v1beta1.ApplicationProfile{
				ObjectMeta: metav1.ObjectMeta{
					Name:      "ug-test-profile", // Added ug- prefix
					Namespace: "default",
					Annotations: map[string]string{
						"kubescape.io/managed-by": "User",
					},
				},
				Spec: v1beta1.ApplicationProfileSpec{
					Containers: []v1beta1.ApplicationProfileContainer{
						{
							Name: "container2",
							Capabilities: []string{
								"SYS_ADMIN",
							},
							Syscalls: []string{
								"write",
							},
						},
					},
				},
			},
			expectedMerged: &v1beta1.ApplicationProfile{
				ObjectMeta: metav1.ObjectMeta{
					Name:      "test-profile", // Keeps original name without ug- prefix
					Namespace: "default",
				},
				Spec: v1beta1.ApplicationProfileSpec{
					Containers: []v1beta1.ApplicationProfileContainer{
						{
							Name: "container1",
							Capabilities: []string{
								"NET_ADMIN",
							},
							Syscalls: []string{
								"open",
								"read",
							},
						},
						{
							Name: "container2",
							Capabilities: []string{
								"SYS_ADMIN",
							},
							Syscalls: []string{
								"write",
							},
						},
					},
				},
			},
		},
		{
			name: "merge profiles with overlapping containers",
			normalProfile: &v1beta1.ApplicationProfile{
				ObjectMeta: metav1.ObjectMeta{
					Name:      "test-profile",
					Namespace: "default",
				},
				Spec: v1beta1.ApplicationProfileSpec{
					Containers: []v1beta1.ApplicationProfileContainer{
						{
							Name: "container1",
							Capabilities: []string{
								"NET_ADMIN",
							},
							Syscalls: []string{
								"open",
							},
							Opens: []v1beta1.OpenCalls{
								{
									Path: "/etc/config",
								},
							},
						},
					},
				},
			},
			userProfile: &v1beta1.ApplicationProfile{
				ObjectMeta: metav1.ObjectMeta{
					Name:      "ug-test-profile", // Added ug- prefix
					Namespace: "default",
					Annotations: map[string]string{
						"kubescape.io/managed-by": "User",
					},
				},
				Spec: v1beta1.ApplicationProfileSpec{
					Containers: []v1beta1.ApplicationProfileContainer{
						{
							Name: "container1",
							Capabilities: []string{
								"SYS_ADMIN",
							},
							Syscalls: []string{
								"write",
							},
							Opens: []v1beta1.OpenCalls{
								{
									Path: "/etc/secret",
								},
							},
						},
					},
				},
			},
			expectedMerged: &v1beta1.ApplicationProfile{
				ObjectMeta: metav1.ObjectMeta{
					Name:      "test-profile", // Keeps original name without ug- prefix
					Namespace: "default",
				},
				Spec: v1beta1.ApplicationProfileSpec{
					Containers: []v1beta1.ApplicationProfileContainer{
						{
							Name: "container1",
							Capabilities: []string{
								"NET_ADMIN",
								"SYS_ADMIN",
							},
							Syscalls: []string{
								"open",
								"write",
							},
							Opens: []v1beta1.OpenCalls{
								{
									Path: "/etc/config",
								},
								{
									Path: "/etc/secret",
								},
							},
						},
					},
				},
			},
		},
		{
			name: "merge profiles with init containers",
			normalProfile: &v1beta1.ApplicationProfile{
				ObjectMeta: metav1.ObjectMeta{
					Name:      "test-profile",
					Namespace: "default",
				},
				Spec: v1beta1.ApplicationProfileSpec{
					InitContainers: []v1beta1.ApplicationProfileContainer{
						{
							Name: "init1",
							Execs: []v1beta1.ExecCalls{
								{
									Path: "mount",
								},
							},
						},
					},
				},
			},
			userProfile: &v1beta1.ApplicationProfile{
				ObjectMeta: metav1.ObjectMeta{
					Name:      "ug-test-profile", // Added ug- prefix
					Namespace: "default",
					Annotations: map[string]string{
						"kubescape.io/managed-by": "User",
					},
				},
				Spec: v1beta1.ApplicationProfileSpec{
					InitContainers: []v1beta1.ApplicationProfileContainer{
						{
							Name: "init1",
							Execs: []v1beta1.ExecCalls{
								{
									Path: "chmod",
								},
							},
							Syscalls: []string{
								"chmod",
							},
						},
					},
				},
			},
			expectedMerged: &v1beta1.ApplicationProfile{
				ObjectMeta: metav1.ObjectMeta{
					Name:      "test-profile", // Keeps original name without ug- prefix
					Namespace: "default",
				},
				Spec: v1beta1.ApplicationProfileSpec{
					InitContainers: []v1beta1.ApplicationProfileContainer{
						{
							Name: "init1",
							Execs: []v1beta1.ExecCalls{
								{
									Path: "mount",
								},
								{
									Path: "chmod",
								},
							},
							Syscalls: []string{
								"chmod",
							},
						},
					},
				},
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			cache := NewApplicationProfileCache("test-node", nil, 0)
			merged := cache.performMerge(tt.normalProfile, tt.userProfile)

			// Verify object metadata
			assert.Equal(t, tt.expectedMerged.Name, merged.Name)
			assert.Equal(t, tt.expectedMerged.Namespace, merged.Namespace)

			// Verify user-managed annotation is removed
			_, hasAnnotation := merged.Annotations["kubescape.io/managed-by"]
			assert.False(t, hasAnnotation)

			// Verify containers
			assert.Equal(t, len(tt.expectedMerged.Spec.Containers), len(merged.Spec.Containers))
			for i, container := range tt.expectedMerged.Spec.Containers {
				assert.Equal(t, container.Name, merged.Spec.Containers[i].Name)
				assert.ElementsMatch(t, container.Capabilities, merged.Spec.Containers[i].Capabilities)
				assert.ElementsMatch(t, container.Syscalls, merged.Spec.Containers[i].Syscalls)
				assert.ElementsMatch(t, container.Opens, merged.Spec.Containers[i].Opens)
				assert.ElementsMatch(t, container.Execs, merged.Spec.Containers[i].Execs)
				assert.ElementsMatch(t, container.Endpoints, merged.Spec.Containers[i].Endpoints)
			}

			// Verify init containers
			assert.Equal(t, len(tt.expectedMerged.Spec.InitContainers), len(merged.Spec.InitContainers))
			for i, container := range tt.expectedMerged.Spec.InitContainers {
				assert.Equal(t, container.Name, merged.Spec.InitContainers[i].Name)
				assert.ElementsMatch(t, container.Capabilities, merged.Spec.InitContainers[i].Capabilities)
				assert.ElementsMatch(t, container.Syscalls, merged.Spec.InitContainers[i].Syscalls)
				assert.ElementsMatch(t, container.Opens, merged.Spec.InitContainers[i].Opens)
				assert.ElementsMatch(t, container.Execs, merged.Spec.InitContainers[i].Execs)
				assert.ElementsMatch(t, container.Endpoints, merged.Spec.InitContainers[i].Endpoints)
			}
		})
	}
}
