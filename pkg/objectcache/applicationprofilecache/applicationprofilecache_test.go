package applicationprofilecache

import (
	"context"
	"fmt"
	"node-agent/mocks"
	"node-agent/pkg/objectcache"
	"testing"

	"github.com/kubescape/storage/pkg/apis/softwarecomposition/v1beta1"
	corev1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/runtime"
	dynamicfake "k8s.io/client-go/dynamic/fake"

	"k8s.io/client-go/kubernetes/scheme"

	helpersv1 "github.com/kubescape/k8s-interface/instanceidhandler/v1/helpers"
	"github.com/kubescape/k8s-interface/k8sinterface"
	"github.com/stretchr/testify/assert"
	v1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
)

func init() {
	v1beta1.AddToScheme(scheme.Scheme)
	corev1.AddToScheme(scheme.Scheme)
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
				helpersv1.CompletionMetadataKey: helpersv1.Complete,
			},
			shouldAdd: true,
		},
		{
			name: "ignore single application profile with incomplete annotation",
			obj:  mocks.GetUnstructured(mocks.TestKindAP, mocks.TestCollection),
			annotations: map[string]string{
				helpersv1.CompletionMetadataKey: helpersv1.Ready,
			},
			shouldAdd: false,
		},
		{
			name:           "add application profile to pod",
			obj:            mocks.GetUnstructured(mocks.TestKindAP, mocks.TestCollection),
			preCreatedPods: []*unstructured.Unstructured{mocks.GetUnstructured(mocks.TestKindPod, mocks.TestCollection)},
			annotations: map[string]string{
				helpersv1.CompletionMetadataKey: helpersv1.Complete,
			},
			shouldAdd:      true,
			shouldAddToPod: true,
		},
		{
			name:           "add application profile without pod",
			obj:            mocks.GetUnstructured(mocks.TestKindAP, mocks.TestCollection),
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
			runtimeObjs = append(runtimeObjs, &corev1.Namespace{ObjectMeta: v1.ObjectMeta{Name: namespace}})

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
				assert.True(t, ap.slugToAppProfile.Has(apName))
			} else {
				assert.Equal(t, 0, ap.allProfiles.Cardinality())
				assert.False(t, ap.slugToAppProfile.Has(apName))
			}

			if tt.shouldAddToPod {
				assert.True(t, ap.slugToPods.Has(apName))
				for i := range tt.preCreatedPods {
					assert.NotNil(t, ap.GetApplicationProfile(namespace, tt.preCreatedPods[i].GetName()))
				}
			} else {
				assert.False(t, ap.slugToPods.Has(apName))
				for i := range tt.preCreatedPods {
					assert.Nil(t, ap.GetApplicationProfile(namespace, tt.preCreatedPods[i].GetName()))
				}
			}
		})
	}
}

func Test_deleteApplicationProfile(t *testing.T) {

	// add single application profile
	tests := []struct {
		obj            *unstructured.Unstructured
		name           string
		preCreatedPods []*unstructured.Unstructured // pre created pods
	}{
		{
			name: "add single application profile nginx",
			obj:  mocks.GetUnstructured(mocks.TestKindAP, mocks.TestNginx),
		},
		{
			name:           "add application profile to pod",
			obj:            mocks.GetUnstructured(mocks.TestKindAP, mocks.TestCollection),
			preCreatedPods: []*unstructured.Unstructured{mocks.GetUnstructured(mocks.TestKindPod, mocks.TestCollection)},
		},
	}
	for i, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {

			namespace := fmt.Sprintf("default-%d", i)
			k8sClient := k8sinterface.NewKubernetesApiMock()

			var runtimeObjs []runtime.Object
			tt.obj.SetNamespace(namespace)
			runtimeObjs = append(runtimeObjs, &corev1.Namespace{ObjectMeta: v1.ObjectMeta{Name: namespace}})

			for i := range tt.preCreatedPods {
				tt.preCreatedPods[i].SetNamespace(namespace)
				runtimeObjs = append(runtimeObjs, mocks.UnstructuredToRuntime(tt.preCreatedPods[i]))
			}

			runtimeObjs = append(runtimeObjs, mocks.UnstructuredToRuntime(tt.obj))
			k8sClient.DynamicClient = dynamicfake.NewSimpleDynamicClient(scheme.Scheme, runtimeObjs...)

			ap := NewApplicationProfileCache("", k8sClient)

			for i := range tt.preCreatedPods {
				ap.addPod(tt.preCreatedPods[i])
			}

			ap.addApplicationProfile(context.Background(), tt.obj)

			// test if the application profile is added to the cache
			apName := objectcache.UnstructuredUniqueName(tt.obj)

			ap.deleteApplicationProfile(tt.obj)
			assert.Equal(t, 0, ap.allProfiles.Cardinality())
			assert.False(t, ap.slugToAppProfile.Has(apName))
			assert.False(t, ap.slugToPods.Has(apName))
		})
	}
}
func Test_addApplicationProfile_existing(t *testing.T) {

	// add single application profile
	tests := []struct {
		obj1         *unstructured.Unstructured
		obj2         *unstructured.Unstructured
		name         string
		annotations1 map[string]string
		annotations2 map[string]string
		storeInCache bool
	}{
		{
			name:         "application profile already exists",
			obj1:         mocks.GetUnstructured(mocks.TestKindAP, mocks.TestNginx),
			obj2:         mocks.GetUnstructured(mocks.TestKindAP, mocks.TestNginx),
			storeInCache: true,
		},
		{
			name: "remove application profile",
			obj1: mocks.GetUnstructured(mocks.TestKindAP, mocks.TestNginx),
			obj2: mocks.GetUnstructured(mocks.TestKindAP, mocks.TestNginx),
			annotations1: map[string]string{
				helpersv1.CompletionMetadataKey: helpersv1.Complete,
			},
			annotations2: map[string]string{
				helpersv1.CompletionMetadataKey: helpersv1.Ready,
			},
			storeInCache: false,
		},
	}
	for i, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if len(tt.annotations1) != 0 {
				tt.obj1.SetAnnotations(tt.annotations1)
			}
			if len(tt.annotations2) != 0 {
				tt.obj2.SetAnnotations(tt.annotations2)
			}
			namespace := fmt.Sprintf("default-%d", i)
			k8sClient := k8sinterface.NewKubernetesApiMock()

			var runtimeObjs []runtime.Object
			runtimeObjs = append(runtimeObjs, &corev1.Namespace{ObjectMeta: v1.ObjectMeta{Name: namespace}})

			runtimeObjs = append(runtimeObjs, mocks.UnstructuredToRuntime(tt.obj1))

			k8sClient.DynamicClient = dynamicfake.NewSimpleDynamicClient(scheme.Scheme, runtimeObjs...)

			ap := NewApplicationProfileCache("", k8sClient)

			ap.addApplicationProfile(context.Background(), tt.obj1)
			ap.addApplicationProfile(context.Background(), tt.obj2)

			// test if the application profile is added to the cache
			apName := objectcache.UnstructuredUniqueName(tt.obj1)
			if tt.storeInCache {
				assert.Equal(t, 1, ap.allProfiles.Cardinality())
				assert.True(t, ap.slugToAppProfile.Has(apName))
			} else {
				assert.Equal(t, 0, ap.allProfiles.Cardinality())
				assert.False(t, ap.slugToAppProfile.Has(apName))
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
