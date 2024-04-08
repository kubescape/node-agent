package dynamicwatcher

import (
	"context"
	"github.com/kubescape/node-agent/mocks"
	"github.com/kubescape/node-agent/pkg/watcher"
	"sync"
	"testing"
	"time"

	"github.com/kubescape/storage/pkg/apis/softwarecomposition/v1beta1"
	appsv1 "k8s.io/api/apps/v1"
	corev1 "k8s.io/api/core/v1"

	"github.com/kubescape/k8s-interface/k8sinterface"
	"github.com/stretchr/testify/assert"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	dynamicfake "k8s.io/client-go/dynamic/fake"
	"k8s.io/client-go/kubernetes/scheme"

	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/runtime/schema"
)

var (
	resourcePod                = schema.GroupVersionResource{Group: "", Version: "v1", Resource: "Pod"}
	resourceNetworkNeighbor    = schema.GroupVersionResource{Group: "spdx.softwarecomposition.kubescape.io", Version: "v1beta1", Resource: "networkneighborses"}
	resourceApplicationProfile = schema.GroupVersionResource{Group: "spdx.softwarecomposition.kubescape.io", Version: "v1beta1", Resource: "applicationprofiles"}
)

func init() {
	v1beta1.AddToScheme(scheme.Scheme)
	corev1.AddToScheme(scheme.Scheme)
	appsv1.AddToScheme(scheme.Scheme)
}

func getGroupVersionResource(obj *unstructured.Unstructured) schema.GroupVersionResource {
	switch obj.GetKind() {
	case "ApplicationProfile":
		return resourceApplicationProfile
	case "NetworkNeighbors":
		return resourceNetworkNeighbor
	default:
		return schema.GroupVersionResource{
			Group:    obj.GetObjectKind().GroupVersionKind().Group,
			Version:  obj.GetObjectKind().GroupVersionKind().Version,
			Resource: obj.GetObjectKind().GroupVersionKind().Kind,
		}
	}
}

type testObj struct {
	name              string
	resources         []schema.GroupVersionResource
	preCreatedObjects []runtime.Object
	createObjects     []*unstructured.Unstructured
	modifiedObjects   []*unstructured.Unstructured
	deleteObjects     []*unstructured.Unstructured
}

func startTest(t *testing.T, tc testObj) {

	ctx := context.Background()

	a := &watcher.AdaptorMock{}
	a.WatcherMock = *watcher.NewWatcherMock()

	for _, v := range tc.resources {
		a.WatchResource = append(a.WatchResource, watcher.WatchResourceMock{Schema: v})
	}

	k8sClient := k8sinterface.NewKubernetesApiMock()
	k8sClient.DynamicClient = dynamicfake.NewSimpleDynamicClient(scheme.Scheme, tc.preCreatedObjects...)

	wh := NewWatchHandler(k8sClient)

	wh.AddAdaptor(a)

	resourcesCreatedWg := &sync.WaitGroup{}
	resourcesModifiedWg := &sync.WaitGroup{}
	resourcesDeleteWg := &sync.WaitGroup{}

	resourcesCreatedWg.Add(len(tc.createObjects) + len(tc.preCreatedObjects))
	resourcesModifiedWg.Add(len(tc.modifiedObjects))
	resourcesDeleteWg.Add(len(tc.deleteObjects))

	wh.Start(ctx)

	createdObj := map[string]*unstructured.Unstructured{}
	modifiedObj := map[string]*unstructured.Unstructured{}
	deleteObj := map[string]*unstructured.Unstructured{}
	l := sync.Mutex{}

	go func() {
		for {
			obj := <-a.WatcherMock.Added
			t.Logf("added object: kind: %s, name: %s\n", obj.GetKind(), obj.GetName())
			l.Lock()
			createdObj[obj.GetKind()+"/"+obj.GetName()] = obj
			resourcesCreatedWg.Done()
			l.Unlock()
		}
	}()
	go func() {
		for obj := range a.WatcherMock.Updated {
			t.Logf("modified object: kind: %s, name: %s\n", obj.GetKind(), obj.GetName())
			l.Lock()
			modifiedObj[obj.GetKind()+"/"+obj.GetName()] = obj
			resourcesModifiedWg.Done()
			l.Unlock()
		}
	}()
	go func() {
		for obj := range a.WatcherMock.Deleted {
			t.Logf("deleted object: kind: %s, name: %s\n", obj.GetKind(), obj.GetName())
			l.Lock()
			deleteObj[obj.GetKind()+"/"+obj.GetName()] = obj
			resourcesDeleteWg.Done()
			l.Unlock()
		}
	}()

	// wait for watcher to start
	time.Sleep(1 * time.Second)

	// cerate objects
	for i := range tc.createObjects {
		if _, err := wh.k8sClient.GetDynamicClient().Resource(getGroupVersionResource(tc.createObjects[i])).Namespace("").Create(ctx, tc.createObjects[i], metav1.CreateOptions{}); err != nil {
			t.Fatalf("error creating object: %v", err)
		}
	}
	resourcesCreatedWg.Wait()
	assert.Equal(t, len(tc.createObjects)+len(tc.preCreatedObjects), len(createdObj))

	for _, o := range tc.createObjects {
		k := o.GetKind() + "/" + o.GetName()
		c, ok := createdObj[k]
		assert.True(t, ok)
		assert.NotNil(t, c)
	}

	// modify objects
	labels := map[string]string{"test": "test"}
	for i := range tc.modifiedObjects {
		tc.modifiedObjects[i].SetLabels(labels)
		if _, err := wh.k8sClient.GetDynamicClient().Resource(getGroupVersionResource(tc.modifiedObjects[i])).Namespace("").Update(ctx, tc.modifiedObjects[i], metav1.UpdateOptions{}); err != nil {
			t.Fatalf("error creating object: %v", err)
		}
	}
	resourcesModifiedWg.Wait()

	assert.Equal(t, len(tc.modifiedObjects), len(modifiedObj))
	for _, o := range tc.modifiedObjects {
		k := o.GetKind() + "/" + o.GetName()
		c, ok := modifiedObj[k]
		assert.True(t, ok)
		assert.NotNil(t, c)
		assert.Equal(t, labels, o.GetLabels())
	}

	// delete objects
	for i := range tc.deleteObjects {
		if err := wh.k8sClient.GetDynamicClient().Resource(getGroupVersionResource(tc.deleteObjects[i])).Namespace("").Delete(ctx, tc.deleteObjects[i].GetName(), metav1.DeleteOptions{}); err != nil {
			t.Fatalf("error creating object: %v", err)
		}
	}
	resourcesDeleteWg.Wait()
	assert.Equal(t, len(tc.deleteObjects), len(deleteObj))
	for _, o := range tc.deleteObjects {
		k := o.GetKind() + "/" + o.GetName()
		c, ok := deleteObj[k]
		assert.True(t, ok)
		assert.NotNil(t, c)
	}

}
func TestStart_1(t *testing.T) {
	tt := []testObj{
		{
			name:              "list ApplicationProfiles",
			resources:         []schema.GroupVersionResource{resourceApplicationProfile},
			preCreatedObjects: []runtime.Object{mocks.GetRuntime(mocks.TestKindAP, mocks.TestNginx), mocks.GetRuntime(mocks.TestKindAP, mocks.TestCollection)},
		},
		{
			name:              "list NetworkNeighbors",
			resources:         []schema.GroupVersionResource{resourceNetworkNeighbor},
			preCreatedObjects: []runtime.Object{mocks.GetRuntime(mocks.TestKindNN, mocks.TestNginx), mocks.GetRuntime(mocks.TestKindNN, mocks.TestCollection)},
		},
		{
			name:          "watch Pods",
			resources:     []schema.GroupVersionResource{resourcePod},
			createObjects: []*unstructured.Unstructured{mocks.GetUnstructured(mocks.TestKindPod, mocks.TestNginx), mocks.GetUnstructured(mocks.TestKindPod, mocks.TestCollection)},
		},
		{
			name:          "watch ApplicationProfiles",
			resources:     []schema.GroupVersionResource{resourceApplicationProfile},
			createObjects: []*unstructured.Unstructured{mocks.GetUnstructured(mocks.TestKindAP, mocks.TestNginx), mocks.GetUnstructured(mocks.TestKindAP, mocks.TestCollection)},
		},
		{
			name:          "watch NetworkNeighbors",
			resources:     []schema.GroupVersionResource{resourceNetworkNeighbor},
			createObjects: []*unstructured.Unstructured{mocks.GetUnstructured(mocks.TestKindNN, mocks.TestNginx), mocks.GetUnstructured(mocks.TestKindNN, mocks.TestCollection)},
		},
	}

	for _, tc := range tt {
		t.Run(tc.name, func(t *testing.T) {
			startTest(t, tc)
		})
	}
}

func TestStart_2(t *testing.T) {
	tt := []testObj{
		{
			name:              "list and modify",
			resources:         []schema.GroupVersionResource{resourceApplicationProfile},
			preCreatedObjects: []runtime.Object{mocks.GetRuntime(mocks.TestKindAP, mocks.TestNginx)},
			modifiedObjects:   []*unstructured.Unstructured{mocks.GetUnstructured(mocks.TestKindAP, mocks.TestNginx)},
		},
		{
			name:            "watch and modify",
			resources:       []schema.GroupVersionResource{resourceApplicationProfile},
			createObjects:   []*unstructured.Unstructured{mocks.GetUnstructured(mocks.TestKindAP, mocks.TestNginx)},
			modifiedObjects: []*unstructured.Unstructured{mocks.GetUnstructured(mocks.TestKindAP, mocks.TestNginx)},
		},
	}

	for _, tc := range tt {
		t.Run(tc.name, func(t *testing.T) {
			startTest(t, tc)
		})
	}
}

func TestStart_3(t *testing.T) {
	tt := []testObj{

		{
			name:              "list and watch",
			resources:         []schema.GroupVersionResource{resourceApplicationProfile},
			preCreatedObjects: []runtime.Object{mocks.GetRuntime(mocks.TestKindAP, mocks.TestCollection)},
			createObjects:     []*unstructured.Unstructured{mocks.GetUnstructured(mocks.TestKindAP, mocks.TestNginx)},
		},
		{
			name:              "list and delete",
			resources:         []schema.GroupVersionResource{resourceApplicationProfile},
			preCreatedObjects: []runtime.Object{mocks.GetRuntime(mocks.TestKindAP, mocks.TestNginx)},
			deleteObjects:     []*unstructured.Unstructured{mocks.GetUnstructured(mocks.TestKindAP, mocks.TestNginx)},
		},
	}

	for _, tc := range tt {
		t.Run(tc.name, func(t *testing.T) {
			startTest(t, tc)
		})
	}
}
func TestStart_4(t *testing.T) {
	tt := []testObj{
		{
			name:            "watch, modify, and delete",
			resources:       []schema.GroupVersionResource{resourceApplicationProfile},
			createObjects:   []*unstructured.Unstructured{mocks.GetUnstructured(mocks.TestKindAP, mocks.TestNginx)},
			modifiedObjects: []*unstructured.Unstructured{mocks.GetUnstructured(mocks.TestKindAP, mocks.TestNginx)},
			deleteObjects:   []*unstructured.Unstructured{mocks.GetUnstructured(mocks.TestKindAP, mocks.TestNginx)},
		},
	}

	for _, tc := range tt {
		t.Run(tc.name, func(t *testing.T) {
			startTest(t, tc)
		})
	}
}

func TestStart_5(t *testing.T) {
	tt := []testObj{
		{
			name:            "multi watch, modify, and delete",
			resources:       []schema.GroupVersionResource{resourceApplicationProfile, resourceNetworkNeighbor, resourcePod},
			createObjects:   []*unstructured.Unstructured{mocks.GetUnstructured(mocks.TestKindAP, mocks.TestNginx), mocks.GetUnstructured(mocks.TestKindAP, mocks.TestCollection), mocks.GetUnstructured(mocks.TestKindNN, mocks.TestNginx), mocks.GetUnstructured(mocks.TestKindNN, mocks.TestCollection), mocks.GetUnstructured(mocks.TestKindPod, mocks.TestNginx), mocks.GetUnstructured(mocks.TestKindPod, mocks.TestCollection)},
			modifiedObjects: []*unstructured.Unstructured{mocks.GetUnstructured(mocks.TestKindAP, mocks.TestNginx), mocks.GetUnstructured(mocks.TestKindAP, mocks.TestCollection), mocks.GetUnstructured(mocks.TestKindNN, mocks.TestNginx), mocks.GetUnstructured(mocks.TestKindNN, mocks.TestCollection), mocks.GetUnstructured(mocks.TestKindPod, mocks.TestNginx), mocks.GetUnstructured(mocks.TestKindPod, mocks.TestCollection)},
			deleteObjects:   []*unstructured.Unstructured{mocks.GetUnstructured(mocks.TestKindAP, mocks.TestNginx), mocks.GetUnstructured(mocks.TestKindAP, mocks.TestCollection), mocks.GetUnstructured(mocks.TestKindNN, mocks.TestNginx), mocks.GetUnstructured(mocks.TestKindNN, mocks.TestCollection), mocks.GetUnstructured(mocks.TestKindPod, mocks.TestNginx), mocks.GetUnstructured(mocks.TestKindPod, mocks.TestCollection)},
		},
	}

	for _, tc := range tt {
		t.Run(tc.name, func(t *testing.T) {
			startTest(t, tc)
		})
	}
}
