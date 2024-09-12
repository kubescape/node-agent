package dynamicwatcher

import (
	"context"
	"sync"
	"testing"
	"time"

	"github.com/kubescape/node-agent/mocks"
	"github.com/kubescape/node-agent/pkg/watcher"

	"github.com/kubescape/storage/pkg/apis/softwarecomposition/v1beta1"
	storagefake "github.com/kubescape/storage/pkg/generated/clientset/versioned/fake"
	appsv1 "k8s.io/api/apps/v1"
	corev1 "k8s.io/api/core/v1"

	"github.com/kubescape/k8s-interface/k8sinterface"
	"github.com/stretchr/testify/assert"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/kubernetes/fake"
	"k8s.io/client-go/kubernetes/scheme"

	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/runtime/schema"
)

var (
	resourcePod                 = schema.GroupVersionResource{Group: "", Version: "v1", Resource: "pods"}
	resourceNetworkNeighborhood = schema.GroupVersionResource{Group: "spdx.softwarecomposition.kubescape.io", Version: "v1beta1", Resource: "networkneighborhoods"}
	resourceApplicationProfile  = schema.GroupVersionResource{Group: "spdx.softwarecomposition.kubescape.io", Version: "v1beta1", Resource: "applicationprofiles"}
)

func init() {
	v1beta1.AddToScheme(scheme.Scheme)
	corev1.AddToScheme(scheme.Scheme)
	appsv1.AddToScheme(scheme.Scheme)
}

type testObj struct {
	name              string
	resources         []schema.GroupVersionResource
	preCreatedObjects []runtime.Object
	createObjects     []runtime.Object
	modifiedObjects   []runtime.Object
	deleteObjects     []runtime.Object
}

func startTest(t *testing.T, tc testObj) {

	ctx := context.Background()

	a := &watcher.AdaptorMock{}
	a.WatcherMock = *watcher.NewWatcherMock()

	for _, v := range tc.resources {
		a.WatchResource = append(a.WatchResource, watcher.WatchResourceMock{Schema: v})
	}

	k8sClient := k8sinterface.NewKubernetesApiMock()
	k8sClient.KubernetesClient = fake.NewClientset()
	storageClient := storagefake.NewSimpleClientset(tc.preCreatedObjects...).SpdxV1beta1()

	wh := NewWatchHandler(k8sClient, storageClient, func(s string) bool {
		return false
	})

	wh.AddAdaptor(a)

	resourcesCreatedWg := &sync.WaitGroup{}
	resourcesModifiedWg := &sync.WaitGroup{}
	resourcesDeleteWg := &sync.WaitGroup{}

	resourcesCreatedWg.Add(len(tc.createObjects) + len(tc.preCreatedObjects))
	resourcesModifiedWg.Add(len(tc.modifiedObjects))
	resourcesDeleteWg.Add(len(tc.deleteObjects))

	wh.Start(ctx)

	createdObj := map[string]runtime.Object{}
	modifiedObj := map[string]runtime.Object{}
	deleteObj := map[string]runtime.Object{}
	l := sync.Mutex{}

	go func() {
		for {
			obj := <-a.WatcherMock.Added
			t.Logf("added object: kind: %s, name: %s\n", obj.GetObjectKind().GroupVersionKind().Kind, obj)
			l.Lock()
			createdObj[getKey(obj)] = obj
			resourcesCreatedWg.Done()
			l.Unlock()
		}
	}()
	go func() {
		for obj := range a.WatcherMock.Updated {
			t.Logf("modified object: kind: %s, name: %s\n", obj.GetObjectKind().GroupVersionKind().Kind, obj.(metav1.Object).GetName())
			l.Lock()
			modifiedObj[getKey(obj)] = obj
			resourcesModifiedWg.Done()
			l.Unlock()
		}
	}()
	go func() {
		for obj := range a.WatcherMock.Deleted {
			t.Logf("deleted object: kind: %s, name: %s\n", obj.GetObjectKind().GroupVersionKind().Kind, obj.(metav1.Object).GetName())
			l.Lock()
			deleteObj[getKey(obj)] = obj
			resourcesDeleteWg.Done()
			l.Unlock()
		}
	}()

	// wait for watcher to start
	time.Sleep(1 * time.Second)

	// create objects
	for i := range tc.createObjects {
		var err error
		if ap, ok := tc.createObjects[i].(*v1beta1.ApplicationProfile); ok {
			_, err = wh.storageClient.ApplicationProfiles(ap.Namespace).Create(ctx, ap, metav1.CreateOptions{})
		} else if nn, ok := tc.createObjects[i].(*v1beta1.NetworkNeighborhood); ok {
			_, err = wh.storageClient.NetworkNeighborhoods(nn.Namespace).Create(ctx, nn, metav1.CreateOptions{})
		} else if pod, ok := tc.createObjects[i].(*corev1.Pod); ok {
			_, err = wh.k8sClient.GetKubernetesClient().CoreV1().Pods(pod.Namespace).Create(ctx, pod, metav1.CreateOptions{})
		} else if sp, ok := tc.createObjects[i].(*v1beta1.SeccompProfile); ok {
			_, err = wh.storageClient.SeccompProfiles(sp.Namespace).Create(ctx, sp, metav1.CreateOptions{})
		} else {
			t.Fatalf("unsupported object type: %v", tc.createObjects[i])
		}
		if err != nil {
			t.Fatalf("error creating object: %v", err)
		}
	}
	waitTimeout(resourcesCreatedWg, 10*time.Second)
	assert.Equal(t, len(tc.createObjects)+len(tc.preCreatedObjects), len(createdObj))

	for _, o := range tc.createObjects {
		k := getKey(o)
		c, ok := createdObj[k]
		assert.True(t, ok)
		assert.NotNil(t, c)
	}

	// modify objects
	labels := map[string]string{"test": "test"}
	for _, o := range tc.modifiedObjects {
		o.(metav1.Object).SetLabels(labels)
		var err error
		if ap, ok := o.(*v1beta1.ApplicationProfile); ok {
			_, err = wh.storageClient.ApplicationProfiles(ap.Namespace).Update(ctx, ap, metav1.UpdateOptions{})
		} else if nn, ok := o.(*v1beta1.NetworkNeighborhood); ok {
			_, err = wh.storageClient.NetworkNeighborhoods(nn.Namespace).Update(ctx, nn, metav1.UpdateOptions{})
		} else if pod, ok := o.(*corev1.Pod); ok {
			_, err = wh.k8sClient.GetKubernetesClient().CoreV1().Pods(pod.Namespace).Update(ctx, pod, metav1.UpdateOptions{})
		} else if sp, ok := o.(*v1beta1.SeccompProfile); ok {
			_, err = wh.storageClient.SeccompProfiles(sp.Namespace).Update(ctx, sp, metav1.UpdateOptions{})
		} else {
			t.Fatalf("unsupported object type: %v", o)
		}
		if err != nil {
			t.Fatalf("error updating object: %v", err)
		}
	}
	waitTimeout(resourcesModifiedWg, 10*time.Second)
	assert.Equal(t, len(tc.modifiedObjects), len(modifiedObj))

	for _, o := range tc.modifiedObjects {
		k := getKey(o)
		c, ok := modifiedObj[k]
		assert.True(t, ok)
		assert.NotNil(t, c)
		assert.Equal(t, labels, o.(metav1.Object).GetLabels())
	}

	// delete objects
	for _, o := range tc.deleteObjects {
		var err error
		if ap, ok := o.(*v1beta1.ApplicationProfile); ok {
			err = wh.storageClient.ApplicationProfiles(ap.Namespace).Delete(ctx, ap.Name, metav1.DeleteOptions{})
		} else if nn, ok := o.(*v1beta1.NetworkNeighborhood); ok {
			err = wh.storageClient.NetworkNeighborhoods(nn.Namespace).Delete(ctx, nn.Name, metav1.DeleteOptions{})
		} else if pod, ok := o.(*corev1.Pod); ok {
			err = wh.k8sClient.GetKubernetesClient().CoreV1().Pods(pod.Namespace).Delete(ctx, pod.Name, metav1.DeleteOptions{})
		} else if sp, ok := o.(*v1beta1.SeccompProfile); ok {
			err = wh.storageClient.SeccompProfiles(sp.Namespace).Delete(ctx, sp.Name, metav1.DeleteOptions{})
		} else {
			t.Fatalf("unsupported object type: %v", o)
		}
		if err != nil {
			t.Fatalf("error deleting object: %v", err)
		}
	}
	waitTimeout(resourcesDeleteWg, 10*time.Second)
	assert.Equal(t, len(tc.deleteObjects), len(deleteObj))

	for _, o := range tc.deleteObjects {
		k := getKey(o)
		c, ok := deleteObj[k]
		assert.True(t, ok)
		assert.NotNil(t, c)
	}
}

func getKey(obj runtime.Object) string {
	return obj.GetObjectKind().GroupVersionKind().Kind + "/" + obj.(metav1.Object).GetName()
}

func TestStart_1(t *testing.T) {
	tt := []testObj{
		{
			name:              "list ApplicationProfiles",
			resources:         []schema.GroupVersionResource{resourceApplicationProfile},
			preCreatedObjects: []runtime.Object{mocks.GetRuntime(mocks.TestKindAP, mocks.TestNginx), mocks.GetRuntime(mocks.TestKindAP, mocks.TestCollection)},
		},
		{
			name:              "list NetworkNeighborhoods",
			resources:         []schema.GroupVersionResource{resourceNetworkNeighborhood},
			preCreatedObjects: []runtime.Object{mocks.GetRuntime(mocks.TestKindNN, mocks.TestNginx), mocks.GetRuntime(mocks.TestKindNN, mocks.TestCollection)},
		},
		{
			name:          "watch Pods",
			resources:     []schema.GroupVersionResource{resourcePod},
			createObjects: []runtime.Object{mocks.GetRuntime(mocks.TestKindPod, mocks.TestNginx), mocks.GetRuntime(mocks.TestKindPod, mocks.TestCollection)},
		},
		{
			name:          "watch ApplicationProfiles",
			resources:     []schema.GroupVersionResource{resourceApplicationProfile},
			createObjects: []runtime.Object{mocks.GetRuntime(mocks.TestKindAP, mocks.TestNginx), mocks.GetRuntime(mocks.TestKindAP, mocks.TestCollection)},
		},
		{
			name:          "watch NetworkNeighborhoods",
			resources:     []schema.GroupVersionResource{resourceNetworkNeighborhood},
			createObjects: []runtime.Object{mocks.GetRuntime(mocks.TestKindNN, mocks.TestNginx), mocks.GetRuntime(mocks.TestKindNN, mocks.TestCollection)},
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
			modifiedObjects:   []runtime.Object{mocks.GetRuntime(mocks.TestKindAP, mocks.TestNginx)},
		},
		{
			name:            "watch and modify",
			resources:       []schema.GroupVersionResource{resourceApplicationProfile},
			createObjects:   []runtime.Object{mocks.GetRuntime(mocks.TestKindAP, mocks.TestNginx)},
			modifiedObjects: []runtime.Object{mocks.GetRuntime(mocks.TestKindAP, mocks.TestNginx)},
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
			createObjects:     []runtime.Object{mocks.GetRuntime(mocks.TestKindAP, mocks.TestNginx)},
		},
		{
			name:              "list and delete",
			resources:         []schema.GroupVersionResource{resourceApplicationProfile},
			preCreatedObjects: []runtime.Object{mocks.GetRuntime(mocks.TestKindAP, mocks.TestNginx)},
			deleteObjects:     []runtime.Object{mocks.GetRuntime(mocks.TestKindAP, mocks.TestNginx)},
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
			createObjects:   []runtime.Object{mocks.GetRuntime(mocks.TestKindAP, mocks.TestNginx)},
			modifiedObjects: []runtime.Object{mocks.GetRuntime(mocks.TestKindAP, mocks.TestNginx)},
			deleteObjects:   []runtime.Object{mocks.GetRuntime(mocks.TestKindAP, mocks.TestNginx)},
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
			resources:       []schema.GroupVersionResource{resourceApplicationProfile, resourceNetworkNeighborhood, resourcePod},
			createObjects:   []runtime.Object{mocks.GetRuntime(mocks.TestKindAP, mocks.TestNginx), mocks.GetRuntime(mocks.TestKindAP, mocks.TestCollection), mocks.GetRuntime(mocks.TestKindNN, mocks.TestNginx), mocks.GetRuntime(mocks.TestKindNN, mocks.TestCollection), mocks.GetRuntime(mocks.TestKindPod, mocks.TestNginx), mocks.GetRuntime(mocks.TestKindPod, mocks.TestCollection)},
			modifiedObjects: []runtime.Object{mocks.GetRuntime(mocks.TestKindAP, mocks.TestNginx), mocks.GetRuntime(mocks.TestKindAP, mocks.TestCollection), mocks.GetRuntime(mocks.TestKindNN, mocks.TestNginx), mocks.GetRuntime(mocks.TestKindNN, mocks.TestCollection), mocks.GetRuntime(mocks.TestKindPod, mocks.TestNginx), mocks.GetRuntime(mocks.TestKindPod, mocks.TestCollection)},
			deleteObjects:   []runtime.Object{mocks.GetRuntime(mocks.TestKindAP, mocks.TestNginx), mocks.GetRuntime(mocks.TestKindAP, mocks.TestCollection), mocks.GetRuntime(mocks.TestKindNN, mocks.TestNginx), mocks.GetRuntime(mocks.TestKindNN, mocks.TestCollection), mocks.GetRuntime(mocks.TestKindPod, mocks.TestNginx), mocks.GetRuntime(mocks.TestKindPod, mocks.TestCollection)},
		},
	}

	for _, tc := range tt {
		t.Run(tc.name, func(t *testing.T) {
			startTest(t, tc)
		})
	}
}

func waitTimeout(wg *sync.WaitGroup, timeout time.Duration) bool {
	c := make(chan struct{})
	go func() {
		defer close(c)
		wg.Wait()
	}()
	select {
	case <-c:
		return false // completed normally
	case <-time.After(timeout):
		return true // timed out
	}
}
