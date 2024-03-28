package dynamicwatcher

import (
	"context"
	"node-agent/mocks"
	"node-agent/pkg/watcher"
	"sync"
	"testing"
	"time"

	"github.com/kubescape/k8s-interface/k8sinterface"
	"github.com/kubescape/storage/pkg/apis/softwarecomposition/v1beta1"
	"github.com/kubescape/storage/pkg/generated/clientset/versioned/scheme"
	"github.com/stretchr/testify/assert"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	dynamicfake "k8s.io/client-go/dynamic/fake"

	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/runtime/schema"
)

// func createDynamicClient(d dynamic.Interface) error {

// 	// Register the custom resource type with the client
// 	d.Resource(schema.GroupVersionResource{}).

//		return nil
//	}
func TestStart(t *testing.T) {
	tt := []struct {
		name              string
		preCreatedObjects []runtime.Object
		createObjects     []*unstructured.Unstructured
		expectedObjects   []*unstructured.Unstructured
		expectedErrors    []error
	}{
		// {
		// 	name:            "watch",
		// 	createObjects:   []*unstructured.Unstructured{mocks.GetUnstructured(mocks.TestKindPod, mocks.TestNginx), mocks.GetUnstructured(mocks.TestKindPod, mocks.TestCollection)},
		// 	expectedObjects: []*unstructured.Unstructured{mocks.GetUnstructured(mocks.TestKindPod, mocks.TestNginx), mocks.GetUnstructured(mocks.TestKindPod, mocks.TestCollection)},
		// },
		// {
		// 	name:            "watch CRDs",
		// 	createObjects:   []*unstructured.Unstructured{mocks.GetUnstructured(mocks.TestKindAA, mocks.TestNginx), mocks.GetUnstructured(mocks.TestKindAA, mocks.TestCollection)},
		// 	expectedObjects: []*unstructured.Unstructured{mocks.GetUnstructured(mocks.TestKindAA, mocks.TestNginx), mocks.GetUnstructured(mocks.TestKindAA, mocks.TestCollection)},
		// },
		{
			name:              "list CRDs",
			preCreatedObjects: []runtime.Object{mocks.GetRuntime(mocks.TestKindAA, mocks.TestNginx), mocks.GetRuntime(mocks.TestKindAA, mocks.TestCollection)},
			expectedObjects:   []*unstructured.Unstructured{mocks.GetUnstructured(mocks.TestKindAA, mocks.TestNginx), mocks.GetUnstructured(mocks.TestKindAA, mocks.TestCollection)},
		},

		// {
		// 	name:            "test list and watch",
		// 	createObjects:   []*unstructured.Unstructured{mocks.GetUnstructured(mocks.TestKindPod, mocks.TestNginx)},
		// 	expectedObjects: []*unstructured.Unstructured{mocks.GetUnstructured(mocks.TestKindPod, mocks.TestNginx)},
		// },
	}

	for _, tc := range tt {
		t.Run(tc.name, func(t *testing.T) {

			ctx := context.Background()

			a := &watcher.AdaptorMock{}
			a.WatcherMock = *watcher.NewWatcherMock()

			m := map[string]schema.GroupVersionResource{}
			for i := range tc.preCreatedObjects {
				r := schema.GroupVersionResource{
					Group:    tc.preCreatedObjects[i].GetObjectKind().GroupVersionKind().Group,
					Version:  tc.preCreatedObjects[i].GetObjectKind().GroupVersionKind().Version,
					Resource: tc.preCreatedObjects[i].GetObjectKind().GroupVersionKind().Kind,
				}
				m[r.String()] = r

				g := schema.GroupVersionKind{
					Group:   tc.preCreatedObjects[i].GetObjectKind().GroupVersionKind().Group,
					Version: tc.preCreatedObjects[i].GetObjectKind().GroupVersionKind().Version,
					Kind:    tc.preCreatedObjects[i].GetObjectKind().GroupVersionKind().Kind,
				}
				ggg := schema.GroupVersionKind{
					Group:   tc.preCreatedObjects[i].GetObjectKind().GroupVersionKind().Group,
					Version: tc.preCreatedObjects[i].GetObjectKind().GroupVersionKind().Version,
					Kind:    "ApplicationActivityList",
				}
				// s.AddKnownTypeWithName(g, tc.preCreatedObjects[i])
				// s.AddKnownTypeWithName(ggg, tc.preCreatedObjects[i])
				scheme.Scheme.AddKnownTypeWithName(g, &v1beta1.ApplicationActivity{})
				scheme.Scheme.AddKnownTypeWithName(ggg, &v1beta1.ApplicationActivityList{})
				// s.
			}
			for i := range tc.createObjects {
				r := schema.GroupVersionResource{
					Group:    tc.createObjects[i].GetObjectKind().GroupVersionKind().Group,
					Version:  tc.createObjects[i].GetObjectKind().GroupVersionKind().Version,
					Resource: tc.createObjects[i].GetObjectKind().GroupVersionKind().Kind,
				}
				m[r.String()] = r
			}
			for _, v := range m {
				a.WatchResource = append(a.WatchResource, watcher.WatchResourceMock{Schema: v})
			}

			dynClient := dynamicfake.NewSimpleDynamicClient(scheme.Scheme, tc.preCreatedObjects...)

			k8sClient := k8sinterface.NewKubernetesApiMock()
			k8sClient.DynamicClient = dynClient

			wh := NewWatchHandler(k8sClient)

			wh.AddAdaptor(a)

			resourcesCreatedWg := &sync.WaitGroup{}
			resourcesModifiedWg := &sync.WaitGroup{}
			resourcesDeleteWg := &sync.WaitGroup{}

			resourcesCreatedWg.Add(len(tc.createObjects) + len(tc.preCreatedObjects))
			// resourcesCreatedWg.Add(len(tc.mo))

			wh.Start(ctx)

			createdObj := []*unstructured.Unstructured{}
			modifiedObj := []*unstructured.Unstructured{}
			deleteObj := []*unstructured.Unstructured{}

			go func() {
				for {
					obj := <-a.WatcherMock.Added
					t.Logf("added object: kind: %s, name: %s\n", obj.GetKind(), obj.GetName())
					createdObj = append(createdObj, obj)
					resourcesCreatedWg.Done()
				}
			}()
			go func() {
				for obj := range a.WatcherMock.Updated {
					t.Logf("modified object: kind: %s, name: %s\n", obj.GetKind(), obj.GetName())
					modifiedObj = append(modifiedObj, obj)
					resourcesModifiedWg.Done()
				}
			}()
			go func() {
				for obj := range a.WatcherMock.Deleted {
					t.Logf("deleted object: kind: %s, name: %s\n", obj.GetKind(), obj.GetName())
					deleteObj = append(deleteObj, obj)
					resourcesDeleteWg.Done()
				}
			}()

			time.Sleep(1 * time.Second)

			for i := range tc.createObjects {
				r := schema.GroupVersionResource{
					Group:    tc.createObjects[i].GetObjectKind().GroupVersionKind().Group,
					Version:  tc.createObjects[i].GetObjectKind().GroupVersionKind().Version,
					Resource: tc.createObjects[i].GetObjectKind().GroupVersionKind().Kind,
				}
				if _, err := wh.k8sClient.GetDynamicClient().Resource(r).Create(ctx, tc.createObjects[i], metav1.CreateOptions{}); err != nil {
					t.Fatalf("error creating object: %v", err)
				}
			}
			t.Log("waiting")
			resourcesCreatedWg.Wait()
			// resourcesModifiedWg.Wait()
			// resourcesDeleteWg.Wait()

			assert.Equal(t, len(tc.expectedObjects), len(createdObj)+len(deleteObj))

		})
	}
}
