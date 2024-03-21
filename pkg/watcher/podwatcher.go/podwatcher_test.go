package podwatcher

// import (
// 	"context"
// 	_ "embed"
// 	"node-agent/pkg/watcher"
// 	"node-agent/pkg/watcher/cooldownqueue"
// 	"sync"
// 	"testing"
// 	"time"

// 	"github.com/kubescape/k8s-interface/k8sinterface"
// 	"github.com/stretchr/testify/assert"
// 	core1 "k8s.io/api/core/v1"
// 	v1 "k8s.io/apimachinery/pkg/apis/meta/v1"
// 	"k8s.io/apimachinery/pkg/watch"
// )

// func TestPodWatch(t *testing.T) {
// 	tt := []struct {
// 		name     string
// 		nodeName string
// 		pods     []*core1.Pod
// 	}{
// 		{
// 			name:     "Adding pods",
// 			nodeName: "nodeTest",
// 			pods: []*core1.Pod{
// 				{
// 					ObjectMeta: v1.ObjectMeta{
// 						Name:      "pod1",
// 						Namespace: "default",
// 					},
// 					Spec: core1.PodSpec{
// 						NodeName: "nodeTest",
// 					},
// 				},
// 			},
// 		},
// 	}

// 	for _, tc := range tt {
// 		t.Run(tc.name, func(t *testing.T) {
// 			k8sAPI := k8sinterface.NewKubernetesApiMock()
// 			whm := &watcher.WatcherMock{}
// 			wh := NewWatchHandler(tc.nodeName, k8sAPI, []watcher.Watcher{whm})
// 			go wh.Watch(context.Background())

// 			for i := range tc.pods {
// 				k8sAPI.GetKubernetesClient().CoreV1().Pods(tc.pods[i].Namespace).Create(context.Background(), tc.pods[i], v1.CreateOptions{})
// 			}

// 			// wait for function to process the event
// 			time.Sleep(2 * time.Second)

// 			assert.Equal(t, len(tc.pods), len(whm.AddedPods))
// 		})
// 	}
// }

// func Test_listPods(t *testing.T) {
// 	tt := []struct {
// 		name                string
// 		pods                []*core1.Pod
// 		nodeName            string
// 		expectedObjectNames []string
// 	}{
// 		{
// 			name:     "list pods",
// 			nodeName: "nodeTest",
// 			pods: []*core1.Pod{
// 				{
// 					ObjectMeta: v1.ObjectMeta{
// 						Name:      "pod1",
// 						Namespace: "",
// 					},
// 					Spec: core1.PodSpec{
// 						NodeName: "nodeTest",
// 					},
// 				},
// 				{
// 					ObjectMeta: v1.ObjectMeta{
// 						Name:      "pod2",
// 						Namespace: "",
// 					},
// 					Spec: core1.PodSpec{
// 						NodeName: "nodeTest",
// 					},
// 				},
// 			},
// 			expectedObjectNames: []string{
// 				"pod1",
// 				"pod2",
// 			},
// 		},
// 	}

// 	for _, tc := range tt {
// 		t.Run(tc.name, func(t *testing.T) {
// 			eventQueue := cooldownqueue.NewCooldownQueue(cooldownqueue.DefaultQueueSize, cooldownqueue.DefaultTTL)
// 			wh := WatchHandler{
// 				k8sClient:  k8sinterface.NewKubernetesApiMock(),
// 				nodeName:   tc.nodeName,
// 				eventQueue: eventQueue,
// 			}
// 			// Prepare starting startingObjects for storage
// 			ctx := context.Background()

// 			resourcesCreatedWg := &sync.WaitGroup{}

// 			for i := range tc.pods {
// 				resourcesCreatedWg.Add(1)
// 				bla := wh.k8sClient.GetKubernetesClient()
// 				_, err := bla.CoreV1().Pods(tc.pods[i].Namespace).Create(ctx, tc.pods[i], v1.CreateOptions{})
// 				assert.NoError(t, err)
// 			}

// 			go func() {
// 				for e := range eventQueue.ResultChan {
// 					assert.Equal(t, watch.Added, e.Type)
// 					assert.Contains(t, tc.expectedObjectNames, e.Object.(*core1.Pod).Name)
// 					resourcesCreatedWg.Done()
// 				}
// 			}()

// 			wh.listPods(ctx)
// 			resourcesCreatedWg.Wait()
// 			eventQueue.Stop()
// 		})
// 	}
// }
