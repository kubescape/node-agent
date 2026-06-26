package cooldownqueue

import (
	"sort"
	"sync"
	"testing"
	"time"

	"github.com/kubescape/node-agent/pkg/watcher"
	"github.com/stretchr/testify/assert"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	"k8s.io/apimachinery/pkg/watch"
)

var (
	configmap       = unstructured.Unstructured{Object: map[string]interface{}{"kind": "ConfigMap", "metadata": map[string]interface{}{"uid": "748ad4a8-e5ff-44da-ba94-309992c97820"}}}
	deployment      = unstructured.Unstructured{Object: map[string]interface{}{"kind": "Deployment", "metadata": map[string]interface{}{"uid": "6b1a0c50-277f-4aa1-a4f9-9fc278ce4fe2"}}}
	pod             = unstructured.Unstructured{Object: map[string]interface{}{"kind": "Pod", "metadata": map[string]interface{}{"uid": "aa5e3e8f-2da5-4c38-93c0-210d3280d10f"}}}
	deploymentAdded = watch.Event{Type: watch.Added, Object: &deployment}
	podAdded        = watch.Event{Type: watch.Added, Object: &pod}
	podModified     = watch.Event{Type: watch.Modified, Object: &pod}
)

func TestCooldownQueue_Enqueue(t *testing.T) {
	tests := []struct {
		name      string
		inEvents  []watch.Event
		outEvents []watch.Event
	}{
		{
			name:      "add pod",
			inEvents:  []watch.Event{deploymentAdded, podAdded, podModified, podModified, podModified},
			outEvents: []watch.Event{deploymentAdded, podModified},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			q := NewCooldownQueue[watch.Event](DefaultExpiration, EvictionInterval)
			go func() {
				time.Sleep(10 * time.Second)
				q.Stop()
			}()
			for _, e := range tt.inEvents {
				time.Sleep(50 * time.Millisecond) // need to sleep to preserve order since the insertion is async
				q.Enqueue(e, watcher.MakeEventKey(e))
			}
			var outEvents []watch.Event
			for e := range q.ResultChan() {
				outEvents = append(outEvents, e)
			}
			// sort outEvents to make the comparison easier
			sort.Slice(outEvents, func(i, j int) bool {
				uidI := outEvents[i].Object.(*unstructured.Unstructured).GetUID()
				uidJ := outEvents[j].Object.(*unstructured.Unstructured).GetUID()
				return uidI < uidJ
			})
			assert.Equal(t, tt.outEvents, outEvents)
		})
	}
}

// TestCooldownQueue_StopDuringEviction verifies that calling Stop() while the TTL
// evicter goroutine is firing eviction callbacks does not cause a "send on closed
// channel" panic (issue: armosec/private-node-agent#368).
func TestCooldownQueue_StopDuringEviction(t *testing.T) {
	// Use a very short cooldown so that items expire (and the eviction callback
	// fires) almost immediately.
	const shortCooldown = 10 * time.Millisecond
	const shortInterval = 5 * time.Millisecond

	for i := 0; i < 50; i++ {
		q := NewCooldownQueue[watch.Event](shortCooldown, shortInterval)

		// Enqueue an event so there is something to evict.
		q.Enqueue(podAdded, watcher.MakeEventKey(podAdded))

		// Drain the result channel in a separate goroutine so the callback is
		// not blocked on an unread receiver when we call Stop().
		var wg sync.WaitGroup
		wg.Add(1)
		go func() {
			defer wg.Done()
			//nolint:revive // intentionally drain all events without processing them to unblock the relay goroutine
			for range q.ResultChan() {
			}
		}()

		// Sleep briefly so the TTL evicter goroutine is likely firing
		// concurrently with the Stop() call below.
		time.Sleep(shortCooldown / 2)

		// Must not panic.
		assert.NotPanics(t, func() { q.Stop() })

		wg.Wait()
	}
}

// key is only based on the UID of the object
func Test_makeEventKey(t *testing.T) {
	tests := []struct {
		name string
		e    watch.Event
		want string
	}{
		{
			name: "add pod",
			e: watch.Event{
				Type:   watch.Added,
				Object: &pod,
			},
			want: "//Pod//",
		},
		{
			name: "delete deployment",
			e: watch.Event{
				Type:   watch.Deleted,
				Object: &deployment,
			},
			want: "//Deployment//",
		},
		{
			name: "modify configmap",
			e: watch.Event{
				Type:   watch.Modified,
				Object: &configmap,
			},
			want: "//ConfigMap//",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := watcher.MakeEventKey(tt.e)
			assert.Equal(t, tt.want, got)
		})
	}
}
