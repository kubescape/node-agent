package cooldownqueue

import (
	"testing"
	"time"

	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"

	"github.com/stretchr/testify/assert"
	core1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/watch"
)

func TestCooldownQueue_Stop(t *testing.T) {
	DefaultQueueSize = 1
	DefaultTTL = 1 * time.Second
	queue := NewCooldownQueue()

	// Assert that the queue is not closed
	assert.False(t, queue.Closed(), "expected queue to be open")
	assert.False(t, queue.closed, "expected queue to be closed")

	// Stop the queue
	queue.Stop()

	// Wait for a short period to allow the queue to stop
	time.Sleep(100 * time.Millisecond)

	// Assert that the queue is closed
	assert.True(t, queue.closed, "expected queue to be closed")
	assert.True(t, queue.Closed(), "expected queue to be closed")
}

func TestCooldownQueue_Enqueue(t *testing.T) {
	DefaultQueueSize = 1
	DefaultTTL = 1 * time.Second
	queue := NewCooldownQueue()

	// Enqueue an event
	event := watch.Event{Type: watch.Added, Object: &core1.Pod{ObjectMeta: metav1.ObjectMeta{UID: "test", Name: "test", Namespace: "test"}}}
	queue.Enqueue(event)

	// Wait for a short period to allow the event to be processed
	time.Sleep(100 * time.Millisecond)

	// Assert that the event was processed
	assert.Equal(t, event, <-queue.innerChan)

	// Enqueue the same event again
	queue.Enqueue(event)

	// Wait for a short period to allow the event to be processed
	time.Sleep(100 * time.Millisecond)

	// Assert that the event was not processed again
	select {
	case <-queue.innerChan:
		assert.Fail(t, "event should not have been processed again")
	default:
		// Event was not processed again, as expected
	}

	// Enqueue a different event
	anotherEvent := watch.Event{Type: watch.Modified, Object: &core1.Pod{ObjectMeta: metav1.ObjectMeta{UID: "test-2", Name: "test", Namespace: "test"}}}
	queue.Enqueue(anotherEvent)

	// Wait for a short period to allow the event to be processed
	time.Sleep(100 * time.Millisecond)

	// Assert that the event was processed
	assert.Equal(t, anotherEvent, <-queue.innerChan)
}
