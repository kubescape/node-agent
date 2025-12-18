package containerwatcher

import (
	"fmt"
	"testing"
	"time"

	"github.com/kubescape/node-agent/pkg/utils"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestOrderedEventQueue_EventOrdering_LowestTimestampFirst(t *testing.T) {
	queue := NewOrderedEventQueue(10*time.Millisecond, 1000)

	// Create events with specific timestamps (in nanoseconds)
	// Event 1: timestamp 20
	// Event 2: timestamp 10
	// Event 2 should come out first (lowest timestamp)

	event1 := &utils.StructEvent{ID: "event1", Timestamp: 20}
	event2 := &utils.StructEvent{ID: "event2", Timestamp: 10}
	event3 := &utils.StructEvent{ID: "event3", Timestamp: 30}

	// Add events in random order
	queue.AddEventDirect(utils.ExecveEventType, event1, "container1", 100) // timestamp 20
	queue.AddEventDirect(utils.ExecveEventType, event3, "container3", 300) // timestamp 30
	queue.AddEventDirect(utils.ExecveEventType, event2, "container2", 200) // timestamp 10

	// Pop events - should come out in timestamp order (10, 20, 30)
	firstEvent, ok := queue.PopEvent()
	require.True(t, ok)
	assert.Equal(t, "event2", firstEvent.Event.(*utils.StructEvent).ID) // timestamp 10 comes first
	assert.Equal(t, int64(10), firstEvent.Event.(*utils.StructEvent).Timestamp)

	secondEvent, ok := queue.PopEvent()
	require.True(t, ok)
	assert.Equal(t, "event1", secondEvent.Event.(*utils.StructEvent).ID) // timestamp 20 comes second
	assert.Equal(t, int64(20), secondEvent.Event.(*utils.StructEvent).Timestamp)

	thirdEvent, ok := queue.PopEvent()
	require.True(t, ok)
	assert.Equal(t, "event3", thirdEvent.Event.(*utils.StructEvent).ID) // timestamp 30 comes last
	assert.Equal(t, int64(30), thirdEvent.Event.(*utils.StructEvent).Timestamp)

	// Verify container IDs and process IDs are preserved
	assert.Equal(t, "container2", firstEvent.ContainerID)  // event2's container
	assert.Equal(t, uint32(200), firstEvent.ProcessID)     // event2's PID
	assert.Equal(t, "container1", secondEvent.ContainerID) // event1's container
	assert.Equal(t, uint32(100), secondEvent.ProcessID)    // event1's PID

	// Queue should be empty now
	_, ok = queue.PopEvent()
	assert.False(t, ok)
	assert.True(t, queue.Empty())
}

func TestOrderedEventQueue_RealTimestampOrdering(t *testing.T) {
	queue := NewOrderedEventQueue(10*time.Millisecond, 1000)

	// Create events with real timestamps (out of order)
	now := time.Now()

	// Events with real nanosecond timestamps
	event1 := &utils.StructEvent{ID: "first", Timestamp: now.UnixNano()}
	event2 := &utils.StructEvent{ID: "second", Timestamp: now.Add(1 * time.Second).UnixNano()}
	event3 := &utils.StructEvent{ID: "third", Timestamp: now.Add(2 * time.Second).UnixNano()}

	// Add events in random order
	queue.AddEventDirect(utils.ExecveEventType, event3, "container1", 100) // third chronologically
	queue.AddEventDirect(utils.ExecveEventType, event1, "container2", 200) // first chronologically
	queue.AddEventDirect(utils.ExecveEventType, event2, "container3", 300) // second chronologically

	// Pop all events and verify they come out in chronological order
	var poppedEvents []EventEntry
	for !queue.Empty() {
		event, ok := queue.PopEvent()
		require.True(t, ok)
		poppedEvents = append(poppedEvents, event)
	}

	require.Len(t, poppedEvents, 3)

	// Verify chronological order (earliest timestamp first)
	assert.Equal(t, "first", poppedEvents[0].Event.(*utils.StructEvent).ID)
	assert.Equal(t, "second", poppedEvents[1].Event.(*utils.StructEvent).ID)
	assert.Equal(t, "third", poppedEvents[2].Event.(*utils.StructEvent).ID)

	// Verify timestamps are in ascending order
	ts1 := poppedEvents[0].Event.(*utils.StructEvent).Timestamp
	ts2 := poppedEvents[1].Event.(*utils.StructEvent).Timestamp
	ts3 := poppedEvents[2].Event.(*utils.StructEvent).Timestamp

	assert.True(t, ts1 < ts2, "First timestamp should be less than second")
	assert.True(t, ts2 < ts3, "Second timestamp should be less than third")
}

func TestOrderedEventQueue_FullQueueAlert(t *testing.T) {
	// Create queue with small buffer to test full alert
	queue := NewOrderedEventQueue(10*time.Millisecond, 3)

	// Add events up to the limit
	for i := 0; i < 3; i++ {
		event := &utils.StructEvent{ID: fmt.Sprintf("event_%d", i), Timestamp: int64(i)}
		queue.AddEventDirect(utils.ExecveEventType, event, fmt.Sprintf("container_%d", i), uint32(i+100))
	}

	assert.Equal(t, 3, queue.Size())

	// Add one more event to trigger full queue alert
	overflowEvent := &utils.StructEvent{ID: "overflow", Timestamp: 100}
	queue.AddEventDirect(utils.ExecveEventType, overflowEvent, "overflow_container", 999)

	// Check that full queue alert is triggered
	select {
	case <-queue.GetFullQueueAlertChannel():
		// Alert received as expected
	default:
		t.Fatal("Expected full queue alert but didn't receive one")
	}

	// Verify all events are still in queue (including overflow event)
	assert.Equal(t, 4, queue.Size())
}

func TestOrderedEventQueue_BasicOperations(t *testing.T) {
	queue := NewOrderedEventQueue(10*time.Millisecond, 1000)

	// Test empty queue
	assert.True(t, queue.Empty())
	assert.Equal(t, 0, queue.Size())

	// Test PeekEvent on empty queue
	_, ok := queue.PeekEvent()
	assert.False(t, ok)

	// Test PopEvent on empty queue
	_, ok = queue.PopEvent()
	assert.False(t, ok)

	// Add single event
	event := &utils.StructEvent{ID: "test", Timestamp: time.Now().UnixNano()}
	queue.AddEventDirect(utils.ExecveEventType, event, "test-container", 1234)

	// Test queue properties
	assert.False(t, queue.Empty())
	assert.Equal(t, 1, queue.Size())

	// Test PeekEvent (should not remove event)
	peekedEvent, ok := queue.PeekEvent()
	require.True(t, ok)
	assert.Equal(t, utils.ExecveEventType, peekedEvent.EventType)
	assert.Equal(t, event, peekedEvent.Event)
	assert.Equal(t, "test-container", peekedEvent.ContainerID)
	assert.Equal(t, uint32(1234), peekedEvent.ProcessID)

	// Queue should still have the event
	assert.Equal(t, 1, queue.Size())

	// Test PopEvent (should remove event)
	poppedEvent, ok := queue.PopEvent()
	require.True(t, ok)
	assert.Equal(t, peekedEvent, poppedEvent) // Should be same as peeked

	// Queue should be empty now
	assert.True(t, queue.Empty())
	assert.Equal(t, 0, queue.Size())
}

func TestOrderedEventQueue_MultipleEventTypes(t *testing.T) {
	queue := NewOrderedEventQueue(10*time.Millisecond, 1000)

	eventTypes := []utils.EventType{
		utils.ExecveEventType,
		utils.OpenEventType,
		utils.NetworkEventType,
		utils.DnsEventType,
		utils.ExitEventType,
	}

	// Add events of different types with increasing timestamps
	for i, eventType := range eventTypes {
		event := &utils.StructEvent{ID: fmt.Sprintf("event_%d", i), Timestamp: int64(i * 10)}
		queue.AddEventDirect(eventType, event, fmt.Sprintf("container_%d", i), uint32(i+100))
	}

	assert.Equal(t, len(eventTypes), queue.Size())

	// Pop all events and verify they maintain order and type
	for i, expectedType := range eventTypes {
		event, ok := queue.PopEvent()
		require.True(t, ok, "Should be able to pop event %d", i)

		assert.Equal(t, expectedType, event.EventType)
		assert.Equal(t, fmt.Sprintf("event_%d", i), event.Event.(*utils.StructEvent).ID)
		assert.Equal(t, fmt.Sprintf("container_%d", i), event.ContainerID)
		assert.Equal(t, uint32(i+100), event.ProcessID)
	}

	assert.True(t, queue.Empty())
}

func TestOrderedEventQueue_LargeNumberOfEvents(t *testing.T) {
	queue := NewOrderedEventQueue(10*time.Millisecond, 10000)

	const numEvents = 1000
	baseTime := time.Now().UnixNano()

	// Add events with random-ish timestamps
	expectedOrder := make([]int, numEvents)
	for i := 0; i < numEvents; i++ {
		// Use reverse order timestamps so we can verify sorting works
		timestamp := baseTime + int64((numEvents-i)*1000)
		event := &utils.StructEvent{ID: fmt.Sprintf("event_%d", i), Timestamp: timestamp}
		queue.AddEventDirect(utils.ExecveEventType, event, fmt.Sprintf("container_%d", i), uint32(i))
		expectedOrder[numEvents-1-i] = i // Expected pop order (reverse of add order)
	}

	assert.Equal(t, numEvents, queue.Size())

	// Pop all events and verify they come out in timestamp order
	for i := 0; i < numEvents; i++ {
		event, ok := queue.PopEvent()
		require.True(t, ok, "Should be able to pop event %d", i)

		expectedID := fmt.Sprintf("event_%d", expectedOrder[i])
		assert.Equal(t, expectedID, event.Event.(*utils.StructEvent).ID,
			"Event %d should have ID %s", i, expectedID)
	}

	assert.True(t, queue.Empty())
}
