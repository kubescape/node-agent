package containerwatcher

import (
	"context"
	"fmt"
	"testing"
	"time"

	"github.com/kubescape/node-agent/pkg/utils"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// MockEvent implements utils.K8sEvent interface for testing
type MockEvent struct {
	ID        string
	Timestamp int64
	Pod       string
	Namespace string
}

func (m MockEvent) GetTimestamp() int64 {
	return m.Timestamp
}

func (m MockEvent) GetPod() string {
	if m.Pod == "" {
		return "test-pod"
	}
	return m.Pod
}

func (m MockEvent) GetNamespace() string {
	if m.Namespace == "" {
		return "test-namespace"
	}
	return m.Namespace
}

func TestOrderedEventQueue_EventOrdering(t *testing.T) {
	// Create queue with very short interval for testing
	queue := NewOrderedEventQueue(10*time.Millisecond, 1000, nil)

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	err := queue.Start(ctx)
	require.NoError(t, err)

	// Create events with different timestamps (out of order)
	now := time.Now()

	// Use AddEventDirect with events that have embedded timestamps
	event1 := MockEvent{ID: "first", Timestamp: now.UnixNano()}
	event2 := MockEvent{ID: "second", Timestamp: now.Add(1 * time.Second).UnixNano()}
	event3 := MockEvent{ID: "third", Timestamp: now.Add(2 * time.Second).UnixNano()}

	// Add events in random order
	queue.AddEventDirect(utils.ExecveEventType, event3, "container1", 100) // third
	queue.AddEventDirect(utils.ExecveEventType, event1, "container2", 200) // first
	queue.AddEventDirect(utils.ExecveEventType, event2, "container3", 300) // second

	// Wait for processing and collect individual events
	ctx2, cancel2 := context.WithTimeout(context.Background(), 100*time.Millisecond)
	defer cancel2()

	var sortedEvents []eventEntry
	outputChan := queue.GetOutputChannel()

	// Collect events from the individual event channel
	for len(sortedEvents) < 3 {
		select {
		case event := <-outputChan:
			sortedEvents = append(sortedEvents, event)
		case <-ctx2.Done():
			t.Fatal("Timeout waiting for sorted events")
		}
	}

	queue.Stop()

	// Verify events are sorted by timestamp
	require.Len(t, sortedEvents, 3)
	assert.Equal(t, "first", sortedEvents[0].Event.(MockEvent).ID)
	assert.Equal(t, "second", sortedEvents[1].Event.(MockEvent).ID)
	assert.Equal(t, "third", sortedEvents[2].Event.(MockEvent).ID)

	// Verify container IDs and process IDs are preserved
	assert.Equal(t, "container2", sortedEvents[0].ContainerID)
	assert.Equal(t, uint32(200), sortedEvents[0].ProcessID)
	assert.Equal(t, "container3", sortedEvents[1].ContainerID)
	assert.Equal(t, uint32(300), sortedEvents[1].ProcessID)
	assert.Equal(t, "container1", sortedEvents[2].ContainerID)
	assert.Equal(t, uint32(100), sortedEvents[2].ProcessID)
}

func TestOrderedEventQueue_BufferOverflow(t *testing.T) {
	// Create queue with small buffer to test overflow
	queue := NewOrderedEventQueue(10*time.Millisecond, 3, nil)

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	err := queue.Start(ctx)
	require.NoError(t, err)

	// Add more events than buffer can hold
	for i := 0; i < 5; i++ {
		event := MockEvent{ID: fmt.Sprintf("event_%d", i), Timestamp: time.Now().UnixNano()}
		queue.AddEventDirect(utils.ExecveEventType, event, fmt.Sprintf("container_%d", i), uint32(i+100))
	}

	// Wait for processing and collect individual events
	ctx2, cancel2 := context.WithTimeout(context.Background(), 100*time.Millisecond)
	defer cancel2()

	var events []eventEntry
	outputChan := queue.GetOutputChannel()

	// Collect events with timeout
	for {
		select {
		case event := <-outputChan:
			events = append(events, event)
		case <-ctx2.Done():
			goto done
		}
	}
done:
	queue.Stop()

	// Should have processed some events due to overflow
	assert.Greater(t, len(events), 0)
}

// MockEventNoTimestamp doesn't implement GetTimestamp() interface
type MockEventNoTimestamp struct {
	ID        string
	Pod       string
	Namespace string
}

func (m MockEventNoTimestamp) GetPod() string {
	if m.Pod == "" {
		return "test-pod"
	}
	return m.Pod
}

func (m MockEventNoTimestamp) GetNamespace() string {
	if m.Namespace == "" {
		return "test-namespace"
	}
	return m.Namespace
}

func TestOrderedEventQueue_AddEventDirect(t *testing.T) {
	queue := NewOrderedEventQueue(10*time.Millisecond, 1000, nil)

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	err := queue.Start(ctx)
	require.NoError(t, err)

	event := MockEvent{ID: "test", Timestamp: time.Now().UnixNano()}
	queue.AddEventDirect(utils.ExecveEventType, event, "test-container", 1234)

	// Wait for processing and receive single event
	ctx2, cancel2 := context.WithTimeout(context.Background(), 50*time.Millisecond)
	defer cancel2()

	var receivedEvent eventEntry
	select {
	case receivedEvent = <-queue.GetOutputChannel():
	case <-ctx2.Done():
		t.Fatal("Timeout waiting for event")
	}

	queue.Stop()

	assert.Equal(t, utils.ExecveEventType, receivedEvent.EventType)
	assert.Equal(t, event, receivedEvent.Event)
	assert.Equal(t, "test-container", receivedEvent.ContainerID)
	assert.Equal(t, uint32(1234), receivedEvent.ProcessID)
}

func TestOrderedEventQueue_MultipleProcessingCycles(t *testing.T) {
	queue := NewOrderedEventQueue(10*time.Millisecond, 1000, nil)

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	err := queue.Start(ctx)
	require.NoError(t, err)

	now := time.Now()
	outputChan := queue.GetOutputChannel()

	// Add first batch
	for i := 0; i < 3; i++ {
		event := MockEvent{ID: string(rune('A' + i)), Timestamp: now.Add(time.Duration(i) * time.Millisecond).UnixNano()}
		queue.AddEventDirect(utils.ExecveEventType, event, "container1", uint32(i+100))
	}

	// Wait for first batch - collect 3 individual events
	ctx2, cancel2 := context.WithTimeout(context.Background(), 200*time.Millisecond)
	defer cancel2()

	var firstBatch []eventEntry
	for len(firstBatch) < 3 {
		select {
		case event := <-outputChan:
			firstBatch = append(firstBatch, event)
		case <-ctx2.Done():
			queue.Stop()
			t.Fatal("Timeout waiting for first batch")
		}
	}

	require.Len(t, firstBatch, 3)
	assert.Equal(t, "A", firstBatch[0].Event.(MockEvent).ID)
	assert.Equal(t, "B", firstBatch[1].Event.(MockEvent).ID)
	assert.Equal(t, "C", firstBatch[2].Event.(MockEvent).ID)

	// Add second batch
	for i := 0; i < 2; i++ {
		event := MockEvent{ID: string(rune('X' + i)), Timestamp: now.Add(time.Duration(100+i) * time.Millisecond).UnixNano()}
		queue.AddEventDirect(utils.OpenEventType, event, "container2", uint32(i+200))
	}

	// Wait for second batch - collect 2 individual events
	ctx3, cancel3 := context.WithTimeout(context.Background(), 200*time.Millisecond)
	defer cancel3()

	var secondBatch []eventEntry
	for len(secondBatch) < 2 {
		select {
		case event := <-outputChan:
			secondBatch = append(secondBatch, event)
		case <-ctx3.Done():
			queue.Stop()
			t.Fatal("Timeout waiting for second batch")
		}
	}

	queue.Stop()

	require.Len(t, secondBatch, 2)
	assert.Equal(t, "X", secondBatch[0].Event.(MockEvent).ID)
	assert.Equal(t, "Y", secondBatch[1].Event.(MockEvent).ID)
}

func TestOrderedEventQueue_StartStop(t *testing.T) {
	queue := NewOrderedEventQueue(10*time.Millisecond, 1000, nil)

	// Test multiple starts
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	err := queue.Start(ctx)
	require.NoError(t, err)

	// Starting again should return error
	err = queue.Start(ctx)
	assert.Error(t, err)

	// Stop should work
	queue.Stop()

	// Starting after stop should return error
	err = queue.Start(ctx)
	assert.Error(t, err)
}

func TestOrderedEventQueue_DropsEventsWhenStopped(t *testing.T) {
	queue := NewOrderedEventQueue(10*time.Millisecond, 1000, nil)

	// Add event before starting - should be dropped (use AddEventDirect)
	event := MockEvent{ID: "dropped", Timestamp: time.Now().UnixNano()}
	queue.AddEventDirect(utils.ExecveEventType, event, "dropped-container", 1000)

	// Start and immediately stop
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	err := queue.Start(ctx)
	require.NoError(t, err)
	queue.Stop()

	// Add event after stopping - should be dropped
	event2 := MockEvent{ID: "also-dropped", Timestamp: time.Now().UnixNano()}
	queue.AddEventDirect(utils.ExecveEventType, event2, "also-dropped-container", 2000)

	// Should not receive any events - channel should be closed
	select {
	case event, ok := <-queue.GetOutputChannel():
		if ok {
			t.Errorf("Unexpected event received: %+v", event)
		}
		// Channel is closed, which is expected
	case <-time.After(100 * time.Millisecond):
		// This is also expected - no events should be sent
	}
}

func TestOrderedEventQueue_EventTypes(t *testing.T) {
	queue := NewOrderedEventQueue(10*time.Millisecond, 1000, nil)

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	err := queue.Start(ctx)
	require.NoError(t, err)

	now := time.Now()
	eventTypes := []utils.EventType{
		utils.ExecveEventType,
		utils.OpenEventType,
		utils.NetworkEventType,
		utils.DnsEventType,
		utils.ExitEventType,
	}

	// Add events of different types
	for i, eventType := range eventTypes {
		event := MockEvent{ID: string(rune('A' + i)), Timestamp: now.Add(time.Duration(i) * time.Millisecond).UnixNano()}
		queue.AddEventDirect(eventType, event, "container1", uint32(i+100))
	}

	// Wait for processing and collect individual events
	ctx2, cancel2 := context.WithTimeout(context.Background(), 500*time.Millisecond)
	defer cancel2()

	var sortedEvents []eventEntry
	outputChan := queue.GetOutputChannel()

	for len(sortedEvents) < len(eventTypes) {
		select {
		case event := <-outputChan:
			sortedEvents = append(sortedEvents, event)
		case <-ctx2.Done():
			queue.Stop()
			t.Fatal("Timeout waiting for events")
		}
	}

	queue.Stop()

	require.Len(t, sortedEvents, len(eventTypes))

	// Verify event types are preserved
	for i, eventType := range eventTypes {
		assert.Equal(t, eventType, sortedEvents[i].EventType)
		assert.Equal(t, string(rune('A'+i)), sortedEvents[i].Event.(MockEvent).ID)
	}
}
