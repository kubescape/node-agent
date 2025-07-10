package containerwatcher

import (
	"testing"
	"time"

	containercollection "github.com/inspektor-gadget/inspektor-gadget/pkg/container-collection"
	tracercollection "github.com/inspektor-gadget/inspektor-gadget/pkg/tracer-collection"
	"github.com/kubescape/node-agent/pkg/containerwatcher"
	"github.com/kubescape/node-agent/pkg/containerwatcher/v2/tracers"
	"github.com/kubescape/node-agent/pkg/utils"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// MockEventEntry represents a test event entry
type MockEventEntry struct {
	EventType   utils.EventType
	Event       utils.K8sEvent
	Timestamp   time.Time
	ContainerID string
	ProcessID   uint32
}

// MockEventQueue implements EventQueueInterface for testing
type MockEventQueue struct {
	events []MockEventEntry
}

func (m *MockEventQueue) AddEventDirect(eventType utils.EventType, event utils.K8sEvent, containerID string, processID uint32) {
	var timestamp time.Time
	if tsGetter, ok := event.(interface{ GetTimestamp() int64 }); ok {
		timestamp = time.Unix(0, tsGetter.GetTimestamp())
	} else {
		timestamp = time.Now()
	}

	m.events = append(m.events, MockEventEntry{
		EventType:   eventType,
		Event:       event,
		Timestamp:   timestamp,
		ContainerID: containerID,
		ProcessID:   processID,
	})
}

func (m *MockEventQueue) GetEvents() []MockEventEntry {
	return m.events
}

func (m *MockEventQueue) Reset() {
	m.events = nil
}

func TestTracerFactory_Creation(t *testing.T) {
	containerCollection := &containercollection.ContainerCollection{}
	tracerCollection, err := tracercollection.NewTracerCollection(containerCollection)
	require.NoError(t, err)

	containerSelector := containercollection.ContainerSelector{}
	mockEventQueue := &MockEventQueue{}

	// Test factory creation
	factory := tracers.NewTracerFactory(
		containerCollection,
		tracerCollection,
		containerSelector,
		mockEventQueue,
		nil, // No socket enricher
	)

	assert.NotNil(t, factory)
}

func TestTracerFactory_CreateAllTracersWithoutSocketEnricher(t *testing.T) {
	containerCollection := &containercollection.ContainerCollection{}
	tracerCollection, err := tracercollection.NewTracerCollection(containerCollection)
	require.NoError(t, err)

	containerSelector := containercollection.ContainerSelector{}
	mockEventQueue := &MockEventQueue{}

	// Test without socket enricher
	factory := tracers.NewTracerFactory(
		containerCollection,
		tracerCollection,
		containerSelector,
		mockEventQueue,
		nil, // No socket enricher
	)

	manager := containerwatcher.NewTracerManager()

	// Test tracer creation
	factory.CreateAllTracers(manager)

	// Verify tracers were registered
	tracers := manager.GetAllTracers()
	assert.NotEmpty(t, tracers)

	// Should have fewer tracers than with socket enricher since network tracers are excluded
	assert.GreaterOrEqual(t, len(tracers), 8)
}

func TestTracerFactory_TracerTypes(t *testing.T) {
	containerCollection := &containercollection.ContainerCollection{}
	tracerCollection, err := tracercollection.NewTracerCollection(containerCollection)
	require.NoError(t, err)

	containerSelector := containercollection.ContainerSelector{}
	mockEventQueue := &MockEventQueue{}

	factory := tracers.NewTracerFactory(
		containerCollection,
		tracerCollection,
		containerSelector,
		mockEventQueue,
		nil,
	)

	manager := containerwatcher.NewTracerManager()
	factory.CreateAllTracers(manager)

	// Verify we can retrieve tracers and they have different types
	tracers := manager.GetAllTracers()

	// Check that we have various tracer types by event type
	expectedEventTypes := []utils.EventType{
		utils.ExecveEventType,
		utils.OpenEventType,
		utils.ExitEventType,
		utils.ForkEventType,
		utils.CapabilitiesEventType,
		utils.SymlinkEventType,
		utils.HardlinkEventType,
		utils.HTTPEventType,
		utils.PtraceEventType,
		utils.IoUringEventType,
		utils.RandomXEventType,
		utils.AllEventType, // TopTracer
	}

	for _, expectedType := range expectedEventTypes {
		tracer, exists := tracers[expectedType]
		assert.True(t, exists, "Expected tracer for event type %s not found", expectedType)
		if exists {
			assert.Equal(t, expectedType, tracer.GetEventType())
		}
	}
}

func TestTracerFactory_NetworkTracersWithoutSocketEnricher(t *testing.T) {
	containerCollection := &containercollection.ContainerCollection{}
	tracerCollection, err := tracercollection.NewTracerCollection(containerCollection)
	require.NoError(t, err)

	containerSelector := containercollection.ContainerSelector{}
	mockEventQueue := &MockEventQueue{}

	// Test without socket enricher
	factory := tracers.NewTracerFactory(
		containerCollection,
		tracerCollection,
		containerSelector,
		mockEventQueue,
		nil,
	)

	manager := containerwatcher.NewTracerManager()
	factory.CreateAllTracers(manager)

	// Verify network tracers are NOT present
	tracers := manager.GetAllTracers()

	networkEventTypes := []utils.EventType{
		utils.NetworkEventType,
		utils.DnsEventType,
		utils.SSHEventType,
	}

	for _, eventType := range networkEventTypes {
		_, exists := tracers[eventType]
		assert.False(t, exists, "Network tracer for event type %s should not exist without socket enricher", eventType)
	}
}

func TestTracerFactory_EventQueueIntegration(t *testing.T) {
	containerCollection := &containercollection.ContainerCollection{}
	tracerCollection, err := tracercollection.NewTracerCollection(containerCollection)
	require.NoError(t, err)

	containerSelector := containercollection.ContainerSelector{}
	mockEventQueue := &MockEventQueue{}

	factory := tracers.NewTracerFactory(
		containerCollection,
		tracerCollection,
		containerSelector,
		mockEventQueue,
		nil,
	)

	manager := containerwatcher.NewTracerManager()
	factory.CreateAllTracers(manager)

	// Verify factory was created with the event queue
	assert.NotNil(t, factory)

	// Verify event queue is empty initially
	events := mockEventQueue.GetEvents()
	assert.Empty(t, events)
}

func TestTracerFactory_TracerManagerIntegration(t *testing.T) {
	containerCollection := &containercollection.ContainerCollection{}
	tracerCollection, err := tracercollection.NewTracerCollection(containerCollection)
	require.NoError(t, err)

	containerSelector := containercollection.ContainerSelector{}
	mockEventQueue := &MockEventQueue{}

	factory := tracers.NewTracerFactory(
		containerCollection,
		tracerCollection,
		containerSelector,
		mockEventQueue,
		nil,
	)

	manager := containerwatcher.NewTracerManager()

	// Before creating tracers, manager should be empty
	tracers := manager.GetAllTracers()
	assert.Empty(t, tracers)

	// After creating tracers, manager should have tracers
	factory.CreateAllTracers(manager)
	tracers = manager.GetAllTracers()
	assert.NotEmpty(t, tracers)

	// Verify each tracer can be retrieved individually
	for eventType, tracer := range tracers {
		retrievedTracer, exists := manager.GetTracer(eventType)
		assert.True(t, exists)
		assert.Equal(t, tracer, retrievedTracer)
	}
}

func TestTracerFactory_EventCallbackCreation(t *testing.T) {
	containerCollection := &containercollection.ContainerCollection{}
	tracerCollection, err := tracercollection.NewTracerCollection(containerCollection)
	require.NoError(t, err)

	containerSelector := containercollection.ContainerSelector{}
	mockEventQueue := &MockEventQueue{}

	factory := tracers.NewTracerFactory(
		containerCollection,
		tracerCollection,
		containerSelector,
		mockEventQueue,
		nil,
	)

	assert.NotNil(t, factory)

	// Test event callback functionality by directly adding an event
	testEvent := MockEvent{
		ID:        "test-event-1",
		Timestamp: time.Now().UnixNano(),
		Pod:       "test-pod",
		Namespace: "test-namespace",
	}

	// Add event directly to the queue
	mockEventQueue.AddEventDirect(utils.ExecveEventType, testEvent, "test-container", 1234)

	// Verify event was added
	events := mockEventQueue.GetEvents()
	assert.Len(t, events, 1)
	assert.Equal(t, utils.ExecveEventType, events[0].EventType)
	assert.Equal(t, testEvent, events[0].Event)
	assert.Equal(t, "test-container", events[0].ContainerID)
	assert.Equal(t, uint32(1234), events[0].ProcessID)
}
