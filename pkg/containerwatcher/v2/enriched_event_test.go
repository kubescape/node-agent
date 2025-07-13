package containerwatcher

import (
	"testing"
	"time"

	apitypes "github.com/armosec/armoapi-go/armotypes"
	"github.com/kubescape/node-agent/pkg/containerwatcher"
	"github.com/kubescape/node-agent/pkg/utils"
	"github.com/stretchr/testify/assert"
)

func TestNewEnrichedEvent(t *testing.T) {
	// Test creating a new enriched event
	eventType := utils.ExecveEventType
	mockEvent := MockEvent{ID: "test-event"}
	timestamp := time.Now()
	containerID := "test-container-123"
	processTree := apitypes.Process{
		PID:  1234,
		Comm: "test-process",
		Path: "/usr/bin/test",
	}

	enrichedEvent := NewEnrichedEvent(eventType, mockEvent, timestamp, containerID, processTree)

	assert.NotNil(t, enrichedEvent)
	assert.Equal(t, eventType, enrichedEvent.EventType)
	assert.Equal(t, mockEvent, enrichedEvent.Event)
	assert.Equal(t, timestamp, enrichedEvent.Timestamp)
	assert.Equal(t, containerID, enrichedEvent.ContainerID)
	assert.Equal(t, processTree, enrichedEvent.ProcessTree)
}

func TestEnrichedEvent_Structure(t *testing.T) {
	// Test the structure of enriched event
	enrichedEvent := &containerwatcher.EnrichedEvent{
		EventType:   utils.OpenEventType,
		Event:       MockEvent{ID: "open-event"},
		Timestamp:   time.Now(),
		ContainerID: "container-456",
		ProcessTree: apitypes.Process{
			PID:  5678,
			Comm: "open-process",
			Path: "/bin/open",
		},
	}

	// Verify all fields are accessible
	assert.Equal(t, utils.OpenEventType, enrichedEvent.EventType)
	assert.Equal(t, "open-event", enrichedEvent.Event.(MockEvent).ID)
	assert.Equal(t, "container-456", enrichedEvent.ContainerID)
	assert.Equal(t, uint32(5678), enrichedEvent.ProcessTree.PID)
	assert.Equal(t, "open-process", enrichedEvent.ProcessTree.Comm)
	assert.Equal(t, "/bin/open", enrichedEvent.ProcessTree.Path)
}

func TestEnrichedEvent_EventTypes(t *testing.T) {
	// Test different event types
	eventTypes := []utils.EventType{
		utils.ExecveEventType,
		utils.OpenEventType,
		utils.NetworkEventType,
		utils.DnsEventType,
		utils.ExitEventType,
		utils.ForkEventType,
		utils.CapabilitiesEventType,
		utils.SymlinkEventType,
		utils.HardlinkEventType,
		utils.HTTPEventType,
		utils.PtraceEventType,
		utils.IoUringEventType,
		utils.RandomXEventType,
		utils.SSHEventType,
	}

	timestamp := time.Now()
	containerID := "test-container"
	processTree := apitypes.Process{PID: 1000, Comm: "test"}

	for i, eventType := range eventTypes {
		t.Run(string(eventType), func(t *testing.T) {
			event := MockEvent{ID: string(rune('A' + i))}
			enrichedEvent := NewEnrichedEvent(eventType, event, timestamp, containerID, processTree)

			assert.Equal(t, eventType, enrichedEvent.EventType)
			assert.Equal(t, event, enrichedEvent.Event)
		})
	}
}

func TestEnrichedEvent_ProcessTreeIntegration(t *testing.T) {
	// Test process tree integration
	processTree := apitypes.Process{
		PID:     9999,
		PPID:    1,
		Comm:    "parent-process",
		Path:    "/usr/bin/parent",
		Cmdline: "parent-process --arg1 --arg2",
		Cwd:     "/home/user",
		ChildrenMap: map[apitypes.CommPID]*apitypes.Process{
			{Comm: "child1", PID: 10001}: {
				PID:  10001,
				PPID: 9999,
				Comm: "child1",
				Path: "/usr/bin/child1",
			},
			{Comm: "child2", PID: 10002}: {
				PID:  10002,
				PPID: 9999,
				Comm: "child2",
				Path: "/usr/bin/child2",
			},
		},
	}

	enrichedEvent := NewEnrichedEvent(
		utils.ExecveEventType,
		MockEvent{ID: "exec-with-tree"},
		time.Now(),
		"container-with-tree",
		processTree,
	)

	// Verify process tree details
	assert.Equal(t, uint32(9999), enrichedEvent.ProcessTree.PID)
	assert.Equal(t, uint32(1), enrichedEvent.ProcessTree.PPID)
	assert.Equal(t, "parent-process", enrichedEvent.ProcessTree.Comm)
	assert.Equal(t, "/usr/bin/parent", enrichedEvent.ProcessTree.Path)
	assert.Equal(t, "parent-process --arg1 --arg2", enrichedEvent.ProcessTree.Cmdline)
	assert.Equal(t, "/home/user", enrichedEvent.ProcessTree.Cwd)
	assert.Len(t, enrichedEvent.ProcessTree.ChildrenMap, 2)

	// Verify children
	child1, exists := enrichedEvent.ProcessTree.ChildrenMap[apitypes.CommPID{Comm: "child1", PID: 10001}]
	assert.True(t, exists)
	assert.Equal(t, uint32(10001), child1.PID)
	assert.Equal(t, uint32(9999), child1.PPID)

	child2, exists := enrichedEvent.ProcessTree.ChildrenMap[apitypes.CommPID{Comm: "child2", PID: 10002}]
	assert.True(t, exists)
	assert.Equal(t, uint32(10002), child2.PID)
	assert.Equal(t, uint32(9999), child2.PPID)
}

func TestEnrichedEvent_TimestampOrdering(t *testing.T) {
	// Test timestamp ordering for event processing
	baseTime := time.Now()

	events := []*containerwatcher.EnrichedEvent{
		NewEnrichedEvent(utils.ExecveEventType, MockEvent{ID: "third"}, baseTime.Add(2*time.Second), "container", apitypes.Process{}),
		NewEnrichedEvent(utils.OpenEventType, MockEvent{ID: "first"}, baseTime, "container", apitypes.Process{}),
		NewEnrichedEvent(utils.NetworkEventType, MockEvent{ID: "second"}, baseTime.Add(1*time.Second), "container", apitypes.Process{}),
	}

	// Sort by timestamp (manually for test)
	if events[0].Timestamp.After(events[1].Timestamp) {
		events[0], events[1] = events[1], events[0]
	}
	if events[1].Timestamp.After(events[2].Timestamp) {
		events[1], events[2] = events[2], events[1]
	}
	if events[0].Timestamp.After(events[1].Timestamp) {
		events[0], events[1] = events[1], events[0]
	}

	// Verify sorted order
	assert.Equal(t, "first", events[0].Event.(MockEvent).ID)
	assert.Equal(t, "second", events[1].Event.(MockEvent).ID)
	assert.Equal(t, "third", events[2].Event.(MockEvent).ID)

	// Verify timestamps are in order
	assert.True(t, events[0].Timestamp.Before(events[1].Timestamp))
	assert.True(t, events[1].Timestamp.Before(events[2].Timestamp))
}

func TestEnrichedEvent_ContainerIDMatching(t *testing.T) {
	// Test container ID matching scenarios
	testCases := []struct {
		name        string
		containerID string
		expected    string
	}{
		{"Short container ID", "abc123", "abc123"},
		{"Full container ID", "container-123456789abcdef", "container-123456789abcdef"},
		{"Empty container ID", "", ""},
		{"Container ID with special chars", "test-container_123.456", "test-container_123.456"},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			enrichedEvent := NewEnrichedEvent(
				utils.ExecveEventType,
				MockEvent{ID: "test"},
				time.Now(),
				tc.containerID,
				apitypes.Process{},
			)

			assert.Equal(t, tc.expected, enrichedEvent.ContainerID)
		})
	}
}

func TestEnrichedEvent_EventMetadata(t *testing.T) {
	// Test event metadata preservation
	mockEvent := MockEvent{
		ID:        "metadata-test",
		Pod:       "test-pod",
		Namespace: "test-namespace",
		Timestamp: time.Now().UnixNano(),
	}

	enrichedEvent := NewEnrichedEvent(
		utils.ExecveEventType,
		mockEvent,
		time.Now(),
		"test-container",
		apitypes.Process{PID: 1234},
	)

	// Verify original event metadata is preserved
	originalEvent := enrichedEvent.Event.(MockEvent)
	assert.Equal(t, "metadata-test", originalEvent.ID)
	assert.Equal(t, "test-pod", originalEvent.Pod)
	assert.Equal(t, "test-namespace", originalEvent.Namespace)
	assert.Equal(t, mockEvent.Timestamp, originalEvent.Timestamp)

	// Verify enriched metadata
	assert.Equal(t, utils.ExecveEventType, enrichedEvent.EventType)
	assert.Equal(t, "test-container", enrichedEvent.ContainerID)
	assert.Equal(t, uint32(1234), enrichedEvent.ProcessTree.PID)
}

func TestEnrichedEvent_EmptyProcessTree(t *testing.T) {
	// Test handling of empty process tree
	enrichedEvent := NewEnrichedEvent(
		utils.OpenEventType,
		MockEvent{ID: "no-process-tree"},
		time.Now(),
		"container-123",
		apitypes.Process{}, // Empty process tree
	)

	assert.Equal(t, utils.OpenEventType, enrichedEvent.EventType)
	assert.Equal(t, "container-123", enrichedEvent.ContainerID)
	assert.Equal(t, uint32(0), enrichedEvent.ProcessTree.PID)
	assert.Equal(t, "", enrichedEvent.ProcessTree.Comm)
	assert.Equal(t, "", enrichedEvent.ProcessTree.Path)
	assert.Nil(t, enrichedEvent.ProcessTree.ChildrenMap)
}
