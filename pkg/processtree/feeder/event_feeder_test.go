package feeder

import (
	"context"
	"testing"
	"time"

	tracerexectype "github.com/inspektor-gadget/inspektor-gadget/pkg/gadgets/trace/exec/types"
	eventtypes "github.com/inspektor-gadget/inspektor-gadget/pkg/types"
	events "github.com/kubescape/node-agent/pkg/ebpf/events"
	tracerexittype "github.com/kubescape/node-agent/pkg/ebpf/gadgets/exit/types"
	"github.com/kubescape/node-agent/pkg/utils"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestEventFeeder_ReportEvent(t *testing.T) {
	feeder := NewEventFeeder()

	// Start the feeder
	ctx := context.Background()
	err := feeder.Start(ctx)
	assert.NoError(t, err)
	defer feeder.Stop()

	// Create a channel to receive events
	eventChan := make(chan ProcessEvent, 1)
	feeder.Subscribe(eventChan)

	// Create a mock exec event
	execEvent := &events.ExecEvent{
		Event: tracerexectype.Event{
			Event: eventtypes.Event{
				CommonData: eventtypes.CommonData{
					Runtime: eventtypes.BasicRuntimeMetadata{
						ContainerID: "container-123",
					},
				},
			},
			Pid:     1234,
			Ppid:    1000,
			Comm:    "test-process",
			ExePath: "/usr/bin/test-process",
			Args:    []string{"/usr/bin/test-process", "--arg1", "value1"},
			Uid:     1000,
			Gid:     1000,
		},
	}

	// Report the event
	feeder.ReportEvent(utils.ExecveEventType, execEvent)

	// Wait for the event to be processed
	select {
	case event := <-eventChan:
		assert.Equal(t, ExecEvent, event.Type)
		assert.Equal(t, uint32(1234), event.PID)
		assert.Equal(t, uint32(1000), event.PPID)
		assert.Equal(t, "test-process", event.Comm)
		assert.Equal(t, "/usr/bin/test-process", event.Path)
		assert.Equal(t, "/usr/bin/test-process --arg1 value1", event.Cmdline)
		assert.Equal(t, uint32(1000), *event.Uid)
		assert.Equal(t, uint32(1000), *event.Gid)
		assert.Equal(t, "container-123", event.ContainerID)
	case <-time.After(1 * time.Second):
		t.Fatal("Timeout waiting for event")
	}
}

func TestEventFeeder_UnknownEventType(t *testing.T) {
	feeder := NewEventFeeder()

	// Start the feeder
	ctx := context.Background()
	err := feeder.Start(ctx)
	assert.NoError(t, err)
	defer feeder.Stop()

	// Create a channel to receive events
	eventChan := make(chan ProcessEvent, 1)
	feeder.Subscribe(eventChan)

	// Create a mock event with unknown type
	mockEvent := &events.ExecEvent{} // Using ExecEvent as a mock

	// Report the event with unknown type
	feeder.ReportEvent("unknown-event-type", mockEvent)

	// Wait a bit to ensure no event is sent
	select {
	case <-eventChan:
		t.Fatal("Expected no event for unknown event type")
	case <-time.After(100 * time.Millisecond):
		// This is expected - no event should be sent
	}
}

func TestEventFeeder_NotStarted(t *testing.T) {
	feeder := NewEventFeeder()

	// Don't start the feeder
	eventChan := make(chan ProcessEvent, 1)
	feeder.Subscribe(eventChan)

	// Create a mock exec event
	execEvent := &events.ExecEvent{
		Event: tracerexectype.Event{
			Event: eventtypes.Event{
				CommonData: eventtypes.CommonData{
					Runtime: eventtypes.BasicRuntimeMetadata{
						ContainerID: "container-123",
					},
				},
			},
			Pid:     1234,
			Ppid:    1000,
			Comm:    "test-process",
			ExePath: "/usr/bin/test-process",
			Args:    []string{"/usr/bin/test-process"},
			Uid:     1000,
			Gid:     1000,
		},
	}

	// Report the event
	feeder.ReportEvent(utils.ExecveEventType, execEvent)

	// Wait a bit to ensure no event is sent
	select {
	case <-eventChan:
		t.Fatal("Expected no event when feeder is not started")
	case <-time.After(100 * time.Millisecond):
		// This is expected - no event should be sent
	}
}

func TestEventFeeder_ExitEvent(t *testing.T) {
	ef := NewEventFeeder()
	ctx := context.Background()
	err := ef.Start(ctx)
	require.NoError(t, err)
	defer ef.Stop()

	// Create a channel to receive events
	eventChan := make(chan ProcessEvent, 1)
	ef.Subscribe(eventChan)

	// Create a mock exit event
	exitEvent := &tracerexittype.Event{
		Pid:        123,
		PPid:       1,
		Comm:       "test-process",
		ExePath:    "/usr/bin/test",
		ExitCode:   0,
		ExitSignal: 0,
	}

	// Report the exit event
	ef.ReportEvent(utils.ExitEventType, exitEvent)

	// Wait for the event
	select {
	case event := <-eventChan:
		assert.Equal(t, ExitEvent, event.Type)
		assert.Equal(t, uint32(123), event.PID)
		assert.Equal(t, uint32(1), event.PPID)
		assert.Equal(t, "test-process", event.Comm)
		assert.Equal(t, "/usr/bin/test", event.Path)
	case <-time.After(1 * time.Second):
		t.Fatal("timeout waiting for exit event")
	}
}
