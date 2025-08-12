package feeder

import (
	"context"
	"os"
	"testing"
	"time"

	"github.com/kubescape/node-agent/pkg/processtree/conversion"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestNewProcfsFeeder(t *testing.T) {
	interval := 100 * time.Millisecond
	feeder := NewProcfsFeeder(interval)

	assert.NotNil(t, feeder)
	assert.Equal(t, interval, feeder.interval)
	assert.Equal(t, "/proc", feeder.procfsPath)
	assert.Nil(t, feeder.ctx)
	assert.Empty(t, feeder.subscribers)
}

func TestProcfsFeeder_Start(t *testing.T) {
	feeder := NewProcfsFeeder(100 * time.Millisecond)
	ctx := context.Background()

	// Test successful start
	err := feeder.Start(ctx)
	assert.NoError(t, err)
	assert.NotNil(t, feeder.ctx)
	assert.NotNil(t, feeder.procfs)

	// Test double start
	err = feeder.Start(ctx)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "already started")

	// Cleanup
	feeder.Stop()
}

func TestProcfsFeeder_Stop(t *testing.T) {
	feeder := NewProcfsFeeder(100 * time.Millisecond)
	ctx := context.Background()

	// Test stop without start
	err := feeder.Stop()
	assert.NoError(t, err)

	// Test stop after start
	err = feeder.Start(ctx)
	require.NoError(t, err)

	err = feeder.Stop()
	assert.NoError(t, err)
	// After stopping, cancel should be nil to allow a restart.
	// The context itself is intentionally not nilled out to prevent a race condition.
	assert.Nil(t, feeder.cancel, "Cancel func should be nil after stop")
}

func TestProcfsFeeder_Subscribe(t *testing.T) {
	feeder := NewProcfsFeeder(100 * time.Millisecond)
	ch := make(chan conversion.ProcessEvent, 1)

	feeder.Subscribe(ch)
	require.Len(t, feeder.subscribers, 1)
	// Cast the bidirectional channel `ch` to the send-only type to match
	// the type in the slice, allowing `assert.Equal` to work correctly.
	assert.Equal(t, (chan<- conversion.ProcessEvent)(ch), feeder.subscribers[0])

	// Test multiple subscribers
	ch2 := make(chan conversion.ProcessEvent, 1)
	feeder.Subscribe(ch2)
	require.Len(t, feeder.subscribers, 2)
	assert.Equal(t, (chan<- conversion.ProcessEvent)(ch2), feeder.subscribers[1])
}

func TestProcfsFeeder_ReadProcessInfo(t *testing.T) {
	feeder := NewProcfsFeeder(100 * time.Millisecond)
	ctx := context.Background()

	err := feeder.Start(ctx)
	require.NoError(t, err, "Feeder should start without error")
	defer feeder.Stop()

	// Test reading info for PID 1 (init/systemd process)
	// This process is guaranteed to exist on any Linux system.
	pid1_event, err := feeder.readProcessInfo(1)
	assert.NoError(t, err)
	assert.Equal(t, conversion.ProcfsEvent, pid1_event.Type)
	assert.Equal(t, uint32(1), pid1_event.PID)
	assert.NotEmpty(t, pid1_event.Comm, "Comm for PID 1 should not be empty")
	// On modern systems, PPID for PID 1 is 0.
	assert.Zero(t, pid1_event.PPID, "PPID for PID 1 should be 0")
	// Note: readProcessInfo does NOT populate Pcomm. This is handled by scanProcfs.
	assert.Empty(t, pid1_event.Pcomm, "Pcomm should be empty from readProcessInfo")

	// Test reading info for a non-existent PID
	_, err = feeder.readProcessInfo(999999)
	assert.Error(t, err)
}

func TestProcfsFeeder_GetProcessComm(t *testing.T) {
	feeder := NewProcfsFeeder(100 * time.Millisecond)
	ctx := context.Background()

	err := feeder.Start(ctx)
	require.NoError(t, err, "Feeder should start without error")
	defer feeder.Stop()

	// Test getting comm for PID 1
	comm, err := feeder.getProcessComm(1)
	assert.NoError(t, err)
	assert.NotEmpty(t, comm)

	// Test getting comm for non-existent PID
	_, err = feeder.getProcessComm(999999)
	assert.Error(t, err)
}

func TestProcfsFeeder_BroadcastEvent(t *testing.T) {
	feeder := NewProcfsFeeder(100 * time.Millisecond)
	ch1 := make(chan conversion.ProcessEvent, 1)
	ch2 := make(chan conversion.ProcessEvent, 1)

	feeder.Subscribe(ch1)
	feeder.Subscribe(ch2)

	event := conversion.ProcessEvent{PID: 123, Comm: "test-process"}
	feeder.broadcastEvent(event)

	// Check that both subscribers received the event
	timeout := time.After(100 * time.Millisecond)
	for i := 0; i < 2; i++ {
		select {
		case receivedEvent := <-ch1:
			assert.Equal(t, event, receivedEvent)
		case receivedEvent := <-ch2:
			assert.Equal(t, event, receivedEvent)
		case <-timeout:
			t.Fatal("timed out waiting for event")
		}
	}
}

func TestProcfsFeeder_ScanProcfs(t *testing.T) {
	feeder := NewProcfsFeeder(100 * time.Millisecond)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	err := feeder.Start(ctx)
	require.NoError(t, err)
	defer feeder.Stop()

	ch := make(chan conversion.ProcessEvent, 256) // Buffer to hold events
	feeder.Subscribe(ch)

	// Run the scan
	feeder.scanProcfs()

	// Check that we received events. We expect at least one (for PID 1).
	// We read in a non-blocking way with a timeout.
	var receivedEvents []conversion.ProcessEvent
	timeout := time.After(500 * time.Millisecond)
ReceiveLoop:
	for {
		select {
		case event := <-ch:
			receivedEvents = append(receivedEvents, event)
		case <-timeout:
			break ReceiveLoop
		}
	}

	assert.NotEmpty(t, receivedEvents, "should have received at least one process event")

	// Validate that the parent lookup logic worked.
	// Find our own process and check if its parent's comm is populated.
	ownPid := uint32(os.Getpid())
	var ownProcessEvent *conversion.ProcessEvent
	for i := range receivedEvents {
		if receivedEvents[i].PID == ownPid {
			ownProcessEvent = &receivedEvents[i]
			break
		}
	}

	require.NotNil(t, ownProcessEvent, "The test's own process should be found in the scan")
	assert.NotEmpty(t, ownProcessEvent.Pcomm, "Parent comm for the test process should be populated")
	assert.Equal(t, uint32(os.Getppid()), ownProcessEvent.PPID, "PPID of test process should match os.Getppid()")
}

func TestProcfsFeeder_ProcessSpecificPID(t *testing.T) {
	feeder := NewProcfsFeeder(100 * time.Millisecond)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	err := feeder.Start(ctx)
	require.NoError(t, err)
	defer feeder.Stop()

	ch := make(chan conversion.ProcessEvent, 1)
	feeder.Subscribe(ch)

	// Test processing PID 1
	err = feeder.ProcessSpecificPID(1)
	assert.NoError(t, err)

	// Check that an event was broadcasted
	select {
	case event := <-ch:
		assert.Equal(t, uint32(1), event.PID)
	case <-time.After(100 * time.Millisecond):
		t.Fatal("timed out waiting for event from ProcessSpecificPID")
	}

	// Test processing a non-existent PID
	err = feeder.ProcessSpecificPID(999999)
	assert.Error(t, err)
}
