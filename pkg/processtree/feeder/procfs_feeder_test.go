package feeder

import (
	"context"
	"testing"
	"time"

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
	assert.NoError(t, err)

	err = feeder.Stop()
	assert.NoError(t, err)
}

func TestProcfsFeeder_Subscribe(t *testing.T) {
	feeder := NewProcfsFeeder(100 * time.Millisecond)
	ch := make(chan ProcessEvent, 1)

	feeder.Subscribe(ch)
	assert.Len(t, feeder.subscribers, 1)

	// Test multiple subscribers
	ch2 := make(chan ProcessEvent, 1)
	feeder.Subscribe(ch2)
	assert.Len(t, feeder.subscribers, 2)
}

func TestProcfsFeeder_ReadProcessInfo(t *testing.T) {
	feeder := NewProcfsFeeder(100 * time.Millisecond)
	ctx := context.Background()

	// Start the feeder to initialize procfs
	err := feeder.Start(ctx)
	require.NoError(t, err)
	defer feeder.Stop()

	// Test reading info for PID 1 (init process)
	event, err := feeder.readProcessInfo(1)
	assert.NoError(t, err)
	assert.Equal(t, ProcfsEvent, event.Type)
	assert.Equal(t, uint32(1), event.PID)
	assert.NotEmpty(t, event.Comm)
	assert.Zero(t, event.PPID) // init should have PPID 0

	// Test reading info for a non-existent PID
	_, err = feeder.readProcessInfo(999999)
	assert.Error(t, err)
}

func TestProcfsFeeder_GetProcessComm(t *testing.T) {
	feeder := NewProcfsFeeder(100 * time.Millisecond)
	ctx := context.Background()

	// Start the feeder to initialize procfs
	err := feeder.Start(ctx)
	require.NoError(t, err)
	defer feeder.Stop()

	// Test getting comm for PID 1
	comm, err := feeder.getProcessComm(1)
	assert.NoError(t, err)
	assert.NotEmpty(t, comm)

	// Test getting comm for non-existent PID
	_, err = feeder.getProcessComm(999999)
	assert.Error(t, err)
}

func TestProcfsFeeder_ProcessSpecificPID(t *testing.T) {
	feeder := NewProcfsFeeder(100 * time.Millisecond)
	ctx := context.Background()

	// Start the feeder to initialize procfs
	err := feeder.Start(ctx)
	require.NoError(t, err)
	defer feeder.Stop()

	// Test processing a specific PID
	err = feeder.ProcessSpecificPID(1)
	assert.NoError(t, err)

	// Test processing a non-existent PID
	err = feeder.ProcessSpecificPID(999999)
	assert.Error(t, err)
}

func TestProcfsFeeder_BroadcastEvent(t *testing.T) {
	feeder := NewProcfsFeeder(100 * time.Millisecond)
	ch1 := make(chan ProcessEvent, 1)
	ch2 := make(chan ProcessEvent, 1)

	feeder.Subscribe(ch1)
	feeder.Subscribe(ch2)

	event := ProcessEvent{
		Type:      ProcfsEvent,
		Timestamp: time.Now(),
		PID:       123,
		Comm:      "test-process",
	}

	feeder.broadcastEvent(event)

	// Check that both subscribers received the event
	select {
	case receivedEvent := <-ch1:
		assert.Equal(t, event.PID, receivedEvent.PID)
		assert.Equal(t, event.Comm, receivedEvent.Comm)
	default:
		t.Error("Expected event on ch1")
	}

	select {
	case receivedEvent := <-ch2:
		assert.Equal(t, event.PID, receivedEvent.PID)
		assert.Equal(t, event.Comm, receivedEvent.Comm)
	default:
		t.Error("Expected event on ch2")
	}
}

func TestProcfsFeeder_ScanProcfs(t *testing.T) {
	feeder := NewProcfsFeeder(100 * time.Millisecond)
	ctx := context.Background()

	// Start the feeder to initialize procfs
	err := feeder.Start(ctx)
	require.NoError(t, err)
	defer feeder.Stop()

	// Test scanning procfs (should not panic and should process some processes)
	feeder.scanProcfs()
	// This test mainly ensures the method doesn't panic
	// In a real environment, it would process actual processes
	time.Sleep(100 * time.Millisecond)
}

func TestProcfsFeeder_ProcessProcfsEntry(t *testing.T) {
	feeder := NewProcfsFeeder(100 * time.Millisecond)
	ctx := context.Background()

	// Start the feeder to initialize procfs
	err := feeder.Start(ctx)
	require.NoError(t, err)
	defer feeder.Stop()

	// Test processing a valid PID
	feeder.processProcfsEntry(1)
	// This test mainly ensures the method doesn't panic

	// Test processing an invalid PID
	feeder.processProcfsEntry(999999)
	// This should handle the error gracefully
}
