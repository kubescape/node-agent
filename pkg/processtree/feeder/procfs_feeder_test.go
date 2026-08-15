package feeder

import (
	"context"
	"os"
	"testing"
	"time"

	"github.com/kubescape/node-agent/pkg/processtree"
	"github.com/kubescape/node-agent/pkg/processtree/conversion"
	"github.com/prometheus/procfs"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestNewProcfsFeeder(t *testing.T) {
	interval := 100 * time.Millisecond
	mockManager := processtree.NewProcessTreeManagerMock()
	feeder := NewProcfsFeeder(interval, 10*time.Millisecond, mockManager)

	assert.NotNil(t, feeder)
	assert.Equal(t, interval, feeder.interval)
	assert.Equal(t, "/proc", feeder.procfsPath)
	assert.Nil(t, feeder.ctx)
	assert.Empty(t, feeder.subscribers)
}

func TestProcfsFeeder_Start(t *testing.T) {
	mockManager := processtree.NewProcessTreeManagerMock()
	feeder := NewProcfsFeeder(100*time.Millisecond, 10*time.Millisecond, mockManager)
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
	mockManager := processtree.NewProcessTreeManagerMock()
	feeder := NewProcfsFeeder(100*time.Millisecond, 10*time.Millisecond, mockManager)
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
	mockManager := processtree.NewProcessTreeManagerMock()
	feeder := NewProcfsFeeder(100*time.Millisecond, 10*time.Millisecond, mockManager)
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
	mockManager := processtree.NewProcessTreeManagerMock()
	feeder := NewProcfsFeeder(100*time.Millisecond, 10*time.Millisecond, mockManager)
	ctx := context.Background()

	err := feeder.Start(ctx)
	require.NoError(t, err, "Feeder should start without error")
	defer feeder.Stop()

	// Test reading info for PID 1 (init/systemd process)
	// This process is guaranteed to exist on any Linux system.
	pid1Event, err := feeder.readProcessInfo(1)
	assert.NoError(t, err)
	assert.Equal(t, conversion.ProcfsEvent, pid1Event.Type)
	assert.Equal(t, uint32(1), pid1Event.PID)
	assert.NotEmpty(t, pid1Event.Comm, "Comm for PID 1 should not be empty")
	// On modern systems, PPID for PID 1 is 0.
	assert.Zero(t, pid1Event.PPID, "PPID for PID 1 should be 0")
	// Note: readProcessInfo does NOT populate Pcomm. This is handled by scanProcfs.
	assert.Empty(t, pid1Event.Pcomm, "Pcomm should be empty from readProcessInfo")

	// Test reading info for a non-existent PID
	_, err = feeder.readProcessInfo(999999)
	assert.Error(t, err)
}

func TestProcfsFeeder_ReadProcessInfo_StartTime(t *testing.T) {
	mockManager := processtree.NewProcessTreeManagerMock()
	feeder := NewProcfsFeeder(100*time.Millisecond, 10*time.Millisecond, mockManager)
	require.NoError(t, feeder.Start(context.Background()))
	defer feeder.Stop()

	event, err := feeder.readProcessInfo(uint32(os.Getpid()))
	require.NoError(t, err)

	// Boot-relative nanoseconds: non-zero and an exact multiple of 10ms,
	// because /proc/<pid>/stat field 22 is denominated in USER_HZ=100 ticks.
	assert.NotZero(t, event.StartTimeNs)
	assert.Zero(t, event.StartTimeNs%10_000_000,
		"procfs-derived StartTimeNs must be an exact multiple of 10^7 ns")

	// Wall-clock derivation: btime + ticks/HZ. Sanity: within [boot, now].
	assert.False(t, event.StartTimeWall.IsZero())
	assert.True(t, event.StartTimeWall.Before(time.Now().Add(2*time.Second)))
	// This process started after boot: wall - bootNs must land near btime.
	// (Loose check: StartTimeWall minus the boot-relative duration is in the past.)
	assert.True(t, event.StartTimeWall.Add(-time.Duration(event.StartTimeNs)).Before(time.Now()))

	// Pin the conversion against an independently read field 22 and the contract's
	// literal 10^7, so a drifted ticksPerSecond fails deterministically instead of
	// only on machines whose uptime happens to make the error visible.
	p, err := procfs.NewProc(os.Getpid())
	require.NoError(t, err)
	stat, err := p.Stat()
	require.NoError(t, err)
	assert.Equal(t, stat.Starttime*10_000_000, event.StartTimeNs,
		"conversion must be exactly field 22 ticks * 10^7 ns (USER_HZ=100)")

	// Sharper check on the arithmetic itself: this is the test binary's own pid,
	// so its real creation time is moments ago. A wrong btime or a wrong tick
	// scaling would land this decades or hours away rather than minutes.
	assert.WithinDuration(t, time.Now(), event.StartTimeWall, 5*time.Minute,
		"btime + ticks/HZ must reconstruct the test process's actual start time")
}

func TestProcfsFeeder_GetProcessComm(t *testing.T) {
	mockManager := processtree.NewProcessTreeManagerMock()
	feeder := NewProcfsFeeder(100*time.Millisecond, 10*time.Millisecond, mockManager)
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
	mockManager := processtree.NewProcessTreeManagerMock()
	feeder := NewProcfsFeeder(100*time.Millisecond, 10*time.Millisecond, mockManager)
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
	mockManager := processtree.NewProcessTreeManagerMock()
	feeder := NewProcfsFeeder(100*time.Millisecond, 10*time.Millisecond, mockManager)
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
	mockManager := processtree.NewProcessTreeManagerMock()
	feeder := NewProcfsFeeder(100*time.Millisecond, 10*time.Millisecond, mockManager)
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
