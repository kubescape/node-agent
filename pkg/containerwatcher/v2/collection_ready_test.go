package containerwatcher

import (
	"context"
	"testing"
	"time"

	"github.com/kubescape/node-agent/pkg/config"
	"github.com/kubescape/node-agent/pkg/containerprofilemanager"
	"github.com/kubescape/node-agent/pkg/containerwatcher"
	"github.com/kubescape/node-agent/pkg/utils"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

type startRecordingTracer struct {
	eventType utils.EventType
	started   chan struct{}
}

func (t *startRecordingTracer) Start(context.Context) error {
	close(t.started)
	return nil
}
func (t *startRecordingTracer) Stop() error                   { return nil }
func (t *startRecordingTracer) GetName() string               { return string(t.eventType) }
func (t *startRecordingTracer) GetEventType() utils.EventType { return t.eventType }
func (t *startRecordingTracer) IsEnabled(config.Config) bool  { return true }
func (t *startRecordingTracer) wasStarted() bool              { return isClosed(t.started) }
func newStartRecordingTracer(e utils.EventType) *startRecordingTracer {
	return &startRecordingTracer{eventType: e, started: make(chan struct{})}
}

type staticTracerFactory []containerwatcher.TracerInterface

func (f staticTracerFactory) CreateAllTracers(manager containerwatcher.TracerRegistrer) {
	for _, tracer := range f {
		manager.RegisterTracer(tracer)
	}
}

func isClosed(ch <-chan struct{}) bool {
	select {
	case <-ch:
		return true
	default:
		return false
	}
}

func waitClosed(t *testing.T, ch <-chan struct{}, what string) {
	t.Helper()
	select {
	case <-ch:
	case <-time.After(5 * time.Second):
		t.Fatalf("timed out waiting for %s", what)
	}
}

// TestStartAllTracersWaitsForCollectionReadyHook: the procfs scan starts while
// the hook runs, but no eBPF tracer starts until the hook has returned.
func TestStartAllTracersWaitsForCollectionReadyHook(t *testing.T) {
	procfs := newStartRecordingTracer(utils.ProcfsEventType)
	exec := newStartRecordingTracer(utils.ExecveEventType)
	tm := NewTracerManager(config.Config{}, staticTracerFactory{procfs, exec})
	gate := make(chan struct{})
	tm.beforeEBPFTracers = gate

	ctx, cancel := context.WithCancel(context.Background())
	result := make(chan error, 1)
	go func() { result <- tm.StartAllTracers(ctx) }()

	waitClosed(t, procfs.started, "procfs tracer start")
	time.Sleep(100 * time.Millisecond)
	assert.False(t, exec.wasStarted(), "eBPF tracer started before the collection-ready hook returned")

	close(gate)
	waitClosed(t, exec.started, "eBPF tracer start")
	cancel() // skip the 2 s stagger after the last tracer
	assert.ErrorIs(t, <-result, context.Canceled)
}

// TestStartAllTracersCancelledWhileWaitingForHook: a cancelled start returns
// without starting an eBPF tracer.
func TestStartAllTracersCancelledWhileWaitingForHook(t *testing.T) {
	procfs := newStartRecordingTracer(utils.ProcfsEventType)
	exec := newStartRecordingTracer(utils.ExecveEventType)
	tm := NewTracerManager(config.Config{}, staticTracerFactory{procfs, exec})
	tm.beforeEBPFTracers = make(chan struct{}) // never closed

	ctx, cancel := context.WithCancel(context.Background())
	result := make(chan error, 1)
	go func() { result <- tm.StartAllTracers(ctx) }()
	waitClosed(t, procfs.started, "procfs tracer start")
	cancel()
	assert.ErrorIs(t, <-result, context.Canceled)
	assert.False(t, exec.wasStarted())
}

// TestStartAllTracersBoundsWaitForHook: a hook that never returns delays the
// eBPF tracers only up to the bound.
func TestStartAllTracersBoundsWaitForHook(t *testing.T) {
	procfs := newStartRecordingTracer(utils.ProcfsEventType)
	exec := newStartRecordingTracer(utils.ExecveEventType)
	tm := NewTracerManager(config.Config{}, staticTracerFactory{procfs, exec})
	tm.beforeEBPFTracers = make(chan struct{}) // a hung hook: never closed
	begin := time.Now()
	tm.beforeEBPFTracersDeadline = begin.Add(200 * time.Millisecond)

	ctx, cancel := context.WithCancel(context.Background())
	result := make(chan error, 1)
	go func() { result <- tm.StartAllTracers(ctx) }()

	waitClosed(t, procfs.started, "procfs tracer start")
	time.Sleep(50 * time.Millisecond)
	assert.False(t, exec.wasStarted(), "eBPF tracer started before the bound")
	waitClosed(t, exec.started, "eBPF tracer start after the bound")
	assert.GreaterOrEqual(t, time.Since(begin), 200*time.Millisecond)
	cancel() // skip the 2 s stagger after the last tracer
	assert.ErrorIs(t, <-result, context.Canceled)
}

func TestRunCollectionReady(t *testing.T) {
	t.Run("no hook", func(t *testing.T) {
		cw := &ContainerWatcher{}
		assert.True(t, isClosed(cw.runCollectionReady(context.Background())))
	})

	t.Run("context done before the collection is ready", func(t *testing.T) {
		called := false
		cw := &ContainerWatcher{}
		cw.OnCollectionReady(func() { called = true }, 0)
		ctx, cancel := context.WithCancel(context.Background())
		cancel()
		done := cw.runCollectionReady(ctx)
		assert.True(t, isClosed(done))
		assert.False(t, called, "hook ran although the start was cancelled")
	})

	t.Run("done closes only after the hook returns", func(t *testing.T) {
		entered, release := make(chan struct{}), make(chan struct{})
		cw := &ContainerWatcher{}
		registered := cw.OnCollectionReady(func() {
			close(entered)
			<-release
		}, 0)
		done := cw.runCollectionReady(context.Background())
		waitClosed(t, entered, "hook entry")
		assert.False(t, isClosed(done))
		assert.False(t, isClosed(registered))
		close(release)
		waitClosed(t, done, "hook return")
		waitClosed(t, registered, "OnCollectionReady channel after the hook returned")
	})

	t.Run("hook runs at most once", func(t *testing.T) {
		calls := 0
		cw := &ContainerWatcher{}
		cw.OnCollectionReady(func() { calls++ }, 0)
		waitClosed(t, cw.runCollectionReady(context.Background()), "first run")
		waitClosed(t, cw.runCollectionReady(context.Background()), "second run")
		assert.Equal(t, 1, calls)
	})
}

// TestAwaitCollectionReadyBounded: Start's wait for a hook still blocked ends
// at the bound (Start then returns and releases the lock Ready needs), while
// the hook's own channel stays open until it returns.
func TestAwaitCollectionReadyBounded(t *testing.T) {
	release := make(chan struct{})
	cw := &ContainerWatcher{}
	registered := cw.OnCollectionReady(func() { <-release }, 0)
	done := cw.runCollectionReady(context.Background())

	begin := time.Now()
	assert.False(t, awaitCollectionReady(done, begin.Add(100*time.Millisecond)), "a blocked hook reported done")
	elapsed := time.Since(begin)
	assert.GreaterOrEqual(t, elapsed, 100*time.Millisecond)
	assert.Less(t, elapsed, 2*time.Second)
	assert.False(t, isClosed(registered), "channel closed while the hook still runs")

	close(release)
	waitClosed(t, registered, "OnCollectionReady channel after the hook returned")
	assert.True(t, awaitCollectionReady(done, time.Time{}))
}

// TestStartFailureClosesHookChannel: a Start that returns before the
// collection is ready never runs the hook and closes its channel, so a caller
// waiting on it is not stuck; Ready is not held.
func TestStartFailureClosesHookChannel(t *testing.T) {
	called := false
	cw := &ContainerWatcher{running: true} // Start fails at once: already running
	registered := cw.OnCollectionReady(func() { called = true }, time.Minute)
	assert.Error(t, cw.Start(context.Background()))
	waitClosed(t, registered, "OnCollectionReady channel after a failed Start")
	assert.False(t, called)
	assert.True(t, cw.Ready())
}

// TestStartBoundsWaitForHungHook drives the real Start with the collection
// and the tracing pipeline stubbed: a hook that never returns delays Start
// only up to maxTracerDelay, after which Start returns, releases its lock and
// Ready answers, while the hook's channel stays open.
func TestStartBoundsWaitForHungHook(t *testing.T) {
	release := make(chan struct{})
	defer close(release)
	cw := &ContainerWatcher{containerProfileManager: containerprofilemanager.CreateContainerProfileManagerMock()}
	cw.startCollection = func(context.Context) error { return nil }
	var pipelineDeadline time.Time
	cw.startTracing = func(_ context.Context, _ <-chan struct{}, deadline time.Time) error {
		pipelineDeadline = deadline
		return nil
	}
	registered := cw.OnCollectionReady(func() { <-release }, 200*time.Millisecond)

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	begin := time.Now()
	result := make(chan error, 1)
	go func() { result <- cw.Start(ctx) }()
	select {
	case err := <-result:
		require.NoError(t, err)
	case <-time.After(5 * time.Second):
		t.Fatal("Start waited for the hung hook past its bound")
	}
	assert.GreaterOrEqual(t, time.Since(begin), 200*time.Millisecond, "Start did not wait for the hook up to the bound")
	assert.False(t, pipelineDeadline.IsZero(), "the tracing pipeline got no bound")

	ready := make(chan bool, 1)
	go func() { ready <- cw.Ready() }()
	select {
	case r := <-ready:
		assert.True(t, r)
	case <-time.After(time.Second):
		t.Fatal("Ready blocked after Start returned")
	}
	assert.False(t, isClosed(registered), "hook channel closed while the hook still runs")
}
