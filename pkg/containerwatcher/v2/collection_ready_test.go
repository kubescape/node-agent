package containerwatcher

import (
	"context"
	"testing"
	"time"

	"github.com/kubescape/node-agent/pkg/config"
	"github.com/kubescape/node-agent/pkg/containerwatcher"
	"github.com/kubescape/node-agent/pkg/utils"
	"github.com/stretchr/testify/assert"
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
	tm.beforeEBPFTracersMaxWait = 200 * time.Millisecond

	ctx, cancel := context.WithCancel(context.Background())
	result := make(chan error, 1)
	begin := time.Now()
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
		cw.OnCollectionReady(func() {
			close(entered)
			<-release
		}, 0)
		done := cw.runCollectionReady(context.Background())
		waitClosed(t, entered, "hook entry")
		assert.False(t, isClosed(done))
		close(release)
		waitClosed(t, done, "hook return")
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
