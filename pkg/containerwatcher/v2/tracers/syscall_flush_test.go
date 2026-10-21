package tracers

import (
	"context"
	"testing"
	"time"

	"github.com/inspektor-gadget/inspektor-gadget/pkg/datasource"
	gadgetcontext "github.com/inspektor-gadget/inspektor-gadget/pkg/gadget-context"
	"github.com/inspektor-gadget/inspektor-gadget/pkg/gadget-service/api"
	"github.com/inspektor-gadget/inspektor-gadget/pkg/utils/syscalls"
	"github.com/kubescape/node-agent/pkg/utils"
	"github.com/stretchr/testify/require"
)

func syscallFlushHarness(t *testing.T, report func(string, []string)) (*SyscallTracer, <-chan struct{}, func(bool)) {
	t.Helper()
	// Mirror syscallTestDatasource's exact field order: DatasourceEvent caches
	// accessors globally by event kind, so this array schema must stay identical.
	gadgetCtx := gadgetcontext.New(t.Context(), "syscall-flush-test")
	ds, err := gadgetCtx.RegisterDataSource(datasource.TypeArray, syscallDataSourceName)
	require.NoError(t, err)
	container, err := ds.AddField("runtime.containerId", api.Kind_String)
	require.NoError(t, err)
	bitmap, err := ds.AddField("syscalls", api.Kind_Bytes)
	require.NoError(t, err)
	triggers := make(chan struct{}, 100)
	st := &SyscallTracer{triggerFetch: func() { triggers <- struct{}{} }, reportSyscalls: report,
		eventCallback: func(event utils.K8sEvent, _ string, _ uint32) {
			defer event.(*utils.DatasourceEvent).Release()
			if got := event.(*utils.DatasourceEvent).GetContainerID(); got != "container" {
				t.Errorf("array callback ran before enrichment: %q", got)
			}
		}}
	// Exercise real operator wiring, including ignoring unrelated single sources.
	_, err = gadgetCtx.RegisterDataSource(datasource.TypeSingle, "unrelated")
	require.NoError(t, err)
	require.NoError(t, ds.Subscribe(func(_ datasource.DataSource, data datasource.Data) error {
		return container.PutString(data, "container")
	}, 0))
	_, err = st.eventOperator().InstantiateDataOperator(gadgetCtx, nil)
	require.NoError(t, err)
	emit := func(nonempty bool) {
		t.Helper()
		array, err := ds.NewPacketArray()
		require.NoError(t, err)
		if nonempty {
			data := array.New()
			require.NoError(t, container.PutString(data, "unenriched"))
			bits := make([]byte, 512)
			for i := range bits {
				if _, ok := syscalls.GetSyscallNameByNumber(i); ok {
					bits[i] = 1
					break
				}
			}
			require.NoError(t, bitmap.PutBytes(data, bits))
			array.Append(data)
		}
		require.NoError(t, ds.EmitAndRelease(array))
	}
	return st, triggers, emit
}

func awaitSyscallTrigger(t *testing.T, triggers <-chan struct{}) {
	t.Helper()
	select {
	case <-triggers:
	case <-time.After(2 * time.Second):
		t.Fatal("missing fetch trigger")
	}
}
func awaitSyscallFlush(t *testing.T, result <-chan error) error {
	t.Helper()
	select {
	case err := <-result:
		return err
	case <-time.After(2 * time.Second):
		t.Fatal("flush did not finish")
		return nil
	}
}
func startSyscallFlush(st *SyscallTracer, ctx context.Context) <-chan error {
	result := make(chan error, 1)
	go func() { result <- st.Flush(ctx) }()
	return result
}

func TestSyscallFlushWaitsForEarlierDeliveryAndEmptyFetches(t *testing.T) {
	blocked := make(chan struct{})
	defer func() {
		select {
		case <-blocked:
		default:
			close(blocked)
		}
	}()
	entered := make(chan struct{})
	st, triggers, emit := syscallFlushHarness(t, func(string, []string) { close(entered); <-blocked })
	emit(true)
	select {
	case <-entered:
	case <-time.After(2 * time.Second):
		t.Fatal("report did not start")
	}
	ctx, cancel := context.WithTimeout(t.Context(), 3*time.Second)
	defer cancel()
	result := startSyscallFlush(st, ctx)
	awaitSyscallTrigger(t, triggers)
	emit(false)
	awaitSyscallTrigger(t, triggers)
	emit(false)
	select {
	case err := <-result:
		t.Fatalf("returned before earlier delivery: %v", err)
	default:
	}
	close(blocked)
	require.NoError(t, awaitSyscallFlush(t, result))
}

func TestSyscallFlushRequiresTwoNewArrayStarts(t *testing.T) {
	st, triggers, emit := syscallFlushHarness(t, func(string, []string) {})
	// A fetch can predate Flush but enter its subscriber only after Flush starts.
	ctx, cancel := context.WithTimeout(t.Context(), 3*time.Second)
	defer cancel()
	result := startSyscallFlush(st, ctx)
	awaitSyscallTrigger(t, triggers)
	emit(false)
	awaitSyscallTrigger(t, triggers)
	select {
	case err := <-result:
		t.Fatalf("first (possibly preexisting) fetch satisfied flush: %v", err)
	default:
	}
	emit(false)
	require.NoError(t, awaitSyscallFlush(t, result))
}

func TestSyscallFlushTimeoutDoesNotCreditLateDeliveryToNextFlush(t *testing.T) {
	blocked := make(chan struct{})
	defer func() {
		select {
		case <-blocked:
		default:
			close(blocked)
		}
	}()
	st, triggers, emit := syscallFlushHarness(t, func(string, []string) { <-blocked })
	ctx, cancel := context.WithCancel(t.Context())
	first := startSyscallFlush(st, ctx)
	awaitSyscallTrigger(t, triggers)
	emit(true)
	awaitSyscallTrigger(t, triggers)
	emit(false)
	cancel()
	require.ErrorIs(t, awaitSyscallFlush(t, first), context.Canceled)
	// The first Flush has exited; discard any retry notifications it already sent.
	for len(triggers) > 0 {
		<-triggers
	}
	nextCtx, nextCancel := context.WithTimeout(t.Context(), 3*time.Second)
	defer nextCancel()
	next := startSyscallFlush(st, nextCtx)
	awaitSyscallTrigger(t, triggers)
	emit(false)
	close(blocked)
	awaitSyscallTrigger(t, triggers)
	select {
	case err := <-next:
		t.Fatalf("late earlier delivery satisfied next flush: %v", err)
	default:
	}
	emit(false)
	require.NoError(t, awaitSyscallFlush(t, next))
}

func TestSyscallFlushStartupRetry(t *testing.T) {
	st, triggers, emit := syscallFlushHarness(t, func(string, []string) {})
	ctx, cancel := context.WithTimeout(t.Context(), 3*time.Second)
	defer cancel()
	result := startSyscallFlush(st, ctx)
	awaitSyscallTrigger(t, triggers) // Missed before gadget trigger registration.
	awaitSyscallTrigger(t, triggers) // Retry must not depend on a periodic poll.
	emit(false)
	awaitSyscallTrigger(t, triggers)
	emit(false)
	require.NoError(t, awaitSyscallFlush(t, result))
}

func TestSyscallFlushConcurrent(t *testing.T) {
	st, _, emit := syscallFlushHarness(t, func(string, []string) {})
	entered, release := make(chan struct{}, 100), make(chan struct{})
	defer func() {
		select {
		case <-release:
		default:
			close(release)
		}
	}()
	// Block each initial trigger so retries from one caller cannot masquerade as
	// entry by the other. Both callers have captured their target before release.
	st.triggerFetch = func() { entered <- struct{}{}; <-release }
	ctx, cancel := context.WithTimeout(t.Context(), 3*time.Second)
	defer cancel()
	first, second := startSyscallFlush(st, ctx), startSyscallFlush(st, ctx)
	awaitSyscallTrigger(t, entered)
	awaitSyscallTrigger(t, entered)
	close(release)
	emit(false)
	emit(false)
	require.NoError(t, awaitSyscallFlush(t, first))
	require.NoError(t, awaitSyscallFlush(t, second))
}

func TestSyscallFlushStopAndDeadline(t *testing.T) {
	st, triggers, _ := syscallFlushHarness(t, func(string, []string) {})
	ctx, cancel := context.WithTimeout(t.Context(), 20*time.Millisecond)
	defer cancel()
	require.ErrorIs(t, st.Flush(ctx), context.DeadlineExceeded)
	<-triggers
	result := startSyscallFlush(st, t.Context())
	awaitSyscallTrigger(t, triggers)
	require.NoError(t, st.Stop())
	require.ErrorContains(t, awaitSyscallFlush(t, result), "stopped")
	require.ErrorContains(t, st.Flush(t.Context()), "stopped")
	require.NoError(t, st.Stop())
}

func TestSyscallFlushStopReleasesDeliveryChain(t *testing.T) {
	blocked, reported := make(chan struct{}), make(chan struct{})
	defer func() {
		select {
		case <-blocked:
		default:
			close(blocked)
		}
	}()
	st, _, emit := syscallFlushHarness(t, func(string, []string) { defer close(reported); <-blocked })
	var tails []<-chan struct{}
	for i := 0; i < 8; i++ {
		emit(i == 0)
		st.flushMu.Lock()
		tails = append(tails, st.deliveryTail)
		st.flushMu.Unlock()
	}
	require.NoError(t, st.Stop())
	for _, tail := range tails {
		select {
		case <-tail:
		case <-time.After(time.Second):
			t.Fatal("delivery-chain waiter survived Stop")
		}
	}
	require.ErrorContains(t, st.Flush(t.Context()), "stopped")
	// Existing report callbacks have no cancellation API; release ours explicitly.
	close(blocked)
	select {
	case <-reported:
	case <-time.After(time.Second):
		t.Fatal("report callback did not return")
	}
}

func TestSyscallFlushWaitsForTargetArrayDelivery(t *testing.T) {
	blocked, entered := make(chan struct{}), make(chan struct{})
	defer func() {
		select {
		case <-blocked:
		default:
			close(blocked)
		}
	}()
	st, triggers, emit := syscallFlushHarness(t, func(string, []string) { close(entered); <-blocked })
	ctx, cancel := context.WithTimeout(t.Context(), 3*time.Second)
	defer cancel()
	result := startSyscallFlush(st, ctx)
	awaitSyscallTrigger(t, triggers)
	emit(false)
	awaitSyscallTrigger(t, triggers)
	emit(true)
	select {
	case <-entered:
	case <-time.After(time.Second):
		t.Fatal("target report did not start")
	}
	select {
	case err := <-result:
		t.Fatalf("target batch was not delivered before flush returned: %v", err)
	default:
	}
	close(blocked)
	require.NoError(t, awaitSyscallFlush(t, result))
}
