package igbackend

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/inspektor-gadget/inspektor-gadget/gadgets/enforce_exec/fullruntime"
	"github.com/kubescape/node-agent/pkg/sandboxpolicy"
)

type counterTestInstance struct {
	*fullTestInstance
	counters fullruntime.KernelEventCounters
	err      error
	reads    int
}

func (i *counterTestInstance) KernelEventCounters() (fullruntime.KernelEventCounters, error) {
	i.reads++
	return i.counters, i.err
}
func (i *counterTestInstance) Stop(ctx context.Context) error {
	if err := i.fullTestInstance.Stop(ctx); err != nil {
		return err
	}
	i.counters.Final = true
	return nil
}

func TestKernelStatsAggregateRetainAndRemainReadOnly(t *testing.T) {
	first := &counterTestInstance{fullTestInstance: &fullTestInstance{}, counters: fullruntime.KernelEventCounters{Submitted: 11, Lost: 3, ObservationErrors: 1}}
	second := &counterTestInstance{fullTestInstance: &fullTestInstance{}, counters: fullruntime.KernelEventCounters{Submitted: 17, Lost: 5, ObservationErrors: 2}}
	a, b := key(sandboxpolicy.Binding{ContainerID: "a"}), key(sandboxpolicy.Binding{ContainerID: "b"})
	backend := &FullBackend{records: map[identity]*fullRecord{a: {instance: first}, b: {instance: second, retiring: true}}, operationTimeout: time.Second}
	stats, err := backend.KernelEventStats(context.Background())
	if err != nil || stats.Owned.Lost != 8 || stats.Owned.Submitted != 28 || stats.Owned.ObservationErrors != 3 || stats.OwnedInstances != 2 || stats.OwnedUnavailable != 0 {
		t.Fatalf("aggregate %+v %v", stats, err)
	}
	if first.stops != 0 || second.stops != 0 || first.updates != 0 || second.resumes != 0 {
		t.Fatal("query mutated enforcement")
	}
	if err := backend.stop(context.Background(), a, backend.records[a]); err != nil {
		t.Fatal(err)
	}
	stats, err = backend.KernelEventStats(context.Background())
	if err != nil || stats.Owned.Lost != 5 || stats.Retired.Lost != 3 || stats.RetiredInstances != 1 || stats.OwnedInstances != 1 {
		t.Fatalf("withdraw snapshot %+v %v", stats, err)
	}
	if err := backend.Close(context.Background()); err != nil {
		t.Fatal(err)
	}
	stats, err = backend.KernelEventStats(context.Background())
	if err != nil || stats.Retired.Lost != 8 || stats.RetiredInstances != 2 || stats.OwnedInstances != 0 {
		t.Fatalf("stopped snapshot %+v %v", stats, err)
	}
}

func TestKernelStatsUnavailableAndCancellation(t *testing.T) {
	instance := &counterTestInstance{fullTestInstance: &fullTestInstance{}, counters: fullruntime.KernelEventCounters{Lost: 7}, err: errors.New("read failed")}
	a, b := key(sandboxpolicy.Binding{ContainerID: "partial"}), key(sandboxpolicy.Binding{ContainerID: "unsupported"})
	backend := &FullBackend{records: map[identity]*fullRecord{a: {instance: instance, retiring: true}, b: {instance: &fullTestInstance{}}}, operationTimeout: time.Second}
	stats, err := backend.KernelEventStats(context.Background())
	if err == nil || stats.OwnedUnavailable != 2 || stats.OwnedInstances != 2 || stats.Owned.Lost != 7 {
		t.Fatalf("unavailable live stats %+v %v", stats, err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	reads := instance.reads
	if _, err := backend.KernelEventStats(ctx); !errors.Is(err, context.Canceled) {
		t.Fatalf("cancellation: %v", err)
	}
	if instance.reads != reads || instance.stops != 0 {
		t.Fatal("canceled query read or stopped owner")
	}
	if err := backend.Close(context.Background()); err != nil {
		t.Fatal(err)
	}
	stats, err = backend.KernelEventStats(context.Background())
	if err == nil || stats.RetiredUnavailable != 2 || stats.RetiredInstances != 2 || stats.Retired.Lost != 7 {
		t.Fatalf("unavailable retained stats %+v %v", stats, err)
	}
}

func TestKernelStatsRejectNonfinalRetirement(t *testing.T) {
	backend := &FullBackend{}
	backend.retainKernelCounters(&counterTestInstance{fullTestInstance: &fullTestInstance{}, counters: fullruntime.KernelEventCounters{Lost: 9}})
	stats, err := backend.KernelEventStats(context.Background())
	if err == nil || stats.RetiredUnavailable != 1 || stats.Retired.Lost != 9 {
		t.Fatalf("nonfinal incorrectly complete: %+v %v", stats, err)
	}
}

type counterTestOwner struct {
	*testFullOwner
	counters fullruntime.KernelEventCounters
	err      error
}

func (o *counterTestOwner) KernelEventCounters() (fullruntime.KernelEventCounters, error) {
	return o.counters, o.err
}
func (o *counterTestOwner) ReleaseAfterDetach() error {
	if err := o.testFullOwner.ReleaseAfterDetach(); err != nil {
		return err
	}
	o.counters.Final = true
	return nil
}

func TestNativeKernelStatsPartialStartupThroughJoinedStop(t *testing.T) {
	var calls []string
	owner := &counterTestOwner{testFullOwner: &testFullOwner{calls: &calls}, counters: fullruntime.KernelEventCounters{Lost: 3}}
	instance := &nativeFullInstance{owner: owner, manager: &testFullManager{stop: func(context.Context, string) error {
		calls = append(calls, "join")
		owner.counters.Lost = 8
		return nil
	}}}
	// A partial start has started=false; its telemetry must still be visible.
	got, err := instance.KernelEventCounters()
	if err != nil || got.Lost != 3 || len(calls) != 0 {
		t.Fatalf("partial startup stats: %+v %v calls=%v", got, err, calls)
	}
	if err := instance.Stop(context.Background()); err != nil {
		t.Fatal(err)
	}
	got, err = instance.KernelEventCounters()
	if err != nil || got.Lost != 8 || !got.Final {
		t.Fatalf("joined stats: %+v %v", got, err)
	}
	if len(calls) != 3 || calls[0] != "drain" || calls[1] != "join" || calls[2] != "release" {
		t.Fatalf("stop ordering: %v", calls)
	}
	unknown := &nativeFullInstance{owner: &testFullOwner{calls: &calls}}
	if _, err := unknown.KernelEventCounters(); err == nil {
		t.Fatal("missing stats interface reported zero loss")
	}
}

func TestKernelStatsCancellationWhileBackendBusy(t *testing.T) {
	for _, deadline := range []bool{false, true} {
		t.Run(map[bool]string{false: "cancel", true: "deadline"}[deadline], func(t *testing.T) {
			instance := &counterTestInstance{fullTestInstance: &fullTestInstance{}}
			backend := &FullBackend{records: map[identity]*fullRecord{{}: {instance: instance}}}
			backend.mu.Lock()
			defer backend.mu.Unlock()
			ctx, cancel := context.WithCancel(context.Background())
			if deadline {
				cancel()
				ctx, cancel = context.WithTimeout(context.Background(), 20*time.Millisecond)
			}
			defer cancel()
			result := make(chan error, 1)
			go func() { _, err := backend.KernelEventStats(ctx); result <- err }()
			if !deadline {
				time.Sleep(20 * time.Millisecond)
				cancel()
			}
			want := context.Canceled
			if deadline {
				want = context.DeadlineExceeded
			}
			select {
			case err := <-result:
				if !errors.Is(err, want) {
					t.Fatalf("got %v, want %v", err, want)
				}
			case <-time.After(time.Second):
				t.Fatal("stats did not cancel while backend mutex remained locked")
			}
			if instance.reads != 0 {
				t.Fatal("canceled waiter read instance counters")
			}
		})
	}
}
