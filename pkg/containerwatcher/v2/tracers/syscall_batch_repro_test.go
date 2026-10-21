package tracers

import (
	"fmt"
	"slices"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/inspektor-gadget/inspektor-gadget/pkg/utils/syscalls"
	"github.com/kubescape/node-agent/pkg/utils"
	"github.com/stretchr/testify/require"
)

// Exercise the real bitmap decoder, packet copies, and asynchronous batch
// dispatch without a running gadget. Each container has seven exclusive marker
// syscalls in addition to 64 common ones, so loss and attribution mixups differ.
func TestSyscallTracerConcurrentBatchReproduction(t *testing.T) {
	const containers, common, markers, rounds = 4, 64, 7, 4
	const snapshots = 1 + markers
	type knownSyscall struct {
		number int
		name   string
	}
	var known []knownSyscall
	seen := map[string]bool{}
	for number := range 512 {
		if name, ok := syscalls.GetSyscallNameByNumber(number); ok && !seen[name] {
			known = append(known, knownSyscall{number, name})
			seen[name] = true
		}
	}
	require.GreaterOrEqual(t, len(known), common+containers*markers)
	fields := syscallTestDatasource() // Share the existing global accessor schema.
	type batch struct {
		container string
		names     []string
	}
	const batchCount = containers * snapshots * rounds
	reports := make(chan batch, batchCount)
	releaseReports := make(chan struct{})
	var releaseOnce sync.Once
	release := func() { releaseOnce.Do(func() { close(releaseReports) }) }
	t.Cleanup(release)
	var mu sync.Mutex
	gotEvents := map[string]map[string]int{}
	var attributionErrors []string
	tracer := &SyscallTracer{
		reportSyscalls: func(container string, names []string) {
			// Read batches only after callbacks release/reuse their source packets.
			<-releaseReports
			reports <- batch{container, slices.Clone(names)}
		},
		eventCallback: func(event utils.K8sEvent, container string, _ uint32) {
			copied := event.(*utils.DatasourceEvent)
			defer copied.Release()
			mu.Lock()
			defer mu.Unlock()
			if copied.GetContainerID() != container {
				attributionErrors = append(attributionErrors, fmt.Sprintf("callback=%q packet=%q", container, copied.GetContainerID()))
			}
			if gotEvents[container] == nil {
				gotEvents[container] = map[string]int{}
			}
			gotEvents[container][copied.GetSyscall()]++
		},
	}
	wantEvents := map[string]map[string]int{}
	wantBatches := map[string]int{}
	wantUnion := map[string]map[string]bool{}
	batchKey := func(container string, names []string) string {
		names = slices.Clone(names)
		slices.Sort(names)
		return container + ":" + strings.Join(names, ",")
	}
	for round := range rounds {
		var callbacks sync.WaitGroup
		start := make(chan struct{})
		for containerIndex := range containers {
			container := fmt.Sprintf("batch-container-%d", containerIndex)
			if wantEvents[container] == nil {
				wantEvents[container] = map[string]int{}
				wantUnion[container] = map[string]bool{}
			}
			for snapshot := range snapshots {
				// A destructive drain emits new observations, not a cumulative
				// replay: one common batch followed by singleton marker deltas.
				selected := known[:common]
				if snapshot > 0 {
					marker := common + containerIndex*markers + snapshot - 1
					selected = known[marker : marker+1]
				}
				bitmap := make([]byte, 512)
				var names []string
				for _, syscall := range selected {
					bitmap[syscall.number] = 1
					names = append(names, syscall.name)
					wantEvents[container][syscall.name]++
					wantUnion[container][syscall.name] = true
				}
				wantBatches[batchKey(container, names)]++
				data, err := fields.ds.NewPacketSingle()
				require.NoError(t, err)
				require.NoError(t, fields.containerIDAcc.PutString(data, container))
				require.NoError(t, fields.syscallsAcc.PutBytes(data, bitmap))
				event := &utils.DatasourceEvent{Data: data, Datasource: fields.ds, EventType: utils.SyscallEventType}
				callbacks.Add(1)
				go func() {
					defer callbacks.Done()
					<-start
					tracer.callback(event) // Owns and releases the original packet.
				}()
			}
		}
		close(start)
		done := make(chan struct{})
		go func() { callbacks.Wait(); close(done) }()
		select {
		case <-done:
		case <-time.After(10 * time.Second):
			t.Fatalf("callbacks stalled in round %d", round)
		}
	}
	release()
	gotBatches := map[string]int{}
	gotUnion := map[string]map[string]bool{}
	deadline := time.NewTimer(10 * time.Second)
	defer deadline.Stop()
	for received := 0; received < batchCount; received++ {
		select {
		case report := <-reports:
			gotBatches[batchKey(report.container, report.names)]++
			if gotUnion[report.container] == nil {
				gotUnion[report.container] = map[string]bool{}
			}
			for _, name := range report.names {
				gotUnion[report.container][name] = true
			}
		case <-deadline.C:
			t.Fatalf("received %d/%d batch acknowledgements", received, batchCount)
		}
	}
	require.Equal(t, wantBatches, gotBatches, "every snapshot must retain its exact syscall set and container")
	require.Equal(t, wantUnion, gotUnion, "no missing or cross-container syscall names")
	mu.Lock()
	defer mu.Unlock()
	require.Empty(t, attributionErrors)
	require.Equal(t, wantEvents, gotEvents, "deep-copied per-syscall events must match the batch stream")
	t.Logf("verified %d batches, %d containers, %d names/container (%d shared + %d exclusive), %d delta snapshots repeated %d times", batchCount, containers, common+markers, common, markers, snapshots, rounds)
}
