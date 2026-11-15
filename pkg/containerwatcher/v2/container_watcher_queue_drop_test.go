package containerwatcher

import (
	"context"
	"testing"
	"time"

	"github.com/kubescape/node-agent/pkg/containerprofilemanager"
	"github.com/kubescape/node-agent/pkg/utils"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.opentelemetry.io/otel/attribute"
	sdkmetric "go.opentelemetry.io/otel/sdk/metric"
	"go.opentelemetry.io/otel/sdk/metric/metricdata"
)

func newDropAccountingWatcher(t *testing.T, queueSize int) (*ContainerWatcher, *spyProfileManager, *sdkmetric.ManualReader) {
	t.Helper()
	reader := sdkmetric.NewManualReader()
	mp := sdkmetric.NewMeterProvider(sdkmetric.WithReader(reader))
	counter, err := mp.Meter("test").Int64Counter("node_agent.ebpf.events_dropped.total")
	require.NoError(t, err)

	spy := &spyProfileManager{}
	var _ containerprofilemanager.ContainerProfileManagerClient = spy
	return &ContainerWatcher{
		orderedEventQueue:       NewOrderedEventQueue(10*time.Millisecond, queueSize),
		containerProfileManager: spy,
		ebpfDropCounter:         counter,
	}, spy, reader
}

// droppedByReason returns the collected counter values keyed by "event_type/reason".
func droppedByReason(t *testing.T, reader *sdkmetric.ManualReader) map[string]int64 {
	t.Helper()
	var rm metricdata.ResourceMetrics
	require.NoError(t, reader.Collect(context.Background(), &rm))
	out := map[string]int64{}
	for _, sm := range rm.ScopeMetrics {
		for _, m := range sm.Metrics {
			sum, ok := m.Data.(metricdata.Sum[int64])
			require.True(t, ok)
			for _, dp := range sum.DataPoints {
				et, _ := dp.Attributes.Value(attribute.Key("event_type"))
				reason, _ := dp.Attributes.Value(attribute.Key("reason"))
				out[et.AsString()+"/"+reason.AsString()] += dp.Value
			}
		}
	}
	return out
}

func TestAccountQueueDrops_FullQueueMarksContainerAndCountsMetric(t *testing.T) {
	cw, spy, reader := newDropAccountingWatcher(t, 1)

	cw.orderedEventQueue.AddEventDirect(utils.ExecveEventType, &utils.StructEvent{Timestamp: 1}, "kept", 1)
	for range 3 {
		cw.orderedEventQueue.AddEventDirect(utils.ExecveEventType, &utils.StructEvent{Timestamp: 2}, "c1", 1)
	}
	cw.orderedEventQueue.AddEventDirect(utils.OpenEventType, &utils.StructEvent{Timestamp: 3}, "c1", 1)
	// An event without a container still counts in the metric but has no profile to mark.
	cw.orderedEventQueue.AddEventDirect(utils.ExecveEventType, &utils.StructEvent{Timestamp: 4}, "", 1)

	cw.accountQueueDrops()

	assert.Equal(t, map[string]int64{
		string(utils.ExecveEventType) + "/ordered_queue_full": 4,
		string(utils.OpenEventType) + "/ordered_queue_full":   1,
	}, droppedByReason(t, reader))
	assert.Equal(t, []string{"c1"}, spy.dropped, "each affected container is reported once per drain")

	// A second pass with no new overflow must not double count.
	cw.accountQueueDrops()
	assert.Equal(t, int64(4), droppedByReason(t, reader)[string(utils.ExecveEventType)+"/ordered_queue_full"])
	assert.Equal(t, []string{"c1"}, spy.dropped)
}

func TestAccountQueueDrops_NoOverflowIsNoop(t *testing.T) {
	cw, spy, reader := newDropAccountingWatcher(t, 10)
	cw.orderedEventQueue.AddEventDirect(utils.ExecveEventType, &utils.StructEvent{Timestamp: 1}, "c1", 1)

	cw.accountQueueDrops()

	assert.Empty(t, droppedByReason(t, reader))
	assert.Empty(t, spy.dropped)
	assert.Equal(t, 1, cw.orderedEventQueue.Size())
}

// startLoop runs eventProcessingLoop the way Start does and returns a cancel func plus its done channel.
func startLoop(cw *ContainerWatcher) (cancel context.CancelFunc) {
	cw.ctx, cancel = context.WithCancel(context.Background())
	cw.cfg.EventBatchSize = 10
	cw.processingDone = make(chan struct{})
	go cw.eventProcessingLoop(cw.processingDone)
	return cancel
}

func TestFinishQueueAccounting_DrainsDropsPendingAtShutdown(t *testing.T) {
	cw, spy, reader := newDropAccountingWatcher(t, 1)
	cancel := startLoop(cw)
	cancel()
	<-cw.processingDone // the loop has exited without seeing this drop

	cw.orderedEventQueue.AddEventDirect(utils.ExecveEventType, &utils.StructEvent{Timestamp: 1}, "kept", 1)
	cw.orderedEventQueue.AddEventDirect(utils.OpenEventType, &utils.StructEvent{Timestamp: 2}, "c1", 1)
	require.Empty(t, droppedByReason(t, reader))

	cw.finishQueueAccounting()

	assert.Equal(t, map[string]int64{string(utils.OpenEventType) + "/ordered_queue_full": 1}, droppedByReason(t, reader))
	assert.Equal(t, []string{"c1"}, spy.dropped)
}

func TestFinishQueueAccounting_NoDoubleCount(t *testing.T) {
	cw, spy, reader := newDropAccountingWatcher(t, 1)
	cw.orderedEventQueue.AddEventDirect(utils.ExecveEventType, &utils.StructEvent{Timestamp: 1}, "kept", 1)
	cw.orderedEventQueue.AddEventDirect(utils.OpenEventType, &utils.StructEvent{Timestamp: 2}, "c1", 1)
	cw.accountQueueDrops() // normal processing already accounted for it

	cw.processingDone = make(chan struct{})
	close(cw.processingDone)
	cw.finishQueueAccounting()
	cw.finishQueueAccounting() // repeated shutdown is safe

	assert.Equal(t, map[string]int64{string(utils.OpenEventType) + "/ordered_queue_full": 1}, droppedByReason(t, reader))
	assert.Equal(t, []string{"c1"}, spy.dropped)
}

// The final drain must not run while the processing loop (the owner of droppedBuf) is alive.
func TestFinishQueueAccounting_WaitsForProcessingLoop(t *testing.T) {
	cw, spy, _ := newDropAccountingWatcher(t, 1)
	cw.orderedEventQueue.AddEventDirect(utils.ExecveEventType, &utils.StructEvent{Timestamp: 1}, "kept", 1)
	cw.orderedEventQueue.AddEventDirect(utils.OpenEventType, &utils.StructEvent{Timestamp: 2}, "c1", 1)
	cw.processingDone = make(chan struct{})

	finished := make(chan struct{})
	go func() { cw.finishQueueAccounting(); close(finished) }()

	select {
	case <-finished:
		t.Fatal("final drain completed while the processing loop was still running")
	case <-time.After(50 * time.Millisecond):
	}
	close(cw.processingDone)
	select {
	case <-finished:
	case <-time.After(5 * time.Second):
		t.Fatal("final drain did not run after the processing loop exited")
	}
	assert.Equal(t, []string{"c1"}, spy.dropped)
}
