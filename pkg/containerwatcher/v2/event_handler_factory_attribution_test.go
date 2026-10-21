package containerwatcher

import (
	"context"
	"testing"

	containercollection "github.com/inspektor-gadget/inspektor-gadget/pkg/container-collection"
	"github.com/kubescape/node-agent/pkg/utils"
	"github.com/stretchr/testify/require"
	sdkmetric "go.opentelemetry.io/otel/sdk/metric"
	"go.opentelemetry.io/otel/sdk/metric/metricdata"
)

func TestProcessEvent_AttributionDropMetrics(t *testing.T) {
	reader := sdkmetric.NewManualReader()
	provider := sdkmetric.NewMeterProvider(sdkmetric.WithReader(reader))
	t.Cleanup(func() { require.NoError(t, provider.Shutdown(context.Background())) })
	counter, err := provider.Meter("attribution-test").Int64Counter("node_agent.ebpf.events_dropped.total")
	require.NoError(t, err)

	collection := &containercollection.ContainerCollection{}
	spy := &enrichedEventSpy{}
	factory := newRemovalTestFactory(t, collection, spy)
	factory.ebpfDropCounter = counter
	factory.ProcessEvent(makeExecEnrichedEvent(""))
	factory.ProcessEvent(makeExecEnrichedEvent("unknown-container-one"))
	factory.ProcessEvent(makeExecEnrichedEvent("unknown-container-two"))
	require.Empty(t, spy.received, "unattributed events must not reach handlers")

	collection.AddContainer(makeTestContainer("known-container", "test-namespace", "pod", "app", 1001))
	factory.ProcessEvent(makeExecEnrichedEvent("known-container"))
	require.Len(t, spy.received, 1, "normal dispatch must remain intact")
	factory.cfg.ExcludeNamespaces = []string{"test-namespace"}
	factory.ProcessEvent(makeExecEnrichedEvent("known-container"))
	require.Len(t, spy.received, 1, "configured exclusions must still skip dispatch")

	var collected metricdata.ResourceMetrics
	require.NoError(t, reader.Collect(context.Background(), &collected))
	counts := map[string]int64{}
	for _, scope := range collected.ScopeMetrics {
		for _, exported := range scope.Metrics {
			if exported.Name != "node_agent.ebpf.events_dropped.total" {
				continue
			}
			sum, ok := exported.Data.(metricdata.Sum[int64])
			require.True(t, ok)
			for _, point := range sum.DataPoints {
				require.Equal(t, 2, point.Attributes.Len(), "identity must not become a metric dimension")
				eventType, ok := point.Attributes.Value("event_type")
				require.True(t, ok)
				require.Equal(t, string(utils.ExecveEventType), eventType.AsString())
				reason, ok := point.Attributes.Value("reason")
				require.True(t, ok)
				counts[reason.AsString()] += point.Value
			}
		}
	}
	require.Equal(t, map[string]int64{"missing_container_id": 1, "container_not_found": 2}, counts,
		"live and namespace-excluded events must not count as attribution errors")
}
