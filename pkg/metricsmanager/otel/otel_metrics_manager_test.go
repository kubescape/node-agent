package otelmetrics

import (
	"context"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.opentelemetry.io/otel"
	"go.opentelemetry.io/otel/attribute"
	sdkmetric "go.opentelemetry.io/otel/sdk/metric"
	"go.opentelemetry.io/otel/sdk/metric/metricdata"
)

func TestContainerProfileConditionalFetchMetrics(t *testing.T) {
	previousProvider := otel.GetMeterProvider()
	reader := sdkmetric.NewManualReader()
	provider := sdkmetric.NewMeterProvider(sdkmetric.WithReader(reader))
	otel.SetMeterProvider(provider)
	t.Cleanup(func() {
		err := provider.Shutdown(context.Background())
		otel.SetMeterProvider(previousProvider)
		assert.NoError(t, err)
	})

	manager := NewOTELMetricsManager("", "", false)
	requestModes := []string{"offered", "missing", "ineligible", "forced_revalidation"}
	responseOutcomes := []string{"body", "unchanged", "not_found", "error", "protocol_error"}
	for _, mode := range requestModes {
		manager.ReportContainerProfileConditionalFetchRequest(mode)
	}
	for _, outcome := range responseOutcomes {
		manager.ReportContainerProfileConditionalFetchResponse(outcome)
	}

	var resourceMetrics metricdata.ResourceMetrics
	require.NoError(t, reader.Collect(context.Background(), &resourceMetrics))
	assertCounterAttributeValues(t, resourceMetrics,
		"node_agent.profile.conditional_fetch.requests.total", "mode", requestModes)
	assertCounterAttributeValues(t, resourceMetrics,
		"node_agent.profile.conditional_fetch.responses.total", "outcome", responseOutcomes)
}

func assertCounterAttributeValues(
	t *testing.T,
	resourceMetrics metricdata.ResourceMetrics,
	metricName string,
	attributeKey attribute.Key,
	want []string,
) {
	t.Helper()

	seen := make(map[string]int64, len(want))
	for _, scopeMetrics := range resourceMetrics.ScopeMetrics {
		for _, exportedMetric := range scopeMetrics.Metrics {
			if exportedMetric.Name != metricName {
				continue
			}
			sum, ok := exportedMetric.Data.(metricdata.Sum[int64])
			require.True(t, ok, "%s must export as an int64 sum", metricName)
			for _, point := range sum.DataPoints {
				attributes := point.Attributes.ToSlice()
				require.Len(t, attributes, 1, "%s must have only its closed-cardinality attribute", metricName)
				assert.Equal(t, attributeKey, attributes[0].Key)
				seen[attributes[0].Value.AsString()] = point.Value
			}
		}
	}

	require.Len(t, seen, len(want), "%s must export every expected label value", metricName)
	for _, value := range want {
		assert.Equal(t, int64(1), seen[value], "%s{%s=%q}", metricName, attributeKey, value)
	}
}
