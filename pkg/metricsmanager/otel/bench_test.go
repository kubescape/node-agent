package otelmetrics

import (
	"testing"
	"time"

	"go.opentelemetry.io/otel"
	sdkmetric "go.opentelemetry.io/otel/sdk/metric"

	"github.com/kubescape/node-agent/pkg/utils"
)

// setupBenchmarkMeterProvider installs a real MeterProvider backed by a
// ManualReader (synchronous, no goroutines). This exercises the full SDK
// instrument → aggregation → reader pipeline without network or disk I/O,
// giving stable alloc numbers for comparison with the Prometheus impl.
func setupBenchmarkMeterProvider() {
	reader := sdkmetric.NewManualReader()
	mp := sdkmetric.NewMeterProvider(sdkmetric.WithReader(reader))
	otel.SetMeterProvider(mp)
}

// BenchmarkReportRuleEvaluationTime measures the hot-path cost of recording a
// rule evaluation histogram observation with pre-cached attribute sets.
// Pass criteria (per Phase 2 plan): allocs/op ≤ Prometheus impl AND
// ns/op ≤ 1.1× Prometheus impl (run with -benchmem to verify).
func BenchmarkReportRuleEvaluationTime(b *testing.B) {
	setupBenchmarkMeterProvider()
	m := NewOTELMetricsManager()

	// Warm the cache for the key under test so the benchmark measures the
	// cached fast path, not the first-call allocation.
	m.ReportRuleEvaluationTime("R1001", utils.ExecveEventType, 3*time.Millisecond)

	b.ResetTimer()
	b.ReportAllocs()
	for i := 0; i < b.N; i++ {
		m.ReportRuleEvaluationTime("R1001", utils.ExecveEventType, 3*time.Millisecond)
	}
}

// BenchmarkReportEvent measures the hot-path cost of incrementing the collapsed
// eBPF events counter with a cached event_type attribute set.
func BenchmarkReportEvent(b *testing.B) {
	setupBenchmarkMeterProvider()
	m := NewOTELMetricsManager()
	m.ReportEvent(utils.ExecveEventType) // warm cache

	b.ResetTimer()
	b.ReportAllocs()
	for i := 0; i < b.N; i++ {
		m.ReportEvent(utils.ExecveEventType)
	}
}

// BenchmarkReportRuleAlert measures the hot-path cost of incrementing the alert
// counter with a cached rule_id attribute set.
func BenchmarkReportRuleAlert(b *testing.B) {
	setupBenchmarkMeterProvider()
	m := NewOTELMetricsManager()
	m.ReportRuleAlert("R1001") // warm cache

	b.ResetTimer()
	b.ReportAllocs()
	for i := 0; i < b.N; i++ {
		m.ReportRuleAlert("R1001")
	}
}
