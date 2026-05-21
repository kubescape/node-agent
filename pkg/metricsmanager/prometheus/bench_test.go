package metricsmanager

import (
	"sync"
	"testing"
	"time"

	"github.com/kubescape/node-agent/pkg/utils"
)

// benchPM is a singleton for benchmarks: promauto registers with the global
// Prometheus DefaultRegisterer, which panics on duplicate registration.
var (
	benchPM   *PrometheusMetric
	benchOnce sync.Once
)

func getBenchPM() *PrometheusMetric {
	benchOnce.Do(func() { benchPM = NewPrometheusMetric() })
	return benchPM
}

// BenchmarkReportRuleEvaluationTime is the Prometheus baseline for the Phase 2
// A/B comparison. The OTEL implementation must not exceed this in allocs/op or
// ns/op × 1.1 (per Phase 2 plan hard gate).
func BenchmarkReportRuleEvaluationTime(b *testing.B) {
	pm := getBenchPM()
	pm.ReportRuleEvaluationTime("R1001", utils.ExecveEventType, 3*time.Millisecond) // warm cache

	b.ResetTimer()
	b.ReportAllocs()
	for i := 0; i < b.N; i++ {
		pm.ReportRuleEvaluationTime("R1001", utils.ExecveEventType, 3*time.Millisecond)
	}
}

func BenchmarkReportEvent(b *testing.B) {
	pm := getBenchPM()
	pm.ReportEvent(utils.ExecveEventType)

	b.ResetTimer()
	b.ReportAllocs()
	for i := 0; i < b.N; i++ {
		pm.ReportEvent(utils.ExecveEventType)
	}
}

func BenchmarkReportRuleAlert(b *testing.B) {
	pm := getBenchPM()
	pm.ReportRuleAlert("R1001") // warm cache

	b.ResetTimer()
	b.ReportAllocs()
	for i := 0; i < b.N; i++ {
		pm.ReportRuleAlert("R1001")
	}
}
