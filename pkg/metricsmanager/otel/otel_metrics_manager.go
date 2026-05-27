package otelmetrics

import (
	"context"
	"fmt"
	"sync"
	"sync/atomic"
	"time"

	"go.opentelemetry.io/otel/attribute"
	"go.opentelemetry.io/otel/metric"

	"github.com/kubescape/node-agent/pkg/metricsmanager"
	"github.com/kubescape/node-agent/pkg/otelsetup"
	"github.com/kubescape/node-agent/pkg/utils"
)

var _ metricsmanager.MetricsManager = (*OTELMetricsManager)(nil)

type OTELMetricsManager struct {
	// eBPF events — collapsed from 17 individual Prometheus counters into one
	// with an event_type attribute (OTEL convention, avoids metric explosion).
	ebpfEventsTotal metric.Int64Counter
	ebpfFailedTotal metric.Int64Counter

	// Rule metrics
	ruleProcTotal    metric.Int64Counter
	rulePrefiltTotal metric.Int64Counter
	alertTotal       metric.Int64Counter
	ruleEvalDuration metric.Float64Histogram

	// Container lifecycle
	containerStartTotal metric.Int64Counter
	containerStopTotal  metric.Int64Counter
	dedupEventsTotal    metric.Int64Counter

	// ContainerProfile cache
	profileLegacyLoadTotal   metric.Int64Counter
	profileCacheEntries      metric.Float64Gauge
	profileCacheHitTotal     metric.Int64Counter
	reconcilerDuration       metric.Float64Histogram
	reconcilerEvictionsTotal metric.Int64Counter

	// Rule projection — always-on
	projMissingDeclTotal   metric.Int64Counter
	projUndeclaredLitTotal metric.Int64Counter
	projStaleEntries       metric.Float64Gauge
	projUndeclaredRules    metric.Float64Gauge

	// Rule projection — detailed (gated by caller)
	projSpecCompileTotal        metric.Int64Counter
	projSpecHashChangeTotal     metric.Int64Counter
	projSpecPatterns            metric.Float64Gauge
	projSpecAllField            metric.Float64Gauge
	projApplyDuration           metric.Float64Histogram
	projReconcileTriggeredTotal metric.Int64Counter
	projHelperCallTotal         metric.Int64Counter
	projUndeclaredRulesDetail   metric.Float64Gauge

	// Memory-savings metrics (dev-only, kept for interface compat; candidates for removal)
	profileRawSize         metric.Float64Histogram
	profileProjectedSize   metric.Float64Histogram
	profileEntriesRaw      metric.Float64Histogram
	profileEntriesRetained metric.Float64Histogram
	profileRetentionRatio  metric.Float64Histogram

	// SBOM scan metrics
	sbomScanTotal    metric.Int64Counter
	sbomScanDuration metric.Float64Histogram
	sbomRestarts     metric.Int64Counter
	sbomReady        metric.Float64Gauge

	// Alert suppression funnel
	alertSuppressedTotal metric.Int64Counter

	// Live container count — incremented on start, decremented on stop.
	// Exposed as node_agent.container.count observable gauge.
	containerCount atomic.Int64

	// Attribute-set caches: mandatory on the hot path to avoid per-call allocations.
	// Each cache maps a string key → metric.MeasurementOption (pre-built attribute set).
	ruleIDCache    sync.Map // ruleID → MeasurementOption (rule_id attribute)
	ruleEvalCache  sync.Map // ruleID+"\x00"+eventType → MeasurementOption (rule_id + event_type)
	eventTypeCache sync.Map // eventType string → MeasurementOption (event_type attribute)
	dedupCache      sync.Map // eventType+"\x00"+result → MeasurementOption (event_type + result)
	suppressedCache sync.Map // ruleID+"\x00"+reason → MeasurementOption (rule_id + reason)

	// SetProjectionUndeclaredRulesDetail tracks the current rule ID set so that
	// removed rules can be zeroed out on the next call (no Reset() in OTEL gauges).
	undeclaredRulesMu  sync.Mutex
	undeclaredRulesSet map[string]struct{}
}

// NewOTELMetricsManager constructs a fully-initialised OTELMetricsManager.
// MUST be called after otelsetup.InitProviders() so that otelsetup.Meter()
// returns the real MeterProvider, not the SDK no-op.
func NewOTELMetricsManager() *OTELMetricsManager {
	meter := otelsetup.Meter()
	m := &OTELMetricsManager{
		undeclaredRulesSet: make(map[string]struct{}),
	}

	mustCounter := func(name, desc string) metric.Int64Counter {
		c, err := meter.Int64Counter(name, metric.WithDescription(desc))
		if err != nil {
			panic(fmt.Sprintf("otelmetrics: counter %q: %v", name, err))
		}
		return c
	}
	mustGauge := func(name, desc string) metric.Float64Gauge {
		g, err := meter.Float64Gauge(name, metric.WithDescription(desc))
		if err != nil {
			panic(fmt.Sprintf("otelmetrics: gauge %q: %v", name, err))
		}
		return g
	}
	mustHistogram := func(name, desc, unit string, boundaries []float64) metric.Float64Histogram {
		h, err := meter.Float64Histogram(name,
			metric.WithDescription(desc),
			metric.WithUnit(unit),
			metric.WithExplicitBucketBoundaries(boundaries...),
		)
		if err != nil {
			panic(fmt.Sprintf("otelmetrics: histogram %q: %v", name, err))
		}
		return h
	}

	// Rule-evaluation buckets: covers P99 in 1–10ms range with a 2s tail bucket.
	evalBuckets := []float64{0.0005, 0.001, 0.002, 0.005, 0.010, 0.050, 0.500, 2.0}
	defBuckets := []float64{0.005, 0.01, 0.025, 0.05, 0.1, 0.25, 0.5, 1.0, 2.5, 5.0, 10.0}
	sizeBuckets := []float64{0, 1024, 4096, 16384, 65536, 262144, 1048576, 4194304}
	entryBuckets := []float64{0, 1, 5, 10, 50, 100, 500, 1000, 5000}
	ratioBuckets := []float64{0, 0.1, 0.2, 0.3, 0.4, 0.5, 0.6, 0.7, 0.8, 0.9, 1.0}

	m.ebpfEventsTotal = mustCounter("node_agent.ebpf.events.total",
		"Total eBPF events received, labeled by event_type (collapses 17 Prometheus counters)")
	m.ebpfFailedTotal = mustCounter("node_agent.ebpf.events.failed.total",
		"Total failed eBPF event processing attempts")

	m.ruleProcTotal = mustCounter("node_agent.rule.processed.total",
		"Total rule evaluations by rule_id")
	m.rulePrefiltTotal = mustCounter("node_agent.rule.prefiltered.total",
		"Total rule evaluations skipped by pre-filter")
	m.alertTotal = mustCounter("node_agent.alert.total",
		"Total security alerts fired, labeled by rule_id")
	m.ruleEvalDuration = mustHistogram("node_agent.rule.evaluation.duration",
		"Rule evaluation latency by rule_id and event_type", "s", evalBuckets)

	m.containerStartTotal = mustCounter("node_agent.container.start.total",
		"Total container start events")
	m.containerStopTotal = mustCounter("node_agent.container.stop.total",
		"Total container stop events")
	m.dedupEventsTotal = mustCounter("node_agent.ebpf.dedup.total",
		"Total events processed by the dedup layer")

	m.profileLegacyLoadTotal = mustCounter("node_agent.profile.legacy_load.total",
		"Legacy ApplicationProfile/NetworkNeighborhood loads (deprecated, will be removed)")
	m.profileCacheEntries = mustGauge("node_agent.profile.cache.entries",
		"Current ContainerProfile cache entries per kind")
	m.profileCacheHitTotal = mustCounter("node_agent.profile.cache.hit.total",
		"ContainerProfile cache lookups by result (hit/miss)")
	m.reconcilerDuration = mustHistogram("node_agent.profile.reconciler.duration",
		"ContainerProfile reconciler phase duration", "s", defBuckets)
	m.reconcilerEvictionsTotal = mustCounter("node_agent.profile.reconciler.evictions.total",
		"ContainerProfile cache evictions by reason")

	m.projMissingDeclTotal = mustCounter("node_agent.rule.projection.missing_decl.total",
		"Rules with profileDependency>0 but no profileDataRequired declaration")
	m.projUndeclaredLitTotal = mustCounter("node_agent.rule.projection.undeclared_literal.total",
		"Literals evaluated against an undeclared projected field")
	m.projStaleEntries = mustGauge("node_agent.rule.projection.stale_entries",
		"Projected cache entries whose spec hash is stale")
	m.projUndeclaredRules = mustGauge("node_agent.rule.projection.undeclared_rules",
		"Rules currently loaded with no profileDataRequired field")

	m.projSpecCompileTotal = mustCounter("node_agent.rule.projection.spec_compile.total",
		"Total projection spec compilations")
	m.projSpecHashChangeTotal = mustCounter("node_agent.rule.projection.spec_hash_change.total",
		"Total projection spec hash changes")
	m.projSpecPatterns = mustGauge("node_agent.rule.projection.spec_patterns",
		"Projection spec pattern counts per field and kind")
	m.projSpecAllField = mustGauge("node_agent.rule.projection.spec_all_field",
		"Whether a projection spec field has All=true (1) or not (0)")
	m.projApplyDuration = mustHistogram("node_agent.rule.projection.apply.duration",
		"Profile projection Apply call duration", "s", defBuckets)
	m.projReconcileTriggeredTotal = mustCounter("node_agent.rule.projection.reconcile_triggered.total",
		"Projection reconcile triggers by type")
	m.projHelperCallTotal = mustCounter("node_agent.rule.projection.helper_call.total",
		"Profile-helper CEL function calls by helper name")
	// program runtime gauges intentionally omitted — dead code since initial implementation
	m.projUndeclaredRulesDetail = mustGauge("node_agent.rule.projection.undeclared_rules_detail",
		"Per-rule gauge for undeclared rules (high-cardinality; candidate for removal in Phase 3)")

	m.profileRawSize = mustHistogram("node_agent.profile.raw_size",
		"Raw ContainerProfile data size before projection (dev-only)", "By", sizeBuckets)
	m.profileProjectedSize = mustHistogram("node_agent.profile.projected_size",
		"Projected ContainerProfile data size after projection (dev-only)", "By", sizeBuckets)
	m.profileEntriesRaw = mustHistogram("node_agent.profile.entries_raw",
		"Entries per field before projection (dev-only)", "{entry}", entryBuckets)
	m.profileEntriesRetained = mustHistogram("node_agent.profile.entries_retained",
		"Entries per field after projection (dev-only)", "{entry}", entryBuckets)
	m.profileRetentionRatio = mustHistogram("node_agent.profile.retention_ratio",
		"Entry retention ratio per field after projection (dev-only)", "1", ratioBuckets)

	// SBOM scan buckets: covers 1s–15min (scans can take several minutes for large images).
	sbomBuckets := []float64{1, 2, 5, 10, 30, 60, 120, 300, 600, 900}
	m.sbomScanTotal = mustCounter("node_agent.sbom.scan.total",
		"Total SBOM scan attempts by status (success/error/oom_killed)")
	m.sbomScanDuration = mustHistogram("node_agent.sbom.scan.duration",
		"SBOM scan duration by status", "s", sbomBuckets)
	m.sbomRestarts = mustCounter("node_agent.sbom.scanner.restarts.total",
		"Total SBOM scanner sidecar restarts detected via connection loss")
	m.sbomReady = mustGauge("node_agent.sbom.scanner.ready",
		"Whether the SBOM scanner sidecar is ready (1=ready, 0=not ready)")

	m.alertSuppressedTotal = mustCounter("node_agent.alert.suppressed.total",
		"Total alerts suppressed before delivery, labeled by rule_id and reason")

	registerResourceMetrics(meter, &m.containerCount)

	return m
}

// Start is a no-op: the Prometheus HTTP listener (if configured) is started
// inside otelsetup.InitProviders when OTEL_METRICS_EXPORTER=prometheus.
func (m *OTELMetricsManager) Start() {}

// Destroy is a no-op: provider shutdown is handled by the otelsetup shutdown func.
func (m *OTELMetricsManager) Destroy() {}

// ── Attribute-set cache helpers ─────────────────────────────────────────────

func (m *OTELMetricsManager) ruleIDOption(ruleID string) metric.MeasurementOption {
	if v, ok := m.ruleIDCache.Load(ruleID); ok {
		return v.(metric.MeasurementOption)
	}
	opt := metric.WithAttributeSet(attribute.NewSet(attribute.String("rule_id", ruleID)))
	m.ruleIDCache.Store(ruleID, opt)
	return opt
}

func (m *OTELMetricsManager) ruleEvalOption(ruleID string, et utils.EventType) metric.MeasurementOption {
	key := ruleID + "\x00" + string(et)
	if v, ok := m.ruleEvalCache.Load(key); ok {
		return v.(metric.MeasurementOption)
	}
	opt := metric.WithAttributeSet(attribute.NewSet(
		attribute.String("rule_id", ruleID),
		attribute.String("event_type", string(et)),
	))
	m.ruleEvalCache.Store(key, opt)
	return opt
}

func (m *OTELMetricsManager) eventTypeOption(et utils.EventType) metric.MeasurementOption {
	key := string(et)
	if v, ok := m.eventTypeCache.Load(key); ok {
		return v.(metric.MeasurementOption)
	}
	opt := metric.WithAttributeSet(attribute.NewSet(attribute.String("event_type", key)))
	m.eventTypeCache.Store(key, opt)
	return opt
}

func (m *OTELMetricsManager) dedupOption(et utils.EventType, duplicate bool) metric.MeasurementOption {
	result := "passed"
	if duplicate {
		result = "deduplicated"
	}
	key := string(et) + "\x00" + result
	if v, ok := m.dedupCache.Load(key); ok {
		return v.(metric.MeasurementOption)
	}
	opt := metric.WithAttributeSet(attribute.NewSet(
		attribute.String("event_type", string(et)),
		attribute.String("result", result),
	))
	m.dedupCache.Store(key, opt)
	return opt
}

// ── Interface implementation ─────────────────────────────────────────────────

func (m *OTELMetricsManager) ReportEvent(eventType utils.EventType) {
	m.ebpfEventsTotal.Add(context.Background(), 1, m.eventTypeOption(eventType))
}

func (m *OTELMetricsManager) ReportFailedEvent() {
	m.ebpfFailedTotal.Add(context.Background(), 1)
}

func (m *OTELMetricsManager) ReportRuleProcessed(ruleID string) {
	m.ruleProcTotal.Add(context.Background(), 1, m.ruleIDOption(ruleID))
}

func (m *OTELMetricsManager) ReportRulePrefiltered(ruleID string) {
	m.rulePrefiltTotal.Add(context.Background(), 1, m.ruleIDOption(ruleID))
}

func (m *OTELMetricsManager) ReportRuleAlert(ruleID string) {
	m.alertTotal.Add(context.Background(), 1, m.ruleIDOption(ruleID))
}

func (m *OTELMetricsManager) ReportRuleEvaluationTime(ctx context.Context, ruleID string, eventType utils.EventType, duration time.Duration) {
	m.ruleEvalDuration.Record(ctx, duration.Seconds(), m.ruleEvalOption(ruleID, eventType))
}

func (m *OTELMetricsManager) ReportContainerStart() {
	m.containerStartTotal.Add(context.Background(), 1)
	m.containerCount.Add(1)
}

func (m *OTELMetricsManager) ReportContainerStop() {
	m.containerStopTotal.Add(context.Background(), 1)
	m.containerCount.Add(-1)
}

func (m *OTELMetricsManager) ReportDedupEvent(eventType utils.EventType, duplicate bool) {
	m.dedupEventsTotal.Add(context.Background(), 1, m.dedupOption(eventType, duplicate))
}

func (m *OTELMetricsManager) ReportContainerProfileLegacyLoad(kind, completeness string) {
	m.profileLegacyLoadTotal.Add(context.Background(), 1, metric.WithAttributes(
		attribute.String("kind", kind),
		attribute.String("completeness", completeness),
	))
}

func (m *OTELMetricsManager) SetContainerProfileCacheEntries(kind string, count float64) {
	m.profileCacheEntries.Record(context.Background(), count, metric.WithAttributes(
		attribute.String("kind", kind),
	))
}

func (m *OTELMetricsManager) ReportContainerProfileCacheHit(hit bool) {
	result := "hit"
	if !hit {
		result = "miss"
	}
	m.profileCacheHitTotal.Add(context.Background(), 1, metric.WithAttributes(
		attribute.String("result", result),
	))
}

func (m *OTELMetricsManager) ReportContainerProfileReconcilerDuration(phase string, duration time.Duration) {
	m.reconcilerDuration.Record(context.Background(), duration.Seconds(), metric.WithAttributes(
		attribute.String("phase", phase),
	))
}

func (m *OTELMetricsManager) ReportContainerProfileReconcilerEviction(reason string) {
	m.reconcilerEvictionsTotal.Add(context.Background(), 1, metric.WithAttributes(
		attribute.String("reason", reason),
	))
}

func (m *OTELMetricsManager) IncMissingProfileDataRequired(ruleID string) {
	m.projMissingDeclTotal.Add(context.Background(), 1, metric.WithAttributes(
		attribute.String("rule_id", ruleID),
	))
}

func (m *OTELMetricsManager) IncProjectionUndeclaredLiteral(helper string) {
	m.projUndeclaredLitTotal.Add(context.Background(), 1, metric.WithAttributes(
		attribute.String("helper", helper),
	))
}

func (m *OTELMetricsManager) SetProjectionStaleEntries(count float64) {
	m.projStaleEntries.Record(context.Background(), count)
}

func (m *OTELMetricsManager) SetProjectionUndeclaredRules(count float64) {
	m.projUndeclaredRules.Record(context.Background(), count)
}

func (m *OTELMetricsManager) IncProjectionSpecCompile() {
	m.projSpecCompileTotal.Add(context.Background(), 1)
}

func (m *OTELMetricsManager) IncProjectionSpecHashChange() {
	m.projSpecHashChangeTotal.Add(context.Background(), 1)
}

func (m *OTELMetricsManager) SetProjectionSpecPatterns(field, kind string, count float64) {
	m.projSpecPatterns.Record(context.Background(), count, metric.WithAttributes(
		attribute.String("field", field),
		attribute.String("kind", kind),
	))
}

func (m *OTELMetricsManager) SetProjectionSpecAllField(field string, isAll bool) {
	v := float64(0)
	if isAll {
		v = 1
	}
	m.projSpecAllField.Record(context.Background(), v, metric.WithAttributes(
		attribute.String("field", field),
	))
}

func (m *OTELMetricsManager) ObserveProjectionApplyDuration(d time.Duration) {
	m.projApplyDuration.Record(context.Background(), d.Seconds())
}

func (m *OTELMetricsManager) IncProjectionReconcileTriggered(trigger string) {
	m.projReconcileTriggeredTotal.Add(context.Background(), 1, metric.WithAttributes(
		attribute.String("trigger", trigger),
	))
}

func (m *OTELMetricsManager) IncHelperCall(helper string) {
	m.projHelperCallTotal.Add(context.Background(), 1, metric.WithAttributes(
		attribute.String("helper", helper),
	))
}

// SetProjectionUndeclaredRulesDetail records 1 for each rule currently undeclared
// and 0 for rules that were in the previous call but are no longer undeclared.
// OTEL synchronous gauges have no Reset(); zeroing removed entries is the equivalent.
func (m *OTELMetricsManager) SetProjectionUndeclaredRulesDetail(ruleIDs []string) {
	m.undeclaredRulesMu.Lock()
	defer m.undeclaredRulesMu.Unlock()

	newSet := make(map[string]struct{}, len(ruleIDs))
	for _, id := range ruleIDs {
		newSet[id] = struct{}{}
	}
	for id := range m.undeclaredRulesSet {
		if _, still := newSet[id]; !still {
			m.projUndeclaredRulesDetail.Record(context.Background(), 0, metric.WithAttributes(
				attribute.String("rule_id", id),
			))
		}
	}
	for _, id := range ruleIDs {
		m.projUndeclaredRulesDetail.Record(context.Background(), 1, metric.WithAttributes(
			attribute.String("rule_id", id),
		))
	}
	m.undeclaredRulesSet = newSet
}

func (m *OTELMetricsManager) ObserveProfileRawSize(bytes float64) {
	m.profileRawSize.Record(context.Background(), bytes)
}

func (m *OTELMetricsManager) ObserveProfileProjectedSize(bytes float64) {
	m.profileProjectedSize.Record(context.Background(), bytes)
}

func (m *OTELMetricsManager) ObserveProfileEntriesRaw(field string, count float64) {
	m.profileEntriesRaw.Record(context.Background(), count, metric.WithAttributes(
		attribute.String("field", field),
	))
}

func (m *OTELMetricsManager) ObserveProfileEntriesRetained(field string, count float64) {
	m.profileEntriesRetained.Record(context.Background(), count, metric.WithAttributes(
		attribute.String("field", field),
	))
}

func (m *OTELMetricsManager) ObserveProfileRetentionRatio(field string, ratio float64) {
	m.profileRetentionRatio.Record(context.Background(), ratio, metric.WithAttributes(
		attribute.String("field", field),
	))
}

func (m *OTELMetricsManager) ReportSBOMScan(status string) {
	m.sbomScanTotal.Add(context.Background(), 1, metric.WithAttributes(attribute.String("status", status)))
}

func (m *OTELMetricsManager) ObserveSBOMScanDuration(status string, d time.Duration) {
	m.sbomScanDuration.Record(context.Background(), d.Seconds(), metric.WithAttributes(attribute.String("status", status)))
}

func (m *OTELMetricsManager) ReportSBOMScannerRestart() {
	m.sbomRestarts.Add(context.Background(), 1)
}

func (m *OTELMetricsManager) SetSBOMScannerReady(ready bool) {
	v := 0.0
	if ready {
		v = 1.0
	}
	m.sbomReady.Record(context.Background(), v)
}

func (m *OTELMetricsManager) suppressedOption(ruleID, reason string) metric.MeasurementOption {
	key := ruleID + "\x00" + reason
	if v, ok := m.suppressedCache.Load(key); ok {
		return v.(metric.MeasurementOption)
	}
	opt := metric.WithAttributeSet(attribute.NewSet(
		attribute.String("rule_id", ruleID),
		attribute.String("reason", reason),
	))
	m.suppressedCache.Store(key, opt)
	return opt
}

func (m *OTELMetricsManager) ReportAlertSuppressed(ruleID, reason string) {
	m.alertSuppressedTotal.Add(context.Background(), 1, m.suppressedOption(ruleID, reason))
}
