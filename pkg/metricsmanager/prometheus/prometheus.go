package metricsmanager

import (
	"net/http"
	"sync"
	"time"

	"github.com/kubescape/go-logger"
	"github.com/kubescape/go-logger/helpers"
	"github.com/kubescape/node-agent/pkg/metricsmanager"
	"github.com/kubescape/node-agent/pkg/utils"
	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promauto"
	"github.com/prometheus/client_golang/prometheus/promhttp"
)

const (
	prometheusRuleIdLabel = "rule_id"
	programTypeLabel      = "program_type"
	programNameLabel      = "program_name"
	eventTypeLabel        = "event_type"
)

var _ metricsmanager.MetricsManager = (*PrometheusMetric)(nil)

type PrometheusMetric struct {
	ebpfExecCounter       prometheus.Counter
	ebpfOpenCounter       prometheus.Counter
	ebpfNetworkCounter    prometheus.Counter
	ebpfDNSCounter        prometheus.Counter
	ebpfSyscallCounter    prometheus.Counter
	ebpfCapabilityCounter prometheus.Counter
	ebpfRandomXCounter    prometheus.Counter
	ebpfFailedCounter     prometheus.Counter
	ebpfSymlinkCounter    prometheus.Counter
	ebpfHardlinkCounter   prometheus.Counter
	ebpfSSHCounter        prometheus.Counter
	ebpfHTTPCounter       prometheus.Counter
	ebpfPtraceCounter     prometheus.Counter
	ebpfIoUringCounter    prometheus.Counter
	ebpfKmodCounter       prometheus.Counter
	ebpfUnshareCounter    prometheus.Counter
	ebpfBpfCounter        prometheus.Counter
	ruleCounter            *prometheus.CounterVec
	rulePrefilteredCounter *prometheus.CounterVec
	alertCounter           *prometheus.CounterVec
	ruleEvaluationTime    *prometheus.HistogramVec

	// Program ID metrics
	programRuntimeGauge       *prometheus.GaugeVec
	programRunCountGauge      *prometheus.GaugeVec
	programTotalRuntimeGauge  *prometheus.GaugeVec
	programTotalRunCountGauge *prometheus.GaugeVec
	programMapMemoryGauge     *prometheus.GaugeVec
	programMapCountGauge      *prometheus.GaugeVec
	programCpuUsageGauge      *prometheus.GaugeVec
	programPerCpuUsageGauge   *prometheus.GaugeVec

	// Container metrics
	containerStartCounter prometheus.Counter
	containerStopCounter  prometheus.Counter

	// Dedup metrics
	dedupEventCounter *prometheus.CounterVec

	// ContainerProfile cache metrics
	cpCacheLegacyLoadsCounter      *prometheus.CounterVec
	cpCacheEntriesGauge            *prometheus.GaugeVec
	cpCacheHitCounter              *prometheus.CounterVec
	cpReconcilerDurationHistogram  *prometheus.HistogramVec
	cpReconcilerEvictionsCounter   *prometheus.CounterVec

	// Profile projection metrics — always-on
	cpProjectionMissingDeclCounter      *prometheus.CounterVec
	cpProjectionUndeclaredLiteralCounter *prometheus.CounterVec
	cpProjectionStaleEntriesGauge        prometheus.Gauge
	cpProjectionUndeclaredRulesGauge     prometheus.Gauge

	// Profile projection metrics — detailed (gated by caller checking detailedMetricsEnabled)
	cpProjectionSpecCompileCounter        prometheus.Counter
	cpProjectionSpecHashChangeCounter     prometheus.Counter
	cpProjectionSpecPatternsGauge         *prometheus.GaugeVec
	cpProjectionSpecAllFieldsGauge        *prometheus.GaugeVec
	cpProjectionApplyDurationHistogram    prometheus.Histogram
	cpProjectionReconcileTriggeredCounter *prometheus.CounterVec
	cpHelperCallCounter                   *prometheus.CounterVec
	cpProjectionUndeclaredRulesListGauge  *prometheus.GaugeVec

	// Memory-savings metrics — detailed
	cpProfileRawSizeHistogram         prometheus.Histogram
	cpProfileProjectedSizeHistogram   prometheus.Histogram
	cpProfileEntriesRawHistogram      *prometheus.HistogramVec
	cpProfileEntriesRetainedHistogram *prometheus.HistogramVec
	cpProfileRetentionRatioHistogram  *prometheus.HistogramVec

	// Cache to avoid allocating Labels maps on every call
	ruleCounterCache          map[string]prometheus.Counter
	rulePrefilteredCounterCache map[string]prometheus.Counter
	alertCounterCache         map[string]prometheus.Counter
	counterCacheMutex sync.RWMutex
}

func NewPrometheusMetric() *PrometheusMetric {
	return &PrometheusMetric{
		ebpfExecCounter: promauto.NewCounter(prometheus.CounterOpts{
			Name: "node_agent_exec_counter",
			Help: "The total number of exec events received from the eBPF probe",
		}),
		ebpfOpenCounter: promauto.NewCounter(prometheus.CounterOpts{
			Name: "node_agent_open_counter",
			Help: "The total number of open events received from the eBPF probe",
		}),
		ebpfNetworkCounter: promauto.NewCounter(prometheus.CounterOpts{
			Name: "node_agent_network_counter",
			Help: "The total number of network events received from the eBPF probe",
		}),
		ebpfDNSCounter: promauto.NewCounter(prometheus.CounterOpts{
			Name: "node_agent_dns_counter",
			Help: "The total number of DNS events received from the eBPF probe",
		}),
		ebpfSyscallCounter: promauto.NewCounter(prometheus.CounterOpts{
			Name: "node_agent_syscall_counter",
			Help: "The total number of syscall events received from the eBPF probe",
		}),
		ebpfCapabilityCounter: promauto.NewCounter(prometheus.CounterOpts{
			Name: "node_agent_capability_counter",
			Help: "The total number of capability events received from the eBPF probe",
		}),
		ebpfRandomXCounter: promauto.NewCounter(prometheus.CounterOpts{
			Name: "node_agent_randomx_counter",
			Help: "The total number of randomx events received from the eBPF probe",
		}),
		ebpfFailedCounter: promauto.NewCounter(prometheus.CounterOpts{
			Name: "node_agent_ebpf_event_failure_counter",
			Help: "The total number of failed events received from the eBPF probe",
		}),
		ebpfSymlinkCounter: promauto.NewCounter(prometheus.CounterOpts{
			Name: "node_agent_symlink_counter",
			Help: "The total number of symlink events received from the eBPF probe",
		}),
		ebpfHardlinkCounter: promauto.NewCounter(prometheus.CounterOpts{
			Name: "node_agent_hardlink_counter",
			Help: "The total number of hardlink events received from the eBPF probe",
		}),
		ebpfSSHCounter: promauto.NewCounter(prometheus.CounterOpts{
			Name: "node_agent_ssh_counter",
			Help: "The total number of SSH events received from the eBPF probe",
		}),
		ebpfHTTPCounter: promauto.NewCounter(prometheus.CounterOpts{
			Name: "node_agent_http_counter",
			Help: "The total number of HTTP events received from the eBPF probe",
		}),
		ebpfPtraceCounter: promauto.NewCounter(prometheus.CounterOpts{
			Name: "node_agent_ptrace_counter",
			Help: "The total number of ptrace events received from the eBPF probe",
		}),
		ebpfIoUringCounter: promauto.NewCounter(prometheus.CounterOpts{
			Name: "node_agent_iouring_counter",
			Help: "The total number of io_uring events received from the eBPF probe",
		}),
		ebpfKmodCounter: promauto.NewCounter(prometheus.CounterOpts{
			Name: "node_agent_kmod_counter",
			Help: "The total number of kmod events received from the eBPF probe",
		}),
		ebpfUnshareCounter: promauto.NewCounter(prometheus.CounterOpts{
			Name: "node_agent_unshare_counter",
			Help: "The total number of unshare events received from the eBPF probe",
		}),
		ebpfBpfCounter: promauto.NewCounter(prometheus.CounterOpts{
			Name: "node_agent_bpf_counter",
			Help: "The total number of bpf events received from the eBPF probe",
		}),
		ruleCounter: promauto.NewCounterVec(prometheus.CounterOpts{
			Name: "node_agent_rule_counter",
			Help: "The total number of rules processed by the engine",
		}, []string{prometheusRuleIdLabel}),
		rulePrefilteredCounter: promauto.NewCounterVec(prometheus.CounterOpts{
			Name: "node_agent_rule_prefiltered_total",
			Help: "Total number of rule evaluations skipped by pre-filter",
		}, []string{prometheusRuleIdLabel}),
		alertCounter: promauto.NewCounterVec(prometheus.CounterOpts{
			Name: "node_agent_alert_counter",
			Help: "The total number of alerts sent by the engine",
		}, []string{prometheusRuleIdLabel}),
		ruleEvaluationTime: promauto.NewHistogramVec(prometheus.HistogramOpts{
			Name:    "node_agent_rule_evaluation_time_seconds",
			Help:    "Time taken to evaluate a rule by rule ID and event type",
			Buckets: prometheus.ExponentialBuckets(0.001, 2, 10), // 1ms to 1024s
		}, []string{prometheusRuleIdLabel, eventTypeLabel}),

		// Program ID metrics
		programRuntimeGauge: promauto.NewGaugeVec(prometheus.GaugeOpts{
			Name: "node_agent_program_current_runtime",
			Help: "Current runtime of programs by program ID",
		}, []string{programTypeLabel, programNameLabel}),

		programRunCountGauge: promauto.NewGaugeVec(prometheus.GaugeOpts{
			Name: "node_agent_program_current_run_count",
			Help: "Current run count of programs by program ID",
		}, []string{programTypeLabel, programNameLabel}),

		programTotalRuntimeGauge: promauto.NewGaugeVec(prometheus.GaugeOpts{
			Name: "node_agent_program_total_runtime",
			Help: "Total runtime of programs by program ID",
		}, []string{programTypeLabel, programNameLabel}),

		programTotalRunCountGauge: promauto.NewGaugeVec(prometheus.GaugeOpts{
			Name: "node_agent_program_total_run_count",
			Help: "Total run count of programs by program ID",
		}, []string{programTypeLabel, programNameLabel}),

		programMapMemoryGauge: promauto.NewGaugeVec(prometheus.GaugeOpts{
			Name: "node_agent_program_map_memory",
			Help: "Map memory usage of programs by program ID",
		}, []string{programTypeLabel, programNameLabel}),

		programMapCountGauge: promauto.NewGaugeVec(prometheus.GaugeOpts{
			Name: "node_agent_program_map_count",
			Help: "Map count of programs by program ID",
		}, []string{programTypeLabel, programNameLabel}),

		programCpuUsageGauge: promauto.NewGaugeVec(prometheus.GaugeOpts{
			Name: "node_agent_program_total_cpu_usage",
			Help: "Total CPU usage of programs by program ID",
		}, []string{programTypeLabel, programNameLabel}),

		programPerCpuUsageGauge: promauto.NewGaugeVec(prometheus.GaugeOpts{
			Name: "node_agent_program_per_cpu_usage",
			Help: "Per-CPU usage of programs by program ID",
		}, []string{programTypeLabel, programNameLabel}),

		// Container metrics
		containerStartCounter: promauto.NewCounter(prometheus.CounterOpts{
			Name: "node_agent_container_start_counter",
			Help: "The total number of container start events",
		}),
		containerStopCounter: promauto.NewCounter(prometheus.CounterOpts{
			Name: "node_agent_container_stop_counter",
			Help: "The total number of container stop events",
		}),

		// Dedup metrics
		dedupEventCounter: promauto.NewCounterVec(prometheus.CounterOpts{
			Name: "node_agent_dedup_events_total",
			Help: "Total number of events processed by the dedup layer",
		}, []string{eventTypeLabel, "result"}),

		// ContainerProfile cache metrics
		cpCacheLegacyLoadsCounter: promauto.NewCounterVec(prometheus.CounterOpts{
			Name: "node_agent_user_profile_legacy_loads_total",
			Help: "Number of times a user-authored legacy ApplicationProfile or NetworkNeighborhood was loaded into the ContainerProfileCache; will be removed in a future release.",
		}, []string{"kind", "completeness"}),
		cpCacheEntriesGauge: promauto.NewGaugeVec(prometheus.GaugeOpts{
			Name: "node_agent_containerprofile_cache_entries",
			Help: "Current number of cached ContainerProfile entries per kind.",
		}, []string{"kind"}),
		cpCacheHitCounter: promauto.NewCounterVec(prometheus.CounterOpts{
			Name: "node_agent_containerprofile_cache_hit_total",
			Help: "Total number of ContainerProfile cache lookups by result.",
		}, []string{"result"}),
		cpReconcilerDurationHistogram: promauto.NewHistogramVec(prometheus.HistogramOpts{
			Name:    "node_agent_containerprofile_reconciler_duration_seconds",
			Help:    "Duration of ContainerProfile reconciler phases in seconds.",
			Buckets: prometheus.DefBuckets,
		}, []string{"phase"}),
		cpReconcilerEvictionsCounter: promauto.NewCounterVec(prometheus.CounterOpts{
			Name: "node_agent_containerprofile_reconciler_evictions_total",
			Help: "Total number of ContainerProfile cache evictions by reason.",
		}, []string{"reason"}),

		// Profile projection metrics — always-on
		cpProjectionMissingDeclCounter: promauto.NewCounterVec(prometheus.CounterOpts{
			Name: "rule_load_rejected_missing_declaration_total",
			Help: "Total rules with profileDependency>0 but no profileDataRequired declaration.",
		}, []string{"rule_id"}),
		cpProjectionUndeclaredLiteralCounter: promauto.NewCounterVec(prometheus.CounterOpts{
			Name: "rule_projection_undeclared_literal_total",
			Help: "Total literal values evaluated against a projected field that was not declared.",
		}, []string{"helper"}),
		cpProjectionStaleEntriesGauge: promauto.NewGauge(prometheus.GaugeOpts{
			Name: "rule_projection_stale_entries",
			Help: "Current number of projected cache entries whose spec hash is stale.",
		}),
		cpProjectionUndeclaredRulesGauge: promauto.NewGauge(prometheus.GaugeOpts{
			Name: "rule_projection_undeclared_rules",
			Help: "Currently-loaded rules with no profileDataRequired field.",
		}),

		// Profile projection metrics — detailed
		cpProjectionSpecCompileCounter: promauto.NewCounter(prometheus.CounterOpts{
			Name: "rule_projection_spec_compile_total",
			Help: "Total number of times the projection spec was compiled.",
		}),
		cpProjectionSpecHashChangeCounter: promauto.NewCounter(prometheus.CounterOpts{
			Name: "rule_projection_spec_hash_changes_total",
			Help: "Total number of times the projection spec hash changed.",
		}),
		cpProjectionSpecPatternsGauge: promauto.NewGaugeVec(prometheus.GaugeOpts{
			Name: "rule_projection_spec_patterns",
			Help: "Number of patterns per field and kind in the current projection spec.",
		}, []string{"field", "kind"}),
		cpProjectionSpecAllFieldsGauge: promauto.NewGaugeVec(prometheus.GaugeOpts{
			Name: "rule_projection_spec_all_fields",
			Help: "Whether a projection spec field has All=true (1) or not (0).",
		}, []string{"field"}),
		cpProjectionApplyDurationHistogram: promauto.NewHistogram(prometheus.HistogramOpts{
			Name:    "rule_projection_apply_duration_seconds",
			Help:    "Duration of profile projection Apply calls in seconds.",
			Buckets: prometheus.DefBuckets,
		}),
		cpProjectionReconcileTriggeredCounter: promauto.NewCounterVec(prometheus.CounterOpts{
			Name: "rule_projection_reconcile_triggered_total",
			Help: "Total number of projection reconcile triggers by type.",
		}, []string{"trigger"}),
		cpHelperCallCounter: promauto.NewCounterVec(prometheus.CounterOpts{
			Name: "rule_helper_call_total",
			Help: "Total number of profile-helper CEL function calls.",
		}, []string{"helper"}),
		cpProjectionUndeclaredRulesListGauge: promauto.NewGaugeVec(prometheus.GaugeOpts{
			Name: "rule_projection_undeclared_rules_list",
			Help: "Per-rule gauge (1) for each rule currently loaded without a profileDataRequired declaration.",
		}, []string{"rule_id"}),

		// Memory-savings metrics — detailed
		cpProfileRawSizeHistogram: promauto.NewHistogram(prometheus.HistogramOpts{
			Name:    "profile_raw_size_bytes",
			Help:    "Approximate byte size of raw ContainerProfile string data before projection.",
			Buckets: []float64{0, 1024, 4096, 16384, 65536, 262144, 1048576, 4194304},
		}),
		cpProfileProjectedSizeHistogram: promauto.NewHistogram(prometheus.HistogramOpts{
			Name:    "profile_projected_size_bytes",
			Help:    "Approximate byte size of projected ContainerProfile string data after projection.",
			Buckets: []float64{0, 1024, 4096, 16384, 65536, 262144, 1048576, 4194304},
		}),
		cpProfileEntriesRawHistogram: promauto.NewHistogramVec(prometheus.HistogramOpts{
			Name:    "profile_entries_raw_total",
			Help:    "Number of entries per field in the raw profile before projection.",
			Buckets: []float64{0, 1, 5, 10, 50, 100, 500, 1000, 5000},
		}, []string{"field"}),
		cpProfileEntriesRetainedHistogram: promauto.NewHistogramVec(prometheus.HistogramOpts{
			Name:    "profile_entries_retained_total",
			Help:    "Number of entries per field retained after projection.",
			Buckets: []float64{0, 1, 5, 10, 50, 100, 500, 1000, 5000},
		}, []string{"field"}),
		cpProfileRetentionRatioHistogram: promauto.NewHistogramVec(prometheus.HistogramOpts{
			Name:    "profile_retention_ratio",
			Help:    "Fraction of entries retained per field after projection (retained/raw).",
			Buckets: []float64{0, 0.1, 0.2, 0.3, 0.4, 0.5, 0.6, 0.7, 0.8, 0.9, 1.0},
		}, []string{"field"}),

		// Initialize counter caches
		ruleCounterCache:            make(map[string]prometheus.Counter),
		rulePrefilteredCounterCache: make(map[string]prometheus.Counter),
		alertCounterCache:           make(map[string]prometheus.Counter),
	}
}

func (p *PrometheusMetric) Start() {
	// Start prometheus metrics server
	go func() {
		http.Handle("/metrics", promhttp.Handler())
		logger.L().Info("prometheus metrics server started", helpers.Int("port", 8080), helpers.String("path", "/metrics"))
		logger.L().Fatal(http.ListenAndServe(":8080", nil).Error())
	}()
}

func (p *PrometheusMetric) Destroy() {
	prometheus.Unregister(p.ebpfExecCounter)
	prometheus.Unregister(p.ebpfOpenCounter)
	prometheus.Unregister(p.ebpfNetworkCounter)
	prometheus.Unregister(p.ebpfDNSCounter)
	prometheus.Unregister(p.ebpfSyscallCounter)
	prometheus.Unregister(p.ebpfCapabilityCounter)
	prometheus.Unregister(p.ebpfRandomXCounter)
	prometheus.Unregister(p.ebpfFailedCounter)
	prometheus.Unregister(p.ruleCounter)
	prometheus.Unregister(p.rulePrefilteredCounter)
	prometheus.Unregister(p.alertCounter)
	prometheus.Unregister(p.ruleEvaluationTime)
	prometheus.Unregister(p.ebpfSymlinkCounter)
	prometheus.Unregister(p.ebpfHardlinkCounter)
	prometheus.Unregister(p.ebpfSSHCounter)
	prometheus.Unregister(p.ebpfHTTPCounter)
	prometheus.Unregister(p.ebpfPtraceCounter)
	prometheus.Unregister(p.ebpfIoUringCounter)
	prometheus.Unregister(p.ebpfKmodCounter)
	prometheus.Unregister(p.ebpfUnshareCounter)
	prometheus.Unregister(p.ebpfBpfCounter)
	prometheus.Unregister(p.containerStartCounter)
	prometheus.Unregister(p.containerStopCounter)
	prometheus.Unregister(p.dedupEventCounter)
	prometheus.Unregister(p.cpCacheLegacyLoadsCounter)
	prometheus.Unregister(p.cpCacheEntriesGauge)
	prometheus.Unregister(p.cpCacheHitCounter)
	prometheus.Unregister(p.cpReconcilerDurationHistogram)
	prometheus.Unregister(p.cpReconcilerEvictionsCounter)
	prometheus.Unregister(p.cpProjectionMissingDeclCounter)
	prometheus.Unregister(p.cpProjectionUndeclaredLiteralCounter)
	prometheus.Unregister(p.cpProjectionStaleEntriesGauge)
	prometheus.Unregister(p.cpProjectionUndeclaredRulesGauge)
	prometheus.Unregister(p.cpProjectionSpecCompileCounter)
	prometheus.Unregister(p.cpProjectionSpecHashChangeCounter)
	prometheus.Unregister(p.cpProjectionSpecPatternsGauge)
	prometheus.Unregister(p.cpProjectionSpecAllFieldsGauge)
	prometheus.Unregister(p.cpProjectionApplyDurationHistogram)
	prometheus.Unregister(p.cpProjectionReconcileTriggeredCounter)
	prometheus.Unregister(p.cpHelperCallCounter)
	prometheus.Unregister(p.cpProjectionUndeclaredRulesListGauge)
	prometheus.Unregister(p.cpProfileRawSizeHistogram)
	prometheus.Unregister(p.cpProfileProjectedSizeHistogram)
	prometheus.Unregister(p.cpProfileEntriesRawHistogram)
	prometheus.Unregister(p.cpProfileEntriesRetainedHistogram)
	prometheus.Unregister(p.cpProfileRetentionRatioHistogram)
	// Unregister program ID metrics
	prometheus.Unregister(p.programRuntimeGauge)
	prometheus.Unregister(p.programRunCountGauge)
	prometheus.Unregister(p.programTotalRuntimeGauge)
	prometheus.Unregister(p.programTotalRunCountGauge)
	prometheus.Unregister(p.programMapMemoryGauge)
	prometheus.Unregister(p.programMapCountGauge)
	prometheus.Unregister(p.programCpuUsageGauge)
	prometheus.Unregister(p.programPerCpuUsageGauge)
}

func (p *PrometheusMetric) ReportEvent(eventType utils.EventType) {
	switch eventType {
	case utils.CapabilitiesEventType:
		p.ebpfCapabilityCounter.Inc()
	case utils.ExecveEventType:
		p.ebpfExecCounter.Inc()
	case utils.OpenEventType:
		p.ebpfOpenCounter.Inc()
	case utils.NetworkEventType:
		p.ebpfNetworkCounter.Inc()
	case utils.DnsEventType:
		p.ebpfDNSCounter.Inc()
	case utils.RandomXEventType:
		p.ebpfRandomXCounter.Inc()
	case utils.SymlinkEventType:
		p.ebpfSymlinkCounter.Inc()
	case utils.HardlinkEventType:
		p.ebpfHardlinkCounter.Inc()
	case utils.SSHEventType:
		p.ebpfSSHCounter.Inc()
	case utils.HTTPEventType:
		p.ebpfHTTPCounter.Inc()
	case utils.PtraceEventType:
		p.ebpfPtraceCounter.Inc()
	case utils.IoUringEventType:
		p.ebpfIoUringCounter.Inc()
	case utils.SyscallEventType:
		p.ebpfSyscallCounter.Inc()
	case utils.KmodEventType:
		p.ebpfKmodCounter.Inc()
	case utils.UnshareEventType:
		p.ebpfUnshareCounter.Inc()
	case utils.BpfEventType:
		p.ebpfBpfCounter.Inc()
	}
}

func (p *PrometheusMetric) ReportFailedEvent() {
	p.ebpfFailedCounter.Inc()
}

// getCachedRuleCounter returns a cached counter for the given rule ID to avoid map allocations
func (p *PrometheusMetric) getCachedRuleCounter(ruleID string) prometheus.Counter {
	p.counterCacheMutex.RLock()
	counter, exists := p.ruleCounterCache[ruleID]
	p.counterCacheMutex.RUnlock()

	if exists {
		return counter
	}

	p.counterCacheMutex.Lock()
	defer p.counterCacheMutex.Unlock()

	// Double-check after acquiring write lock
	if counter, exists := p.ruleCounterCache[ruleID]; exists {
		return counter
	}

	// Create new counter and cache it
	counter = p.ruleCounter.With(prometheus.Labels{prometheusRuleIdLabel: ruleID})
	p.ruleCounterCache[ruleID] = counter
	return counter
}

// getCachedAlertCounter returns a cached counter for the given rule ID to avoid map allocations
func (p *PrometheusMetric) getCachedAlertCounter(ruleID string) prometheus.Counter {
	p.counterCacheMutex.RLock()
	counter, exists := p.alertCounterCache[ruleID]
	p.counterCacheMutex.RUnlock()

	if exists {
		return counter
	}

	p.counterCacheMutex.Lock()
	defer p.counterCacheMutex.Unlock()

	// Double-check after acquiring write lock
	if counter, exists := p.alertCounterCache[ruleID]; exists {
		return counter
	}

	// Create new counter and cache it
	counter = p.alertCounter.With(prometheus.Labels{prometheusRuleIdLabel: ruleID})
	p.alertCounterCache[ruleID] = counter
	return counter
}

func (p *PrometheusMetric) ReportRuleProcessed(ruleID string) {
	p.getCachedRuleCounter(ruleID).Inc()
}

func (p *PrometheusMetric) getCachedRulePrefilteredCounter(ruleName string) prometheus.Counter {
	p.counterCacheMutex.RLock()
	counter, exists := p.rulePrefilteredCounterCache[ruleName]
	p.counterCacheMutex.RUnlock()

	if exists {
		return counter
	}

	p.counterCacheMutex.Lock()
	defer p.counterCacheMutex.Unlock()

	if counter, exists := p.rulePrefilteredCounterCache[ruleName]; exists {
		return counter
	}

	counter = p.rulePrefilteredCounter.With(prometheus.Labels{prometheusRuleIdLabel: ruleName})
	p.rulePrefilteredCounterCache[ruleName] = counter
	return counter
}

func (p *PrometheusMetric) ReportRulePrefiltered(ruleName string) {
	p.getCachedRulePrefilteredCounter(ruleName).Inc()
}

func (p *PrometheusMetric) ReportRuleAlert(ruleID string) {
	p.getCachedAlertCounter(ruleID).Inc()
}

func (p *PrometheusMetric) ReportRuleEvaluationTime(ruleID string, eventType utils.EventType, duration time.Duration) {
	labels := prometheus.Labels{
		prometheusRuleIdLabel: ruleID,
		eventTypeLabel:        string(eventType),
	}
	p.ruleEvaluationTime.With(labels).Observe(duration.Seconds())
}

//func (p *PrometheusMetric) ReportEbpfStats(stats *top.Event[toptypes.Stats]) {
//	logger.L().Debug("reporting ebpf stats", helpers.Int("stats_count", len(stats.Stats)))
//
//	for _, stat := range stats.Stats {
//		labels := prometheus.Labels{
//			programTypeLabel: stat.Type,
//			programNameLabel: stat.Name,
//		}
//
//		p.programRuntimeGauge.With(labels).Set(float64(stat.CurrentRuntime))
//		p.programRunCountGauge.With(labels).Set(float64(stat.CurrentRunCount))
//		p.programTotalRuntimeGauge.With(labels).Set(float64(stat.TotalRuntime))
//		p.programTotalRunCountGauge.With(labels).Set(float64(stat.TotalRunCount))
//		p.programMapMemoryGauge.With(labels).Set(float64(stat.MapMemory))
//		p.programMapCountGauge.With(labels).Set(float64(stat.MapCount))
//		p.programCpuUsageGauge.With(labels).Set(stat.TotalCpuUsage)
//		p.programPerCpuUsageGauge.With(labels).Set(stat.PerCpuUsage)
//	}
//}

func (p *PrometheusMetric) ReportContainerStart() {
	p.containerStartCounter.Inc()
}

func (p *PrometheusMetric) ReportContainerStop() {
	p.containerStopCounter.Inc()
}

func (p *PrometheusMetric) ReportDedupEvent(eventType utils.EventType, duplicate bool) {
	result := "passed"
	if duplicate {
		result = "deduplicated"
	}
	p.dedupEventCounter.WithLabelValues(string(eventType), result).Inc()
}

func (p *PrometheusMetric) ReportContainerProfileLegacyLoad(kind, completeness string) {
	p.cpCacheLegacyLoadsCounter.WithLabelValues(kind, completeness).Inc()
}

func (p *PrometheusMetric) SetContainerProfileCacheEntries(kind string, count float64) {
	p.cpCacheEntriesGauge.WithLabelValues(kind).Set(count)
}

func (p *PrometheusMetric) ReportContainerProfileCacheHit(hit bool) {
	result := "hit"
	if !hit {
		result = "miss"
	}
	p.cpCacheHitCounter.WithLabelValues(result).Inc()
}

func (p *PrometheusMetric) ReportContainerProfileReconcilerDuration(phase string, duration time.Duration) {
	p.cpReconcilerDurationHistogram.WithLabelValues(phase).Observe(duration.Seconds())
}

func (p *PrometheusMetric) ReportContainerProfileReconcilerEviction(reason string) {
	p.cpReconcilerEvictionsCounter.WithLabelValues(reason).Inc()
}

func (p *PrometheusMetric) IncMissingProfileDataRequired(ruleID string) {
	p.cpProjectionMissingDeclCounter.WithLabelValues(ruleID).Inc()
}
func (p *PrometheusMetric) IncProjectionUndeclaredLiteral(helper string) {
	p.cpProjectionUndeclaredLiteralCounter.WithLabelValues(helper).Inc()
}
func (p *PrometheusMetric) SetProjectionStaleEntries(count float64) {
	p.cpProjectionStaleEntriesGauge.Set(count)
}
func (p *PrometheusMetric) SetProjectionUndeclaredRules(count float64) {
	p.cpProjectionUndeclaredRulesGauge.Set(count)
}
func (p *PrometheusMetric) IncProjectionSpecCompile() {
	p.cpProjectionSpecCompileCounter.Inc()
}
func (p *PrometheusMetric) IncProjectionSpecHashChange() {
	p.cpProjectionSpecHashChangeCounter.Inc()
}
func (p *PrometheusMetric) SetProjectionSpecPatterns(field, kind string, count float64) {
	p.cpProjectionSpecPatternsGauge.WithLabelValues(field, kind).Set(count)
}
func (p *PrometheusMetric) SetProjectionSpecAllField(field string, isAll bool) {
	v := float64(0)
	if isAll {
		v = 1
	}
	p.cpProjectionSpecAllFieldsGauge.WithLabelValues(field).Set(v)
}
func (p *PrometheusMetric) ObserveProjectionApplyDuration(d time.Duration) {
	p.cpProjectionApplyDurationHistogram.Observe(d.Seconds())
}
func (p *PrometheusMetric) IncProjectionReconcileTriggered(trigger string) {
	p.cpProjectionReconcileTriggeredCounter.WithLabelValues(trigger).Inc()
}
func (p *PrometheusMetric) IncHelperCall(helper string) {
	p.cpHelperCallCounter.WithLabelValues(helper).Inc()
}
func (p *PrometheusMetric) SetProjectionUndeclaredRulesDetail(ruleIDs []string) {
	p.cpProjectionUndeclaredRulesListGauge.Reset()
	for _, id := range ruleIDs {
		p.cpProjectionUndeclaredRulesListGauge.WithLabelValues(id).Set(1)
	}
}
func (p *PrometheusMetric) ObserveProfileRawSize(bytes float64) {
	p.cpProfileRawSizeHistogram.Observe(bytes)
}
func (p *PrometheusMetric) ObserveProfileProjectedSize(bytes float64) {
	p.cpProfileProjectedSizeHistogram.Observe(bytes)
}
func (p *PrometheusMetric) ObserveProfileEntriesRaw(field string, count float64) {
	p.cpProfileEntriesRawHistogram.WithLabelValues(field).Observe(count)
}
func (p *PrometheusMetric) ObserveProfileEntriesRetained(field string, count float64) {
	p.cpProfileEntriesRetainedHistogram.WithLabelValues(field).Observe(count)
}
func (p *PrometheusMetric) ObserveProfileRetentionRatio(field string, ratio float64) {
	p.cpProfileRetentionRatioHistogram.WithLabelValues(field).Observe(ratio)
}
