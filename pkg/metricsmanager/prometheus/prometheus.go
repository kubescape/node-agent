package metricsmanager

import (
	"net/http"
	"sync"
	"time"

	"github.com/inspektor-gadget/inspektor-gadget/pkg/gadgets/top"
	toptypes "github.com/inspektor-gadget/inspektor-gadget/pkg/gadgets/top/ebpf/types"
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
	ruleCounter           *prometheus.CounterVec
	alertCounter          *prometheus.CounterVec
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

	// Cache to avoid allocating Labels maps on every call
	ruleCounterCache  map[string]prometheus.Counter
	alertCounterCache map[string]prometheus.Counter
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
		ruleCounter: promauto.NewCounterVec(prometheus.CounterOpts{
			Name: "node_agent_rule_counter",
			Help: "The total number of rules processed by the engine",
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

		// Initialize counter caches
		ruleCounterCache:  make(map[string]prometheus.Counter),
		alertCounterCache: make(map[string]prometheus.Counter),
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
	prometheus.Unregister(p.alertCounter)
	prometheus.Unregister(p.ruleEvaluationTime)

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
	case utils.ExecveEventType:
		p.ebpfExecCounter.Inc()
	case utils.OpenEventType:
		p.ebpfOpenCounter.Inc()
	case utils.NetworkEventType:
		p.ebpfNetworkCounter.Inc()
	case utils.DnsEventType:
		p.ebpfDNSCounter.Inc()
	case utils.SyscallEventType:
		p.ebpfSyscallCounter.Inc()
	case utils.CapabilitiesEventType:
		p.ebpfCapabilityCounter.Inc()
	case utils.RandomXEventType:
		p.ebpfRandomXCounter.Inc()
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

func (p *PrometheusMetric) ReportEbpfStats(stats *top.Event[toptypes.Stats]) {
	logger.L().Debug("reporting ebpf stats", helpers.Int("stats_count", len(stats.Stats)))

	for _, stat := range stats.Stats {
		labels := prometheus.Labels{
			programTypeLabel: stat.Type,
			programNameLabel: stat.Name,
		}

		p.programRuntimeGauge.With(labels).Set(float64(stat.CurrentRuntime))
		p.programRunCountGauge.With(labels).Set(float64(stat.CurrentRunCount))
		p.programTotalRuntimeGauge.With(labels).Set(float64(stat.TotalRuntime))
		p.programTotalRunCountGauge.With(labels).Set(float64(stat.TotalRunCount))
		p.programMapMemoryGauge.With(labels).Set(float64(stat.MapMemory))
		p.programMapCountGauge.With(labels).Set(float64(stat.MapCount))
		p.programCpuUsageGauge.With(labels).Set(stat.TotalCpuUsage)
		p.programPerCpuUsageGauge.With(labels).Set(stat.PerCpuUsage)
	}
}
