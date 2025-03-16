package metricsmanager

import (
	"net/http"
	"strconv"

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
	programIdLabel        = "program_id"
	programTypeLabel      = "program_type"
	programNameLabel      = "program_name"
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

	// Program ID metrics
	programRuntimeGauge       *prometheus.GaugeVec
	programRunCountGauge      *prometheus.GaugeVec
	programCumulRuntimeGauge  *prometheus.GaugeVec
	programCumulRunCountGauge *prometheus.GaugeVec
	programTotalRuntimeGauge  *prometheus.GaugeVec
	programTotalRunCountGauge *prometheus.GaugeVec
	programMapMemoryGauge     *prometheus.GaugeVec
	programMapCountGauge      *prometheus.GaugeVec
	programCpuUsageGauge      *prometheus.GaugeVec
	programPerCpuUsageGauge   *prometheus.GaugeVec
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

		// Program ID metrics
		programRuntimeGauge: promauto.NewGaugeVec(prometheus.GaugeOpts{
			Name: "node_agent_program_current_runtime",
			Help: "Current runtime of programs by program ID",
		}, []string{programIdLabel, programTypeLabel, programNameLabel}),

		programRunCountGauge: promauto.NewGaugeVec(prometheus.GaugeOpts{
			Name: "node_agent_program_current_run_count",
			Help: "Current run count of programs by program ID",
		}, []string{programIdLabel, programTypeLabel, programNameLabel}),

		programCumulRuntimeGauge: promauto.NewGaugeVec(prometheus.GaugeOpts{
			Name: "node_agent_program_cumulative_runtime",
			Help: "Cumulative runtime of programs by program ID",
		}, []string{programIdLabel, programTypeLabel, programNameLabel}),

		programCumulRunCountGauge: promauto.NewGaugeVec(prometheus.GaugeOpts{
			Name: "node_agent_program_cumulative_run_count",
			Help: "Cumulative run count of programs by program ID",
		}, []string{programIdLabel, programTypeLabel, programNameLabel}),

		programTotalRuntimeGauge: promauto.NewGaugeVec(prometheus.GaugeOpts{
			Name: "node_agent_program_total_runtime",
			Help: "Total runtime of programs by program ID",
		}, []string{programIdLabel, programTypeLabel, programNameLabel}),

		programTotalRunCountGauge: promauto.NewGaugeVec(prometheus.GaugeOpts{
			Name: "node_agent_program_total_run_count",
			Help: "Total run count of programs by program ID",
		}, []string{programIdLabel, programTypeLabel, programNameLabel}),

		programMapMemoryGauge: promauto.NewGaugeVec(prometheus.GaugeOpts{
			Name: "node_agent_program_map_memory",
			Help: "Map memory usage of programs by program ID",
		}, []string{programIdLabel, programTypeLabel, programNameLabel}),

		programMapCountGauge: promauto.NewGaugeVec(prometheus.GaugeOpts{
			Name: "node_agent_program_map_count",
			Help: "Map count of programs by program ID",
		}, []string{programIdLabel, programTypeLabel, programNameLabel}),

		programCpuUsageGauge: promauto.NewGaugeVec(prometheus.GaugeOpts{
			Name: "node_agent_program_total_cpu_usage",
			Help: "Total CPU usage of programs by program ID",
		}, []string{programIdLabel, programTypeLabel, programNameLabel}),

		programPerCpuUsageGauge: promauto.NewGaugeVec(prometheus.GaugeOpts{
			Name: "node_agent_program_per_cpu_usage",
			Help: "Per-CPU usage of programs by program ID",
		}, []string{programIdLabel, programTypeLabel, programNameLabel}),
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

	// Unregister program ID metrics
	prometheus.Unregister(p.programRuntimeGauge)
	prometheus.Unregister(p.programRunCountGauge)
	prometheus.Unregister(p.programCumulRuntimeGauge)
	prometheus.Unregister(p.programCumulRunCountGauge)
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

func (p *PrometheusMetric) ReportRuleProcessed(ruleID string) {
	p.ruleCounter.With(prometheus.Labels{prometheusRuleIdLabel: ruleID}).Inc()
}

func (p *PrometheusMetric) ReportRuleAlert(ruleID string) {
	p.alertCounter.With(prometheus.Labels{prometheusRuleIdLabel: ruleID}).Inc()
}

func (p *PrometheusMetric) ReportEbpfStats(stats *top.Event[toptypes.Stats]) {
	if stats.Error != "" {
		logger.L().Warning(stats.Error)
		return
	}

	for _, stat := range stats.Stats {
		programIDStr := strconv.FormatUint(uint64(stat.ProgramID), 10)

		labels := prometheus.Labels{
			programIdLabel:   programIDStr,
			programTypeLabel: stat.Type,
			programNameLabel: stat.Name,
		}

		p.programRuntimeGauge.With(labels).Set(float64(stat.CurrentRuntime))
		p.programRunCountGauge.With(labels).Set(float64(stat.CurrentRunCount))
		p.programCumulRuntimeGauge.With(labels).Set(float64(stat.CumulativeRuntime))
		p.programCumulRunCountGauge.With(labels).Set(float64(stat.CumulativeRunCount))
		p.programTotalRuntimeGauge.With(labels).Set(float64(stat.TotalRuntime))
		p.programTotalRunCountGauge.With(labels).Set(float64(stat.TotalRunCount))
		p.programMapMemoryGauge.With(labels).Set(float64(stat.MapMemory))
		p.programMapCountGauge.With(labels).Set(float64(stat.MapCount))
		p.programCpuUsageGauge.With(labels).Set(stat.TotalCpuUsage)
		p.programPerCpuUsageGauge.With(labels).Set(stat.PerCpuUsage)
	}
}
