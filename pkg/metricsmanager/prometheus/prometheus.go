package metricsmanager

import (
	"net/http"

	"github.com/kubescape/node-agent/pkg/metricsmanager"
	"github.com/kubescape/node-agent/pkg/utils"

	"github.com/kubescape/go-logger"
	"github.com/kubescape/go-logger/helpers"
	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promauto"
	"github.com/prometheus/client_golang/prometheus/promhttp"
)

const (
	prometheusRuleIdLabel = "rule_id"
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
