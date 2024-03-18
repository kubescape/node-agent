package metricsmanager

import (
	"node-agent/pkg/metricsmanager"
	"node-agent/pkg/utils"

	"github.com/prometheus/client_golang/prometheus"
)

var _ metricsmanager.MetricsManager = (*prometheusMetric)(nil)

type prometheusMetric struct {
	ebpfExecCounter       prometheus.Counter
	ebpfOpenCounter       prometheus.Counter
	ebpfNetworkCounter    prometheus.Counter
	ebpfDNSCounter        prometheus.Counter
	ebpfSyscallCounter    prometheus.Counter
	ebpfCapabilityCounter prometheus.Counter
	ebpfRandomXCounter    prometheus.Counter
	ebpfFailedCounter     prometheus.Counter
	ruleCounter           prometheus.Counter
	alertCounter          prometheus.Counter
}

func NewPrometheusMetric() *prometheusMetric {
	ebpfExecCounter := prometheus.NewCounter(prometheus.CounterOpts{
		Name: "kubescape_exec_counter",
		Help: "The total number of exec events received from the eBPF probe",
	})
	prometheus.MustRegister(ebpfExecCounter)

	ebpfOpenCounter := prometheus.NewCounter(prometheus.CounterOpts{
		Name: "kubescape_open_counter",
		Help: "The total number of open events received from the eBPF probe",
	})
	prometheus.MustRegister(ebpfOpenCounter)

	ebpfNetworkCounter := prometheus.NewCounter(prometheus.CounterOpts{
		Name: "kubescape_network_counter",
		Help: "The total number of network events received from the eBPF probe",
	})
	prometheus.MustRegister(ebpfNetworkCounter)

	ebpfDNSCounter := prometheus.NewCounter(prometheus.CounterOpts{
		Name: "kubescape_dns_counter",
		Help: "The total number of DNS events received from the eBPF probe",
	})
	prometheus.MustRegister(ebpfDNSCounter)

	ebpfSyscallCounter := prometheus.NewCounter(prometheus.CounterOpts{
		Name: "kubescape_syscall_counter",
		Help: "The total number of syscall events received from the eBPF probe",
	})
	prometheus.MustRegister(ebpfSyscallCounter)

	ebpfCapabilityCounter := prometheus.NewCounter(prometheus.CounterOpts{
		Name: "kubescape_capability_counter",
		Help: "The total number of capability events received from the eBPF probe",
	})
	prometheus.MustRegister(ebpfCapabilityCounter)

	ebpfRandomXCounter := prometheus.NewCounter(prometheus.CounterOpts{
		Name: "kubescape_randomx_counter",
		Help: "The total number of randomx events received from the eBPF probe",
	})
	prometheus.MustRegister(ebpfRandomXCounter)

	ruleCounter := prometheus.NewCounter(prometheus.CounterOpts{
		Name: "kubescape_rule_counter",
		Help: "The total number of rules processed by the engine",
	})
	prometheus.MustRegister(ruleCounter)

	alertCounter := prometheus.NewCounter(prometheus.CounterOpts{
		Name: "kubescape_alert_counter",
		Help: "The total number of alerts sent by the engine",
	})
	prometheus.MustRegister(alertCounter)

	ebpfFailedCounter := prometheus.NewCounter(prometheus.CounterOpts{
		Name: "kubescape_ebpf_event_failure_counter",
		Help: "The total number of failed events received from the eBPF probe",
	})
	prometheus.MustRegister(ebpfFailedCounter)

	return &prometheusMetric{
		ebpfExecCounter:       ebpfExecCounter,
		ebpfOpenCounter:       ebpfOpenCounter,
		ebpfNetworkCounter:    ebpfNetworkCounter,
		ebpfDNSCounter:        ebpfDNSCounter,
		ebpfSyscallCounter:    ebpfSyscallCounter,
		ebpfCapabilityCounter: ebpfCapabilityCounter,
		ebpfRandomXCounter:    ebpfRandomXCounter,
		ebpfFailedCounter:     ebpfFailedCounter,
		ruleCounter:           ruleCounter,
		alertCounter:          alertCounter,
	}
}

func (p *prometheusMetric) Destroy() {
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

func (p *prometheusMetric) ReportEvent(eventType utils.EventType) {
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

func (p *prometheusMetric) ReportFailedEvent() {
	p.ebpfFailedCounter.Inc()
}

func (p *prometheusMetric) ReportRuleProcessed(ruleID string) {
	p.ruleCounter.Inc()
}

func (p *prometheusMetric) ReportRuleAlert(ruleID string) {
	p.alertCounter.Inc()
}
