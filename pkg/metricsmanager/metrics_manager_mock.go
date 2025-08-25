package metricsmanager

import (
	"sync/atomic"
	"time"

	"github.com/inspektor-gadget/inspektor-gadget/pkg/gadgets/top"
	toptypes "github.com/inspektor-gadget/inspektor-gadget/pkg/gadgets/top/ebpf/types"
	"github.com/kubescape/node-agent/pkg/utils"

	"github.com/goradd/maps"
)

var _ MetricsManager = (*MetricsMock)(nil)

type MetricsMock struct {
	FailedEventCounter   atomic.Int32
	RuleProcessedCounter maps.SafeMap[string, int]
	RuleAlertCounter     maps.SafeMap[string, int]
	EventCounter         maps.SafeMap[utils.EventType, int]
	RuleEvaluationTime   maps.SafeMap[string, time.Duration] // key: "ruleID:eventType"
}

func NewMetricsMock() *MetricsMock {
	return &MetricsMock{
		FailedEventCounter: atomic.Int32{},
	}
}

func (m *MetricsMock) Start() {
}

func (m *MetricsMock) Destroy() {
	m.FailedEventCounter.Store(0)
	m.RuleProcessedCounter.Clear()
	m.RuleAlertCounter.Clear()
	m.EventCounter.Clear()
	m.RuleEvaluationTime.Clear()
}

func (m *MetricsMock) ReportFailedEvent() {
	m.FailedEventCounter.Add(1)
}

func (m *MetricsMock) ReportEvent(eventType utils.EventType) {
	m.EventCounter.Set(eventType, m.EventCounter.Get(eventType)+1)
}

func (m *MetricsMock) ReportRuleProcessed(ruleID string) {
	m.RuleProcessedCounter.Set(ruleID, m.RuleProcessedCounter.Get(ruleID)+1)
}

func (m *MetricsMock) ReportRuleAlert(ruleID string) {
	m.RuleAlertCounter.Set(ruleID, m.RuleAlertCounter.Get(ruleID)+1)
}

func (m *MetricsMock) ReportRuleEvaluationTime(ruleID string, eventType utils.EventType, duration time.Duration) {
	key := ruleID + ":" + string(eventType)
	m.RuleEvaluationTime.Set(key, duration)
}

func (m *MetricsMock) ReportEbpfStats(stats *top.Event[toptypes.Stats]) {
}

func (m *MetricsMock) ReportContainerStart() {}

func (m *MetricsMock) ReportContainerStop() {}
