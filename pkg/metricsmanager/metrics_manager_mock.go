package metricsmanager

import (
	"github.com/kubescape/node-agent/pkg/utils"
	"sync/atomic"

	"github.com/goradd/maps"
)

var _ MetricsManager = (*MetricsMock)(nil)

type MetricsMock struct {
	FailedEventCounter   atomic.Int32
	RuleProcessedCounter maps.SafeMap[string, int]
	RuleAlertCounter     maps.SafeMap[string, int]
	EventCounter         maps.SafeMap[utils.EventType, int]
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
