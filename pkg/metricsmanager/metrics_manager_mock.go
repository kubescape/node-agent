package metricsmanager

import (
	"sync/atomic"
	"time"

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

//func (m *MetricsMock) ReportEbpfStats(stats *top.Event[toptypes.Stats]) {
//}

func (m *MetricsMock) ReportRulePrefiltered(ruleName string) {}

func (m *MetricsMock) ReportContainerStart() {}

func (m *MetricsMock) ReportContainerStop() {}

func (m *MetricsMock) ReportDedupEvent(eventType utils.EventType, duplicate bool)          {}
func (m *MetricsMock) ReportContainerProfileLegacyLoad(_, _ string)                       {}
func (m *MetricsMock) SetContainerProfileCacheEntries(_ string, _ float64)                {}
func (m *MetricsMock) ReportContainerProfileCacheHit(_ bool)                              {}
func (m *MetricsMock) ReportContainerProfileReconcilerDuration(_ string, _ time.Duration) {}
func (m *MetricsMock) ReportContainerProfileReconcilerEviction(_ string)                  {}
func (m *MetricsMock) IncMissingProfileDataRequired(_ string)            {}
func (m *MetricsMock) IncProjectionUndeclaredLiteral(_ string)           {}
func (m *MetricsMock) SetProjectionStaleEntries(_ float64)               {}
func (m *MetricsMock) SetProjectionUndeclaredRules(_ float64)            {}
func (m *MetricsMock) IncProjectionSpecCompile()                         {}
func (m *MetricsMock) IncProjectionSpecHashChange()                      {}
func (m *MetricsMock) SetProjectionSpecPatterns(_, _ string, _ float64)  {}
func (m *MetricsMock) SetProjectionSpecAllField(_ string, _ bool)        {}
func (m *MetricsMock) ObserveProjectionApplyDuration(_ time.Duration)    {}
func (m *MetricsMock) IncProjectionReconcileTriggered(_ string)          {}
func (m *MetricsMock) IncHelperCall(_ string)                            {}
func (m *MetricsMock) SetProjectionUndeclaredRulesDetail(_ []string)     {}
func (m *MetricsMock) ObserveProfileRawSize(_ float64)                   {}
func (m *MetricsMock) ObserveProfileProjectedSize(_ float64)             {}
func (m *MetricsMock) ObserveProfileEntriesRaw(_ string, _ float64)     {}
func (m *MetricsMock) ObserveProfileEntriesRetained(_ string, _ float64) {}
func (m *MetricsMock) ObserveProfileRetentionRatio(_ string, _ float64)  {}
