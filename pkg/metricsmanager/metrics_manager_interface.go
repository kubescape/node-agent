package metricsmanager

import (
	"time"

	"github.com/kubescape/node-agent/pkg/utils"
)

// MetricsManager is an interface for reporting metrics
type MetricsManager interface {
	Start()
	Destroy()
	ReportEvent(eventType utils.EventType)
	ReportFailedEvent()
	ReportRuleProcessed(ruleID string)
	ReportRuleAlert(ruleID string)
	ReportRuleEvaluationTime(ruleID string, eventType utils.EventType, duration time.Duration)
	//ReportEbpfStats(stats *top.Event[toptypes.Stats])
	ReportContainerStart()
	ReportContainerStop()
}
