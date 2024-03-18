package metricsmanager

import "node-agent/pkg/utils"

// MetricsManager is an interface for reporting metrics
type MetricsManager interface {
	Destroy()
	ReportEvent(eventType utils.EventType)
	ReportFailedEvent()
	ReportRuleProcessed(ruleID string)
	ReportRuleAlert(ruleID string)
}
