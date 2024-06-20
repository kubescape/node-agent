package metricsmanager

import "github.com/kubescape/node-agent/pkg/utils"

// MetricsManager is an interface for reporting metrics
type MetricsManager interface {
	Start()
	Destroy()
	ReportEvent(eventType utils.EventType)
	ReportFailedEvent()
	ReportRuleProcessed(ruleID string)
	ReportRuleAlert(ruleID string)
}
