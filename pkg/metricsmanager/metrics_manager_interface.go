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
	ReportRulePrefiltered(ruleName string)
	ReportRuleAlert(ruleID string)
	ReportRuleEvaluationTime(ruleID string, eventType utils.EventType, duration time.Duration)
	//ReportEbpfStats(stats *top.Event[toptypes.Stats])
	ReportContainerStart()
	ReportContainerStop()
	ReportDedupEvent(eventType utils.EventType, duplicate bool)
	ReportContainerProfileLegacyLoad(kind, completeness string)
	SetContainerProfileCacheEntries(kind string, count float64)
	ReportContainerProfileCacheHit(hit bool)
	ReportContainerProfileReconcilerDuration(duration time.Duration)
	ReportContainerProfileReconcilerEviction(reason string)
}
