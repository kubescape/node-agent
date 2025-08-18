package metricsmanager

import (
	"github.com/inspektor-gadget/inspektor-gadget/pkg/gadgets/top"
	toptypes "github.com/inspektor-gadget/inspektor-gadget/pkg/gadgets/top/ebpf/types"
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
	ReportEbpfStats(stats *top.Event[toptypes.Stats])
	ReportContainerStart()
	ReportContainerStop()
}
