package metricsmanager

import (
	"time"

	"github.com/kubescape/node-agent/pkg/utils"
)

var _ MetricsManager = (*MetricsNoop)(nil)

type MetricsNoop struct{}

func NewMetricsNoop() *MetricsNoop                                                          { return &MetricsNoop{} }
func (m *MetricsNoop) Start()                                                               {}
func (m *MetricsNoop) Destroy()                                                             {}
func (m *MetricsNoop) ReportEvent(_ utils.EventType)                                        {}
func (m *MetricsNoop) ReportFailedEvent()                                                   {}
func (m *MetricsNoop) ReportRuleProcessed(_ string)                                         {}
func (m *MetricsNoop) ReportRulePrefiltered(_ string)                                       {}
func (m *MetricsNoop) ReportRuleAlert(_ string)                                             {}
func (m *MetricsNoop) ReportRuleEvaluationTime(_ string, _ utils.EventType, _ time.Duration) {}
func (m *MetricsNoop) ReportContainerStart()                                                {}
func (m *MetricsNoop) ReportContainerStop()                                                 {}
