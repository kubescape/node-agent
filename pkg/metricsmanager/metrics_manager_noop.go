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
func (m *MetricsNoop) ReportDedupEvent(_ utils.EventType, _ bool)                           {}
func (m *MetricsNoop) ReportContainerProfileLegacyLoad(_, _ string)                        {}
func (m *MetricsNoop) SetContainerProfileCacheEntries(_ string, _ float64)                 {}
func (m *MetricsNoop) ReportContainerProfileCacheHit(_ bool)                               {}
func (m *MetricsNoop) ReportContainerProfileReconcilerDuration(_ string, _ time.Duration)  {}
func (m *MetricsNoop) ReportContainerProfileReconcilerEviction(_ string)                   {}
