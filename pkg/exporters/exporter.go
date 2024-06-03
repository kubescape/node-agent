package exporters

import (
	"node-agent/pkg/malwaremanager"
	"node-agent/pkg/ruleengine"
)

// generic exporter interface
type Exporter interface {
	// SendRuleAlert sends an alert on failed rule to the exporter
	SendRuleAlert(failedRule ruleengine.RuleFailure)
	// SendMalwareAlert sends an alert on malware detection to the exporter.
	SendMalwareAlert(malwareResult malwaremanager.MalwareResult)
}

var _ Exporter = (*ExporterMock)(nil)

type ExporterMock struct{}

func (e *ExporterMock) SendRuleAlert(_ ruleengine.RuleFailure) {
}

func (e *ExporterMock) SendMalwareAlert(_ malwaremanager.MalwareResult) {
}
