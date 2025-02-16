package exporters

import (
	"github.com/kubescape/node-agent/pkg/hosthashsensor"
	"github.com/kubescape/node-agent/pkg/malwaremanager"
	"github.com/kubescape/node-agent/pkg/ruleengine"
)

// generic exporter interface
type Exporter interface {
	// SendRuleAlert sends an alert on failed rule to the exporter
	SendRuleAlert(failedRule ruleengine.RuleFailure)
	// SendMalwareAlert sends an alert on malware detection to the exporter.
	SendMalwareAlert(malwareResult malwaremanager.MalwareResult)
	// SendFileHashAlerts sends an alert on file hash detection to the exporter.
	SendFileHashAlerts(fileHashResults []hosthashsensor.FileHashResult)
}

var _ Exporter = (*ExporterMock)(nil)

type ExporterMock struct{}

func (e *ExporterMock) SendRuleAlert(_ ruleengine.RuleFailure) {
}

func (e *ExporterMock) SendMalwareAlert(_ malwaremanager.MalwareResult) {
}

func (e *ExporterMock) SendFileHashAlerts(_ []hosthashsensor.FileHashResult) {
}
