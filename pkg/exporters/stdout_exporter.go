package exporters

import (
	"node-agent/pkg/malwaremanager"
	"node-agent/pkg/ruleengine"
	"os"

	log "github.com/sirupsen/logrus"
)

type StdoutExporter struct {
	logger *log.Logger
}

func InitStdoutExporter(useStdout *bool) *StdoutExporter {
	if useStdout == nil {
		useStdout = new(bool)
		*useStdout = os.Getenv("STDOUT_ENABLED") != "false"
	}
	if !*useStdout {
		return nil
	}

	logger := log.New()
	logger.SetFormatter(&log.JSONFormatter{})
	logger.SetOutput(os.Stderr)

	return &StdoutExporter{
		logger: logger,
	}
}

func (exporter *StdoutExporter) SendRuleAlert(failedRule ruleengine.RuleFailure) {
	exporter.logger.WithFields(log.Fields{
		"message":               failedRule.GetRuleAlert().RuleDescription,
		"event":                 failedRule.GetTriggerEvent(),
		"BaseRuntimeMetadata":   failedRule.GetBaseRuntimeAlert(),
		"RuntimeProcessDetails": failedRule.GetRuntimeProcessDetails(),
		"RuntimeK8sDetails":     failedRule.GetRuntimeAlertK8sDetails(),
		"RuleID":                failedRule.GetRuleId(),
	}).Error(failedRule.GetBaseRuntimeAlert().AlertName)
}

func (exporter *StdoutExporter) SendMalwareAlert(malwareResult malwaremanager.MalwareResult) {
	exporter.logger.WithFields(log.Fields{
		"message":               malwareResult.GetMalwareRuntimeAlert().MalwareDescription,
		"event":                 malwareResult.GetTriggerEvent(),
		"BaseRuntimeMetadata":   malwareResult.GetBasicRuntimeAlert(),
		"RuntimeProcessDetails": malwareResult.GetRuntimeProcessDetails(),
		"RuntimeK8sDetails":     malwareResult.GetRuntimeAlertK8sDetails(),
		"RuleID":                "R3000",
	}).Error(malwareResult.GetBasicRuntimeAlert().AlertName)
}
