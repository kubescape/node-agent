package exporters

import (
	"os"

	apitypes "github.com/armosec/armoapi-go/armotypes"
	"github.com/kubescape/node-agent/pkg/malwaremanager"
	"github.com/kubescape/node-agent/pkg/ruleengine"

	log "github.com/sirupsen/logrus"
)

type StdoutExporter struct {
	logger        *log.Logger
	cloudmetadata *apitypes.CloudMetadata
}

func InitStdoutExporter(useStdout *bool, cloudmetadata *apitypes.CloudMetadata) *StdoutExporter {
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
		logger:        logger,
		cloudmetadata: cloudmetadata,
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
		"CloudMetadata":         exporter.cloudmetadata,
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
		"CloudMetadata":         exporter.cloudmetadata,
	}).Error(malwareResult.GetBasicRuntimeAlert().AlertName)
}
