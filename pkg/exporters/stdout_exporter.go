package exporters

import (
	"fmt"
	"os"

	apitypes "github.com/armosec/armoapi-go/armotypes"
	"github.com/kubescape/node-agent/pkg/malwaremanager"
	"github.com/kubescape/node-agent/pkg/rulemanager/types"
	"github.com/kubescape/node-agent/pkg/utils"

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

func (exporter *StdoutExporter) SendRuleAlert(failedRule types.RuleFailure) {
	processTree := failedRule.GetRuntimeProcessDetails().ProcessTree
	exporter.logger.WithFields(log.Fields{
		"message":               failedRule.GetRuleAlert().RuleDescription,
		"event":                 failedRule.GetTriggerEvent(), // TODO: Don't print payload
		"BaseRuntimeMetadata":   failedRule.GetBaseRuntimeAlert(),
		"RuntimeProcessDetails": failedRule.GetRuntimeProcessDetails(),
		"RuntimeK8sDetails":     failedRule.GetRuntimeAlertK8sDetails(),
		"RuleID":                failedRule.GetRuleId(),
		"CloudMetadata":         exporter.cloudmetadata,
		"processtree_depth":     fmt.Sprintf("%d", utils.CalculateProcessTreeDepth(&processTree)),
	}).Error(failedRule.GetBaseRuntimeAlert().AlertName)
}

func (exporter *StdoutExporter) SendMalwareAlert(malwareResult malwaremanager.MalwareResult) {
	processTree := malwareResult.GetRuntimeProcessDetails().ProcessTree

	exporter.logger.WithFields(log.Fields{
		"message":               malwareResult.GetMalwareRuntimeAlert().MalwareDescription,
		"event":                 malwareResult.GetTriggerEvent(),
		"BaseRuntimeMetadata":   malwareResult.GetBasicRuntimeAlert(),
		"RuntimeProcessDetails": malwareResult.GetRuntimeProcessDetails(),
		"RuntimeK8sDetails":     malwareResult.GetRuntimeAlertK8sDetails(),
		"RuleID":                "R3000",
		"CloudMetadata":         exporter.cloudmetadata,
		"processtree_depth":     fmt.Sprintf("%d", utils.CalculateProcessTreeDepth(&processTree)),
	}).Error(malwareResult.GetBasicRuntimeAlert().AlertName)
}
