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
		"severity":              failedRule.GetBaseRuntimeAlert().Severity,
		"message":               failedRule.GetRuleAlert().RuleDescription,
		"event":                 failedRule.GetTriggerEvent(),
		"BaseRuntimeMetadata":   failedRule.GetBaseRuntimeAlert(),
		"RuntimeProcessDetails": failedRule.GetRuntimeProcessDetails(),
		"RuntimeK8sDetails":     failedRule.GetRuntimeAlertK8sDetails(),
	}).Error(failedRule.GetBaseRuntimeAlert().AlertName)
}

func (exporter *StdoutExporter) SendMalwareAlert(malwareResult malwaremanager.MalwareResult) {
	exporter.logger.WithFields(log.Fields{
		"severity":             10,
		"description":          malwareResult.GetMalwareRuntimeAlert().MalwareDescription,
		"md5hash":              malwareResult.GetBasicRuntimeAlert().MD5Hash,
		"sha1hash":             malwareResult.GetBasicRuntimeAlert().SHA1Hash,
		"sha256hash":           malwareResult.GetBasicRuntimeAlert().SHA256Hash,
		"path":                 malwareResult.GetRuntimeProcessDetails().ProcessTree.Hardlink,
		"size":                 malwareResult.GetBasicRuntimeAlert().Size,
		"pod":                  malwareResult.GetTriggerEvent().GetBaseEvent().GetPod(),
		"namespace":            malwareResult.GetTriggerEvent().GetBaseEvent().GetNamespace(),
		"container":            malwareResult.GetTriggerEvent().GetBaseEvent().GetContainer(),
		"containerID":          malwareResult.GetTriggerEvent().Runtime.ContainerID,
		"isPartOfImage":        !malwareResult.GetRuntimeProcessDetails().ProcessTree.UpperLayer,
		"containerImage":       malwareResult.GetTriggerEvent().Runtime.ContainerImageName,
		"containerImageDigest": malwareResult.GetTriggerEvent().Runtime.ContainerImageDigest,
	}).Error(malwareResult.GetBasicRuntimeAlert().AlertName)
}
