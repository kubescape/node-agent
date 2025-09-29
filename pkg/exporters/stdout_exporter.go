package exporters

import (
	"fmt"
	"os"
	"strings"

	apitypes "github.com/armosec/armoapi-go/armotypes"
	"github.com/kubescape/node-agent/pkg/auditmanager"
	"github.com/kubescape/node-agent/pkg/hostfimsensor"
	"github.com/kubescape/node-agent/pkg/malwaremanager"
	"github.com/kubescape/node-agent/pkg/ruleengine"
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

func (exporter *StdoutExporter) SendRuleAlert(failedRule ruleengine.RuleFailure) {
	processTree := failedRule.GetRuntimeProcessDetails().ProcessTree
	exporter.logger.WithFields(log.Fields{
		"message":               failedRule.GetRuleAlert().RuleDescription,
		"event":                 failedRule.GetTriggerEvent(),
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

func (exporter *StdoutExporter) SendFimAlerts(fimEvents []hostfimsensor.FimEvent) {
	for _, event := range fimEvents {
		exporter.logger.WithFields(log.Fields{
			"event":       event.GetEventType(),
			"path":        event.GetPath(),
			"fileSize":    event.GetFileSize(),
			"fileInode":   event.GetFileInode(),
			"fileDevice":  event.GetFileDevice(),
			"fileMtime":   event.GetFileMtime(),
			"fileCtime":   event.GetFileCtime(),
			"uid":         event.GetUid(),
			"gid":         event.GetGid(),
			"mode":        event.GetMode(),
			"processPid":  event.GetProcessPid(),
			"processName": event.GetProcessName(),
			"processArgs": event.GetProcessArgs(),
			"hostName":    event.GetHostName(),
			"agentId":     event.GetAgentId(),
		}).Info("FIM event")
	}
}

func (exporter *StdoutExporter) SendAuditAlert(auditResult auditmanager.AuditResult) {
	auditEvent := auditResult.GetAuditEvent()

	exporter.logger.WithFields(log.Fields{
		"message":       fmt.Sprintf("Audit event: %d", auditEvent.Type),
		"audit_id":      auditEvent.AuditID,
		"message_type":  auditEvent.Type.String(),
		"rule_type":     auditEvent.RuleType,
		"keys":          strings.Join(auditEvent.Keys, ","),
		"pid":           auditEvent.PID,
		"uid":           auditEvent.UID,
		"comm":          auditEvent.Comm,
		"exe":           auditEvent.Exe,
		"path":          auditEvent.Path,
		"syscall":       auditEvent.Syscall,
		"container_id":  auditEvent.ContainerID,
		"pod":           auditEvent.Pod,
		"namespace":     auditEvent.Namespace,
		"raw_message":   auditEvent.RawMessage,
		"CloudMetadata": exporter.cloudmetadata,
		"tags":          auditEvent.Tags,
		"success":       auditEvent.Success,
		"exit":          auditEvent.Exit,
		"error_code":    auditEvent.ErrorCode,
		"sock_addr":     auditEvent.SockAddr,
		"sock_family":   auditEvent.SockFamily,
		"sock_port":     auditEvent.SockPort,
	}).Info(fmt.Sprintf("Audit Event: %s", strings.Join(auditEvent.Keys, ",")))
}
