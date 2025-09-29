package exporters

import (
	"fmt"
	"log/syslog"
	"os"
	"strings"
	"time"

	"github.com/kubescape/node-agent/pkg/auditmanager"
	"github.com/kubescape/node-agent/pkg/hostfimsensor"
	"github.com/kubescape/node-agent/pkg/malwaremanager"
	"github.com/kubescape/node-agent/pkg/ruleengine"

	"github.com/kubescape/go-logger"
	"github.com/kubescape/go-logger/helpers"

	"github.com/crewjam/rfc5424"
)

// SyslogExporter is an exporter that sends alerts to syslog
type SyslogExporter struct {
	writer *syslog.Writer
}

// InitSyslogExporter initializes a new SyslogExporter
func InitSyslogExporter(syslogHost string) *SyslogExporter {
	if syslogHost == "" {
		syslogHost = os.Getenv("SYSLOG_HOST")
		if syslogHost == "" {
			return nil
		}
	}

	// Set default protocol to UDP
	if os.Getenv("SYSLOG_PROTOCOL") == "" {
		os.Setenv("SYSLOG_PROTOCOL", "udp")
	}

	writer, err := syslog.Dial(os.Getenv("SYSLOG_PROTOCOL"), syslogHost, syslog.LOG_ERR, "kubecop")
	if err != nil {
		logger.L().Fatal("InitSyslogExporter - failed to initialize syslog exporter", helpers.Error(err))
		return nil
	}

	return &SyslogExporter{
		writer: writer,
	}
}

// SendRuleAlert sends an alert to syslog (RFC 5424) - https://tools.ietf.org/html/rfc5424
func (se *SyslogExporter) SendRuleAlert(failedRule ruleengine.RuleFailure) {
	message := rfc5424.Message{
		Priority:  rfc5424.Error,
		Timestamp: failedRule.GetBaseRuntimeAlert().Timestamp,
		Hostname:  failedRule.GetRuntimeAlertK8sDetails().PodName,
		AppName:   failedRule.GetRuntimeAlertK8sDetails().ContainerName,
		ProcessID: fmt.Sprintf("%d", failedRule.GetRuntimeProcessDetails().ProcessTree.PID),
		StructuredData: []rfc5424.StructuredData{
			{
				ID: fmt.Sprintf("kubecop@%d", failedRule.GetRuntimeProcessDetails().ProcessTree.PID),
				Parameters: []rfc5424.SDParam{
					{
						Name:  "rule",
						Value: failedRule.GetBaseRuntimeAlert().AlertName,
					},
					{
						Name:  "priority",
						Value: fmt.Sprintf("%d", failedRule.GetBaseRuntimeAlert().Severity),
					},
					{
						Name:  "error",
						Value: failedRule.GetRuleAlert().RuleDescription,
					},
					{
						Name:  "fix_suggestion",
						Value: failedRule.GetBaseRuntimeAlert().FixSuggestions,
					},
					{
						Name:  "comm",
						Value: failedRule.GetRuntimeProcessDetails().ProcessTree.Comm,
					},
					{
						Name:  "uid",
						Value: fmt.Sprintf("%d", failedRule.GetRuntimeProcessDetails().ProcessTree.Uid),
					},
					{
						Name:  "gid",
						Value: fmt.Sprintf("%d", failedRule.GetRuntimeProcessDetails().ProcessTree.Gid),
					},
					{
						Name:  "namespace",
						Value: failedRule.GetRuntimeAlertK8sDetails().Namespace,
					},
					{
						Name:  "pod_name",
						Value: failedRule.GetRuntimeAlertK8sDetails().PodName,
					},
					{
						Name:  "container_name",
						Value: failedRule.GetRuntimeAlertK8sDetails().ContainerName,
					},
					{
						Name:  "container_id",
						Value: failedRule.GetRuntimeAlertK8sDetails().ContainerID,
					},
				},
			},
		},
		Message: []byte(failedRule.GetRuleAlert().RuleDescription),
	}

	_, err := message.WriteTo(se.writer)
	if err != nil {
		logger.L().Warning("SyslogExporter - failed to send alert to syslog", helpers.Error(err))
	}
}

// SendMalwareAlert sends an alert to syslog (RFC 5424) - https://tools.ietf.org/html/rfc5424
func (se *SyslogExporter) SendMalwareAlert(malwareResult malwaremanager.MalwareResult) {
	message := rfc5424.Message{
		Priority:  rfc5424.Error,
		Timestamp: time.Now(),
		Hostname:  malwareResult.GetTriggerEvent().GetBaseEvent().GetPod(),
		AppName:   malwareResult.GetTriggerEvent().GetBaseEvent().GetContainer(),
		ProcessID: fmt.Sprintf("%d", os.Getpid()), // TODO: is this correct?
		StructuredData: []rfc5424.StructuredData{
			{
				ID: fmt.Sprintf("kubecop@%d", os.Getpid()),
				Parameters: []rfc5424.SDParam{
					{
						Name:  "malware_name",
						Value: malwareResult.GetBasicRuntimeAlert().AlertName,
					},
					{
						Name:  "description",
						Value: malwareResult.GetMalwareRuntimeAlert().MalwareDescription,
					},
					{
						Name:  "md5hash",
						Value: malwareResult.GetBasicRuntimeAlert().MD5Hash,
					},
					{
						Name:  "sha1hash",
						Value: malwareResult.GetBasicRuntimeAlert().SHA1Hash,
					},
					{
						Name:  "sha256hash",
						Value: malwareResult.GetBasicRuntimeAlert().SHA256Hash,
					},
					{
						Name:  "size",
						Value: malwareResult.GetBasicRuntimeAlert().Size,
					},
					{
						Name:  "namespace",
						Value: malwareResult.GetTriggerEvent().GetBaseEvent().GetNamespace(),
					},
					{
						Name:  "pod_name",
						Value: malwareResult.GetTriggerEvent().GetBaseEvent().GetPod(),
					},
					{
						Name:  "container_name",
						Value: malwareResult.GetTriggerEvent().GetBaseEvent().GetContainer(),
					},
					{
						Name:  "container_id",
						Value: malwareResult.GetTriggerEvent().Runtime.ContainerID,
					},
					{
						Name:  "container_image",
						Value: malwareResult.GetTriggerEvent().Runtime.ContainerImageName,
					},
					{
						Name:  "container_image_digest",
						Value: malwareResult.GetTriggerEvent().Runtime.ContainerImageDigest,
					},
				},
			},
		},
		Message: []byte(fmt.Sprintf("Malware '%s' detected in namespace '%s' pod '%s' description '%s'", malwareResult.GetBasicRuntimeAlert().AlertName, malwareResult.GetTriggerEvent().GetBaseEvent().GetNamespace(), malwareResult.GetTriggerEvent().GetBaseEvent().GetPod(), malwareResult.GetMalwareRuntimeAlert().MalwareDescription)),
	}

	_, err := message.WriteTo(se.writer)
	if err != nil {
		logger.L().Warning("SyslogExporter - failed to send alert to syslog", helpers.Error(err))
	}
}

func (se *SyslogExporter) SendFimAlerts(fimEvents []hostfimsensor.FimEvent) {
	// TODO: Implement FIM alerts sending logic
	logger.L().Debug("SyslogExporter.SendFimAlerts - stub implementation", helpers.Int("events", len(fimEvents)))
}

func (se *SyslogExporter) SendAuditAlert(auditResult auditmanager.AuditResult) {
	auditEvent := auditResult.GetAuditEvent()

	message := &rfc5424.Message{
		Priority:  rfc5424.Daemon | rfc5424.Info,
		Timestamp: time.Now(),
		Hostname:  "kubescape-node-agent",
		AppName:   "kubescape-node-agent",
		Message:   []byte(fmt.Sprintf("Audit event '%s' detected: type=%s path=%s pid=%d comm=%s", strings.Join(auditEvent.Keys, ","), auditEvent.Type.String(), auditEvent.Path, auditEvent.PID, auditEvent.Comm)),
	}

	_, err := message.WriteTo(se.writer)
	if err != nil {
		logger.L().Warning("SyslogExporter - failed to send audit alert to syslog", helpers.Error(err))
	}
}
