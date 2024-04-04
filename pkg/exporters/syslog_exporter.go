package exporters

import (
	"fmt"
	"log/syslog"
	"node-agent/pkg/malwaremanager"
	"node-agent/pkg/ruleengine"
	"os"
	"time"

	log "github.com/sirupsen/logrus"

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
		log.Printf("failed to initialize syslog exporter: %v", err)
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
		Timestamp: time.Unix(failedRule.Event().Timestamp, 0),
		Hostname:  failedRule.Event().PodName,
		AppName:   failedRule.Event().ContainerName,
		ProcessID: fmt.Sprintf("%d", failedRule.Event().Pid),
		StructuredData: []rfc5424.StructuredData{
			{
				ID: fmt.Sprintf("kubecop@%d", failedRule.Event().Pid),
				Parameters: []rfc5424.SDParam{
					{
						Name:  "rule",
						Value: failedRule.Name(),
					},
					{
						Name:  "priority",
						Value: fmt.Sprintf("%d", failedRule.Priority()),
					},
					{
						Name:  "error",
						Value: failedRule.Error(),
					},
					{
						Name:  "fix_suggestion",
						Value: failedRule.FixSuggestion(),
					},
					{
						Name:  "ppid",
						Value: fmt.Sprintf("%d", failedRule.Event().Ppid),
					},
					{
						Name:  "comm",
						Value: failedRule.Event().Comm,
					},
					{
						Name:  "uid",
						Value: fmt.Sprintf("%d", failedRule.Event().Uid),
					},
					{
						Name:  "gid",
						Value: fmt.Sprintf("%d", failedRule.Event().Gid),
					},
					{
						Name:  "namespace",
						Value: failedRule.Event().Namespace,
					},
					{
						Name:  "pod_name",
						Value: failedRule.Event().PodName,
					},
					{
						Name:  "container_name",
						Value: failedRule.Event().ContainerName,
					},
					{
						Name:  "container_id",
						Value: failedRule.Event().ContainerID,
					},
					{
						Name:  "cwd",
						Value: failedRule.Event().Cwd,
					},
				},
			},
		},
		Message: []byte(failedRule.Error()),
	}

	_, err := message.WriteTo(se.writer)
	if err != nil {
		log.Errorf("failed to send alert to syslog: %v", err)
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
						Name:  "path",
						Value: malwareResult.GetRuntimeProcessDetails().Path,
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
						Value: *malwareResult.GetBasicRuntimeAlert().Size,
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
						Name:  "is_part_of_image",
						Value: fmt.Sprintf("%t", malwareResult.GetBasicRuntimeAlert().IsPartOfImage),
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
		Message: []byte(fmt.Sprintf("Malware '%s' detected in namespace '%s' pod '%s' description '%s' path '%s'", malwareResult.GetBasicRuntimeAlert().AlertName, malwareResult.GetTriggerEvent().GetBaseEvent().GetNamespace(), malwareResult.GetTriggerEvent().GetBaseEvent().GetPod(), malwareResult.GetMalwareRuntimeAlert().MalwareDescription, malwareResult.GetRuntimeProcessDetails().Path)),
	}

	_, err := message.WriteTo(se.writer)
	if err != nil {
		log.Errorf("failed to send alert to syslog: %v", err)
	}
}