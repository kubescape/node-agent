package exporters

import (
	"fmt"
	"log/syslog"
	"os"
	"time"

	"github.com/kubescape/node-agent/pkg/hosthashsensor"
	hostnetworksensor "github.com/kubescape/node-agent/pkg/hostnetworksensor/types"
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

func (se *SyslogExporter) SendFileHashAlerts(fileHashResults []hosthashsensor.FileHashResult) {
	for _, fileHashResult := range fileHashResults {
		message := rfc5424.Message{
			Priority:  rfc5424.Error,
			Timestamp: time.Now(),
			Hostname:  "kubecop",
			AppName:   "kubecop",
			Message:   []byte(fmt.Sprintf("File hash alert for file '%s' in namespace '%s' pod '%s' description '%s'", fileHashResult.GetBasicRuntimeAlert().AlertName, fileHashResult.GetTriggerEvent().GetBaseEvent().GetNamespace(), fileHashResult.GetTriggerEvent().GetBaseEvent().GetPod(), fileHashResult.GetMalwareRuntimeAlert().MalwareDescription)),
			StructuredData: []rfc5424.StructuredData{
				{
					ID: "filehash@48577",
					Parameters: []rfc5424.SDParam{
						{
							Name:  "file_name",
							Value: fileHashResult.GetBasicRuntimeAlert().AlertName,
						},
						{
							Name:  "md5hash",
							Value: fileHashResult.GetBasicRuntimeAlert().MD5Hash,
						},
						{
							Name:  "sha1hash",
							Value: fileHashResult.GetBasicRuntimeAlert().SHA1Hash,
						},
						{
							Name:  "sha256hash",
							Value: fileHashResult.GetBasicRuntimeAlert().SHA256Hash,
						},
						{
							Name:  "size",
							Value: fileHashResult.GetBasicRuntimeAlert().Size,
						},
						{
							Name:  "namespace",
							Value: fileHashResult.GetTriggerEvent().GetBaseEvent().GetNamespace(),
						},
						{
							Name:  "pod_name",
							Value: fileHashResult.GetTriggerEvent().GetBaseEvent().GetPod(),
						},
						{
							Name:  "container_name",
							Value: fileHashResult.GetTriggerEvent().GetBaseEvent().GetContainer(),
						},
						{
							Name:  "container_id",
							Value: fileHashResult.GetTriggerEvent().Runtime.ContainerID,
						},
						{
							Name:  "container_image",
							Value: fileHashResult.GetTriggerEvent().Runtime.ContainerImageName,
						},
						{
							Name:  "container_image_digest",
							Value: fileHashResult.GetTriggerEvent().Runtime.ContainerImageDigest,
						},
					},
				},
			},
		}

		_, err := message.WriteTo(se.writer)
		if err != nil {
			logger.L().Warning("SyslogExporter - failed to send alert to syslog", helpers.Error(err))
		}
	}
}

func (se *SyslogExporter) SendNetworkScanAlert(networkScanResult hostnetworksensor.NetworkScanResult) {
	message := rfc5424.Message{
		Priority:  rfc5424.Error,
		Timestamp: time.Now(),
		Hostname:  "kubecop",
		AppName:   "kubecop",
		Message:   []byte(fmt.Sprintf("Network scan alert for pod '%s' in namespace '%s' description '%s'", networkScanResult.GetBasicRuntimeAlert().AlertName, networkScanResult.GetTriggerEvent().GetBaseEvent().GetPod(), "Network scan alert")),
		StructuredData: []rfc5424.StructuredData{
			{
				ID: "networkscan@48577",
				Parameters: []rfc5424.SDParam{
					{
						Name:  "pod_name",
						Value: networkScanResult.GetTriggerEvent().GetBaseEvent().GetPod(),
					},
					{
						Name:  "namespace",
						Value: networkScanResult.GetTriggerEvent().GetBaseEvent().GetNamespace(),
					},
					{
						Name:  "container_name",
						Value: networkScanResult.GetTriggerEvent().GetBaseEvent().GetContainer(),
					},
					{
						Name:  "container_id",
						Value: networkScanResult.GetTriggerEvent().Runtime.ContainerID,
					},
					{
						Name:  "container_image",
						Value: networkScanResult.GetTriggerEvent().Runtime.ContainerImageName,
					},
					{
						Name:  "container_image_digest",
						Value: networkScanResult.GetTriggerEvent().Runtime.ContainerImageDigest,
					},
				},
			},
		},
	}

	_, err := message.WriteTo(se.writer)
	if err != nil {
		logger.L().Warning("SyslogExporter - failed to send alert to syslog", helpers.Error(err))
	}
}
