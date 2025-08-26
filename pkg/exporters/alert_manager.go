package exporters

// here we will have the functionality to export the alerts to the alert manager
// Path: pkg/exporters/alert_manager.go

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"time"

	apitypes "github.com/armosec/armoapi-go/armotypes"
	"github.com/go-openapi/strfmt"
	"github.com/kubescape/go-logger"
	"github.com/kubescape/go-logger/helpers"
	"github.com/kubescape/node-agent/pkg/hostfimsensor"
	"github.com/kubescape/node-agent/pkg/malwaremanager"
	"github.com/kubescape/node-agent/pkg/ruleengine"
	"github.com/kubescape/node-agent/pkg/utils"
	"github.com/prometheus/alertmanager/api/v2/client"
	"github.com/prometheus/alertmanager/api/v2/client/alert"
	"github.com/prometheus/alertmanager/api/v2/models"
)

// TODO: Add missing fields.

type AlertManagerExporter struct {
	Host     string
	NodeName string
	client   *client.AlertmanagerAPI
}

func InitAlertManagerExporter(alertManagerURL string) *AlertManagerExporter {
	// Create a new alertManager client
	cfg := client.DefaultTransportConfig().WithHost(alertManagerURL)
	amClient := client.NewHTTPClientWithConfig(nil, cfg)
	hostName, err := os.Hostname()
	if err != nil {
		panic(fmt.Sprintf("failed to get hostname: %v", err))
	}

	return &AlertManagerExporter{
		client:   amClient,
		Host:     hostName,
		NodeName: os.Getenv("NODE_NAME"),
	}
}

func (ame *AlertManagerExporter) SendRuleAlert(failedRule ruleengine.RuleFailure) {
	profileMetadata := failedRule.GetBaseRuntimeAlert().ProfileMetadata
	failOnProfile := false
	completedStatus := ""
	if profileMetadata != nil {
		failOnProfile = profileMetadata.FailOnProfile
		completedStatus = profileMetadata.Status
	}

	trace, err := traceToString(failedRule.GetBaseRuntimeAlert().Trace)
	if err != nil {
		logger.L().Debug("AlertManagerExporter.SendRuleAlert - converting trace to string", helpers.Error(err), helpers.Interface("trace", failedRule.GetBaseRuntimeAlert().Trace))
		trace = ""
	}

	processTree := failedRule.GetRuntimeProcessDetails().ProcessTree
	process := utils.GetProcessFromProcessTree(&processTree, failedRule.GetBaseRuntimeAlert().InfectedPID)
	if process == nil {
		logger.L().Warning("AlertManagerExporter.SendRuleAlert - failed to get process from process tree", helpers.String("trace", trace), helpers.Int("pid", int(failedRule.GetBaseRuntimeAlert().InfectedPID)))
		return
	}
	sourceUrl := fmt.Sprintf("https://armosec.github.io/kubecop/alertviewer/?AlertMessage=%s&AlertRuleName=%s&AlertRuleID=%s&AlertFix=%s&AlertNamespace=%s&AlertPod=%s&AlertContainer=%s&AlertProcess=%s",
		failedRule.GetRuleAlert().RuleDescription,
		failedRule.GetBaseRuntimeAlert().AlertName,
		failedRule.GetRuleId(),
		failedRule.GetBaseRuntimeAlert().FixSuggestions,
		failedRule.GetRuntimeAlertK8sDetails().Namespace,
		failedRule.GetRuntimeAlertK8sDetails().PodName,
		failedRule.GetRuntimeAlertK8sDetails().ContainerName,
		fmt.Sprintf("%s (%d)", process.Comm, process.PID),
	)
	summary := fmt.Sprintf("Rule '%s' in '%s' namespace '%s' failed", failedRule.GetBaseRuntimeAlert().AlertName, failedRule.GetRuntimeAlertK8sDetails().PodName, failedRule.GetRuntimeAlertK8sDetails().Namespace)
	myAlert := models.PostableAlert{
		StartsAt: strfmt.DateTime(time.Now()),
		EndsAt:   strfmt.DateTime(time.Now().Add(time.Hour)),
		Annotations: map[string]string{
			"title":       summary,
			"summary":     summary,
			"message":     failedRule.GetRuleAlert().RuleDescription,
			"description": failedRule.GetRuleAlert().RuleDescription,
			"fix":         failedRule.GetBaseRuntimeAlert().FixSuggestions,
		},
		Alert: models.Alert{
			GeneratorURL: strfmt.URI(sourceUrl),
			Labels: map[string]string{
				"alertname":         "KubescapeRuleViolated",
				"rule_name":         failedRule.GetBaseRuntimeAlert().AlertName,
				"rule_id":           failedRule.GetRuleId(),
				"container_id":      failedRule.GetRuntimeAlertK8sDetails().ContainerID,
				"container_name":    failedRule.GetRuntimeAlertK8sDetails().ContainerName,
				"namespace":         failedRule.GetRuntimeAlertK8sDetails().Namespace,
				"pod_name":          failedRule.GetRuntimeAlertK8sDetails().PodName,
				"severity":          PriorityToStatus(failedRule.GetBaseRuntimeAlert().Severity),
				"host":              ame.Host,
				"node_name":         ame.NodeName,
				"pid":               fmt.Sprintf("%d", process.PID),
				"ppid":              fmt.Sprintf("%d", process.PPID),
				"pcomm":             process.Pcomm,
				"comm":              process.Comm,
				"uid":               fmt.Sprintf("%d", process.Uid),
				"gid":               fmt.Sprintf("%d", process.Gid),
				"trace":             trace,
				"fail_on_profile":   fmt.Sprintf("%t", failOnProfile),
				"profile_status":    completedStatus,
				"processtree_depth": fmt.Sprintf("%d", utils.CalculateProcessTreeDepth(&processTree)),
			},
		},
	}

	// Send the alert
	params := alert.NewPostAlertsParams().WithContext(context.Background()).WithAlerts(models.PostableAlerts{&myAlert})
	isOK, err := ame.client.Alert.PostAlerts(params)
	if err != nil {
		logger.L().Warning("AlertManagerExporter.SendRuleAlert - error sending alert", helpers.Error(err))
		return
	}
	if isOK == nil {
		logger.L().Warning("AlertManagerExporter.SendRuleAlert - alert was not sent successfully")
		return
	}
}

func (ame *AlertManagerExporter) SendMalwareAlert(malwareResult malwaremanager.MalwareResult) {
	summary := fmt.Sprintf("Malware '%s' detected in namespace '%s' pod '%s' description '%s'", malwareResult.GetBasicRuntimeAlert().AlertName, malwareResult.GetTriggerEvent().GetBaseEvent().GetNamespace(), malwareResult.GetTriggerEvent().GetBaseEvent().GetPod(), malwareResult.GetMalwareRuntimeAlert().MalwareDescription)
	myAlert := models.PostableAlert{
		StartsAt: strfmt.DateTime(time.Now()),
		EndsAt:   strfmt.DateTime(time.Now().Add(time.Hour)),
		Annotations: map[string]string{
			"title":       malwareResult.GetBasicRuntimeAlert().AlertName,
			"summary":     summary,
			"message":     summary,
			"description": malwareResult.GetMalwareRuntimeAlert().MalwareDescription,
			"fix":         "Remove the malware from the container",
		},
		Alert: models.Alert{
			GeneratorURL: strfmt.URI("https://armosec.github.io/kubecop/alertviewer/"),
			Labels: map[string]string{
				"alertname":              "KubescapeMalwareDetected",
				"malware_name":           malwareResult.GetBasicRuntimeAlert().AlertName,
				"container_id":           malwareResult.GetTriggerEvent().Runtime.ContainerID,
				"container_name":         malwareResult.GetTriggerEvent().GetBaseEvent().GetContainer(),
				"namespace":              malwareResult.GetTriggerEvent().GetBaseEvent().GetNamespace(),
				"pod_name":               malwareResult.GetTriggerEvent().GetBaseEvent().GetPod(),
				"size":                   malwareResult.GetBasicRuntimeAlert().Size,
				"md5hash":                malwareResult.GetBasicRuntimeAlert().MD5Hash,
				"sha256hash":             malwareResult.GetBasicRuntimeAlert().SHA256Hash,
				"sha1hash":               malwareResult.GetBasicRuntimeAlert().SHA1Hash,
				"container_image":        malwareResult.GetTriggerEvent().Runtime.ContainerImageName,
				"container_image_digest": malwareResult.GetTriggerEvent().Runtime.ContainerImageDigest,
				"severity":               "critical",
				"host":                   ame.Host,
				"node_name":              ame.NodeName,
			},
		},
	}

	// Send the alert
	params := alert.NewPostAlertsParams().WithContext(context.Background()).WithAlerts(models.PostableAlerts{&myAlert})
	isOK, err := ame.client.Alert.PostAlerts(params)
	if err != nil {
		logger.L().Warning("AlertManagerExporter.SendMalwareAlert - error sending alert", helpers.Error(err))
		return
	}
	if isOK == nil {
		logger.L().Warning("AlertManagerExporter.SendMalwareAlert - alert was not sent successfully")
		return
	}
}

func (ame *AlertManagerExporter) SendFimAlerts(fimEvents []hostfimsensor.FimEvent) {
	// TODO: Implement FIM alerts sending logic
	logger.L().Debug("AlertManagerExporter.SendFimAlerts - stub implementation", helpers.Int("events", len(fimEvents)))
}

func traceToString(t apitypes.Trace) (string, error) {
	bytes, err := json.Marshal(t)
	if err != nil {
		return "", fmt.Errorf("error marshaling trace: %v", err)
	}
	return string(bytes), nil
}
