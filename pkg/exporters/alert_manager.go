package exporters

// here we will have the functionality to export the alerts to the alert manager
// Path: pkg/exporters/alert_manager.go

import (
	"context"
	"fmt"
	"node-agent/pkg/malwaremanager"
	"node-agent/pkg/ruleengine"
	"os"
	"time"

	logger "github.com/kubescape/go-logger"
	"github.com/kubescape/go-logger/helpers"

	"github.com/go-openapi/strfmt"
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
	sourceUrl := fmt.Sprintf("https://armosec.github.io/kubecop/alertviewer/?AlertMessage=%s&AlertRuleName=%s&AlertRuleID=%s&AlertFix=%s&AlertNamespace=%s&AlertPod=%s&AlertContainer=%s&AlertProcess=%s",
		failedRule.GetRuleAlert().RuleDescription,
		failedRule.GetBaseRuntimeAlert().AlertName,
		failedRule.GetRuleAlert().RuleID,
		failedRule.GetBaseRuntimeAlert().FixSuggestions,
		failedRule.GetRuntimeAlertK8sDetails().Namespace,
		failedRule.GetRuntimeAlertK8sDetails().PodName,
		failedRule.GetRuntimeAlertK8sDetails().ContainerName,
		fmt.Sprintf("%s (%d)", failedRule.GetRuntimeProcessDetails().ProcessTree.Comm, failedRule.GetRuntimeProcessDetails().ProcessTree.PID),
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
				"alertname":      "KubescapeRuleViolated",
				"rule_name":      failedRule.GetBaseRuntimeAlert().AlertName,
				"rule_id":        failedRule.GetRuleAlert().RuleID,
				"container_id":   failedRule.GetRuntimeAlertK8sDetails().ContainerID,
				"container_name": failedRule.GetRuntimeAlertK8sDetails().ContainerName,
				"namespace":      failedRule.GetRuntimeAlertK8sDetails().Namespace,
				"pod_name":       failedRule.GetRuntimeAlertK8sDetails().PodName,
				"severity":       PriorityToStatus(failedRule.GetBaseRuntimeAlert().Severity),
				"host":           ame.Host,
				"node_name":      ame.NodeName,
				"pid":            fmt.Sprintf("%d", failedRule.GetRuntimeProcessDetails().ProcessTree.PID),
				"ppid":           fmt.Sprintf("%d", failedRule.GetRuntimeProcessDetails().ProcessTree.PPID),
				"pcomm":          failedRule.GetRuntimeProcessDetails().ProcessTree.Pcomm,
				"comm":           failedRule.GetRuntimeProcessDetails().ProcessTree.Comm,
				"uid":            fmt.Sprintf("%d", failedRule.GetRuntimeProcessDetails().ProcessTree.Uid),
				"gid":            fmt.Sprintf("%d", failedRule.GetRuntimeProcessDetails().ProcessTree.Gid),
			},
		},
	}

	// Send the alert
	params := alert.NewPostAlertsParams().WithContext(context.Background()).WithAlerts(models.PostableAlerts{&myAlert})
	isOK, err := ame.client.Alert.PostAlerts(params)
	if err != nil {
		logger.L().Error("Error sending alert", helpers.Error(err))
		return
	}
	if isOK == nil {
		logger.L().Error("Alert was not sent successfully")
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
				"size":                   *malwareResult.GetBasicRuntimeAlert().Size,
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
		logger.L().Error("Error sending alert", helpers.Error(err))
		return
	}
	if isOK == nil {
		logger.L().Error("Alert was not sent successfully")
		return
	}
}
