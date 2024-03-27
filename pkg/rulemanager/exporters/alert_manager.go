package exporters

// here we will have the functionality to export the alerts to the alert manager
// Path: pkg/exporters/alert_manager.go

import (
	"context"
	"fmt"
	"node-agent/pkg/malwarescanner"
	"node-agent/pkg/ruleengine"
	"os"
	"time"

	log "github.com/sirupsen/logrus"

	"github.com/go-openapi/strfmt"
	"github.com/prometheus/alertmanager/api/v2/client"
	"github.com/prometheus/alertmanager/api/v2/client/alert"
	"github.com/prometheus/alertmanager/api/v2/models"
)

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
		failedRule.Error(),
		failedRule.Name(),
		failedRule.ID(),
		failedRule.FixSuggestion(),
		failedRule.Event().Namespace,
		failedRule.Event().PodName,
		failedRule.Event().ContainerName,
		fmt.Sprintf("%s (%d)", failedRule.Event().Comm, failedRule.Event().Pid),
	)
	summary := fmt.Sprintf("Rule '%s' in '%s' namespace '%s' failed", failedRule.Name(), failedRule.Event().PodName, failedRule.Event().Namespace)
	myAlert := models.PostableAlert{
		StartsAt: strfmt.DateTime(time.Now()),
		EndsAt:   strfmt.DateTime(time.Now().Add(time.Hour)),
		Annotations: map[string]string{
			"title":       summary,
			"summary":     summary,
			"message":     failedRule.Error(),
			"description": failedRule.Error(),
			"fix":         failedRule.FixSuggestion(),
		},
		Alert: models.Alert{
			GeneratorURL: strfmt.URI(sourceUrl),
			Labels: map[string]string{
				"alertname":      "KubescapeRuleViolated",
				"rule_name":      failedRule.Name(),
				"rule_id":        failedRule.ID(),
				"container_id":   failedRule.Event().ContainerID,
				"container_name": failedRule.Event().ContainerName,
				"namespace":      failedRule.Event().Namespace,
				"pod_name":       failedRule.Event().PodName,
				"severity":       PriorityToStatus(failedRule.Priority()),
				"host":           ame.Host,
				"node_name":      ame.NodeName,
				"pid":            fmt.Sprintf("%d", failedRule.Event().Pid),
				"ppid":           fmt.Sprintf("%d", failedRule.Event().Ppid),
				"comm":           failedRule.Event().Comm,
				"uid":            fmt.Sprintf("%d", failedRule.Event().Uid),
				"gid":            fmt.Sprintf("%d", failedRule.Event().Gid),
			},
		},
	}

	// Send the alert
	params := alert.NewPostAlertsParams().WithContext(context.Background()).WithAlerts(models.PostableAlerts{&myAlert})
	isOK, err := ame.client.Alert.PostAlerts(params)
	if err != nil {
		log.Errorf("Error sending alert: %v\n", err)
		return
	}
	if isOK == nil {
		log.Errorln("Alert was not sent successfully")
		return
	}
}

func (ame *AlertManagerExporter) SendMalwareAlert(malwareDescription malwarescanner.MalwareDescription) {
	summary := fmt.Sprintf("Malware '%s' detected in namespace '%s' pod '%s' description '%s' path '%s'", malwareDescription.Name, malwareDescription.Namespace, malwareDescription.PodName, malwareDescription.Description, malwareDescription.Path)
	myAlert := models.PostableAlert{
		StartsAt: strfmt.DateTime(time.Now()),
		EndsAt:   strfmt.DateTime(time.Now().Add(time.Hour)),
		Annotations: map[string]string{
			"title":       malwareDescription.Name,
			"summary":     summary,
			"message":     summary,
			"description": malwareDescription.Description,
			"fix":         "Remove the malware from the container",
		},
		Alert: models.Alert{
			GeneratorURL: strfmt.URI("https://armosec.github.io/kubecop/alertviewer/"),
			Labels: map[string]string{
				"alertname":        "KubescapeMalwareDetected",
				"malware_name":     malwareDescription.Name,
				"container_id":     malwareDescription.ContainerID,
				"container_name":   malwareDescription.ContainerName,
				"namespace":        malwareDescription.Namespace,
				"pod_name":         malwareDescription.PodName,
				"size":             malwareDescription.Size,
				"hash":             malwareDescription.Hash,
				"is_part_of_image": fmt.Sprintf("%t", malwareDescription.IsPartOfImage),
				"container_image":  malwareDescription.ContainerImage,
				"severity":         "critical",
				"host":             ame.Host,
				"node_name":        ame.NodeName,
			},
		},
	}

	// Send the alert
	params := alert.NewPostAlertsParams().WithContext(context.Background()).WithAlerts(models.PostableAlerts{&myAlert})
	isOK, err := ame.client.Alert.PostAlerts(params)
	if err != nil {
		log.Errorf("Error sending alert: %v\n", err)
		return
	}
	if isOK == nil {
		log.Errorln("Alert was not sent successfully")
		return
	}
}
