package exporters

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"sync"
	"time"

	"github.com/kubescape/node-agent/pkg/malwaremanager"
	"github.com/kubescape/node-agent/pkg/ruleengine"
	ruleenginev1 "github.com/kubescape/node-agent/pkg/ruleengine/v1"

	"github.com/kubescape/go-logger"
	"github.com/kubescape/go-logger/helpers"

	apitypes "github.com/armosec/armoapi-go/armotypes"
)

type HTTPExporterConfig struct {
	// URL is the URL to send the HTTP request to
	URL string `json:"url"`
	// Headers is a map of headers to send in the HTTP request
	Headers map[string]string `json:"headers"`
	// Timeout is the timeout for the HTTP request
	TimeoutSeconds int `json:"timeoutSeconds"`
	// Method is the HTTP method to use for the HTTP request
	Method             string `json:"method"`
	MaxAlertsPerMinute int    `json:"maxAlertsPerMinute"`
}

// we will have a CRD-like json struct to send in the HTTP request
type HTTPExporter struct {
	config      HTTPExporterConfig
	Host        string `json:"host"`
	NodeName    string `json:"nodeName"`
	ClusterName string `json:"clusterName"`
	httpClient  *http.Client
	// alertCount is the number of alerts sent in the last minute, used to limit the number of alerts sent, so we don't overload the system or reach the rate limit
	alertCount         int
	alertCountLock     sync.Mutex
	alertCountStart    time.Time
	alertLimitNotified bool
	cloudMetadata      *apitypes.CloudMetadata
}

type HTTPAlertsList struct {
	Kind       string             `json:"kind"`
	ApiVersion string             `json:"apiVersion"`
	Spec       HTTPAlertsListSpec `json:"spec"`
}

type HTTPAlertsListSpec struct {
	Alerts        []apitypes.RuntimeAlert `json:"alerts"`
	ProcessTree   apitypes.ProcessTree    `json:"processTree"`
	CloudMetadata apitypes.CloudMetadata  `json:"cloudMetadata"`
}

func (config *HTTPExporterConfig) Validate() error {
	if config.Method == "" {
		config.Method = "POST"
	} else if config.Method != "POST" && config.Method != "PUT" {
		return fmt.Errorf("method must be POST or PUT")
	}
	if config.TimeoutSeconds == 0 {
		config.TimeoutSeconds = 5
	}
	if config.MaxAlertsPerMinute == 0 {
		config.MaxAlertsPerMinute = 100
	}
	if config.Headers == nil {
		config.Headers = make(map[string]string)
	}
	if config.URL == "" {
		return fmt.Errorf("URL is required")
	}
	return nil
}

// InitHTTPExporter initializes an HTTPExporter with the given URL, headers, timeout, and method
func InitHTTPExporter(config HTTPExporterConfig, clusterName string, nodeName string, cloudMetadata *apitypes.CloudMetadata) (*HTTPExporter, error) {
	if err := config.Validate(); err != nil {
		return nil, err
	}

	return &HTTPExporter{
		ClusterName: clusterName,
		NodeName:    nodeName,
		config:      config,
		httpClient: &http.Client{
			Timeout: time.Duration(config.TimeoutSeconds) * time.Second,
		},
		cloudMetadata: cloudMetadata,
	}, nil
}

func (exporter *HTTPExporter) sendAlertLimitReached() {
	httpAlert := apitypes.RuntimeAlert{
		Message:   "Alert limit reached",
		HostName:  exporter.Host,
		AlertType: apitypes.AlertTypeRule, // TODO: change this to a new alert type. @bez
		BaseRuntimeAlert: apitypes.BaseRuntimeAlert{
			AlertName:      "AlertLimitReached",
			Severity:       ruleenginev1.RulePrioritySystemIssue,
			FixSuggestions: "Check logs for more information",
		},
		RuntimeAlertK8sDetails: apitypes.RuntimeAlertK8sDetails{
			NodeName:    exporter.NodeName,
			ClusterName: exporter.ClusterName,
		},
	}

	logger.L().Error("Alert limit reached", helpers.Int("alerts", exporter.alertCount), helpers.String("since", exporter.alertCountStart.Format(time.RFC3339)))
	exporter.sendInAlertList(httpAlert, apitypes.ProcessTree{})
}

func (exporter *HTTPExporter) SendRuleAlert(failedRule ruleengine.RuleFailure) {
	isLimitReached := exporter.checkAlertLimit()
	if isLimitReached && !exporter.alertLimitNotified {
		exporter.sendAlertLimitReached()
		exporter.alertLimitNotified = true
		return
	}

	// populate the RuntimeAlert struct with the data from the failedRule
	k8sDetails := failedRule.GetRuntimeAlertK8sDetails()
	k8sDetails.NodeName = exporter.NodeName
	k8sDetails.ClusterName = exporter.ClusterName

	httpAlert := apitypes.RuntimeAlert{
		Message:                failedRule.GetRuleAlert().RuleDescription,
		HostName:               exporter.Host,
		AlertType:              apitypes.AlertTypeRule,
		BaseRuntimeAlert:       failedRule.GetBaseRuntimeAlert(),
		RuntimeAlertK8sDetails: k8sDetails,
		RuleAlert:              failedRule.GetRuleAlert(),
		RuleID:                 failedRule.GetRuleId(),
	}
	exporter.sendInAlertList(httpAlert, failedRule.GetRuntimeProcessDetails())
}

func (exporter *HTTPExporter) sendInAlertList(httpAlert apitypes.RuntimeAlert, processTree apitypes.ProcessTree) {
	// create the HTTPAlertsListSpec struct
	// TODO: accumulate alerts and send them in a batch
	var cloudMetadata apitypes.CloudMetadata
	if exporter.cloudMetadata == nil {
		cloudMetadata = apitypes.CloudMetadata{}
	} else {
		cloudMetadata = *exporter.cloudMetadata
	}

	httpAlertsListSpec := HTTPAlertsListSpec{
		Alerts:        []apitypes.RuntimeAlert{httpAlert},
		ProcessTree:   processTree,
		CloudMetadata: cloudMetadata,
	}
	// create the HTTPAlertsList struct
	httpAlertsList := HTTPAlertsList{
		Kind:       "RuntimeAlerts",
		ApiVersion: "kubescape.io/v1",
		Spec:       httpAlertsListSpec,
	}

	// create the JSON representation of the HTTPAlertsList struct
	bodyBytes, err := json.Marshal(httpAlertsList)
	if err != nil {
		logger.L().Error("failed to marshal HTTPAlertsList", helpers.Error(err))
		return
	}
	bodyReader := bytes.NewReader(bodyBytes)

	// send the HTTP request
	req, err := http.NewRequest(exporter.config.Method,
		exporter.config.URL+"/v1/runtimealerts", bodyReader)
	if err != nil {
		logger.L().Error("failed to create HTTP request", helpers.Error(err))
		return
	}
	for key, value := range exporter.config.Headers {
		req.Header.Set(key, value)
	}

	resp, err := exporter.httpClient.Do(req)
	if err != nil {
		logger.L().Error("failed to send HTTP request", helpers.Error(err))
		return
	}
	defer resp.Body.Close()

	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		logger.L().Error("Received non-2xx status code", helpers.Int("status", resp.StatusCode))
		return
	}

	// discard the body
	if _, err := io.Copy(io.Discard, resp.Body); err != nil {
		logger.L().Error("failed to clear response body", helpers.Error(err))
	}
}

func (exporter *HTTPExporter) SendMalwareAlert(malwareResult malwaremanager.MalwareResult) {
	isLimitReached := exporter.checkAlertLimit()
	if isLimitReached && !exporter.alertLimitNotified {
		exporter.sendAlertLimitReached()
		exporter.alertLimitNotified = true
		return
	}

	k8sDetails := malwareResult.GetRuntimeAlertK8sDetails()
	k8sDetails.NodeName = exporter.NodeName
	k8sDetails.ClusterName = exporter.ClusterName

	httpAlert := apitypes.RuntimeAlert{
		Message:                fmt.Sprintf("Malware detected: %s", malwareResult.GetBasicRuntimeAlert().AlertName),
		HostName:               exporter.Host,
		AlertType:              apitypes.AlertTypeMalware,
		BaseRuntimeAlert:       malwareResult.GetBasicRuntimeAlert(),
		RuntimeAlertK8sDetails: k8sDetails,
		MalwareAlert:           malwareResult.GetMalwareRuntimeAlert(),
		RuleID:                 "R3000", // Hardcoded rule ID for malware alerts.
	}
	exporter.sendInAlertList(httpAlert, malwareResult.GetRuntimeProcessDetails())
}

func (exporter *HTTPExporter) checkAlertLimit() bool {
	exporter.alertCountLock.Lock()
	defer exporter.alertCountLock.Unlock()

	if exporter.alertCountStart.IsZero() {
		exporter.alertCountStart = time.Now()
	}

	if time.Since(exporter.alertCountStart) > time.Minute {
		exporter.alertCountStart = time.Now()
		exporter.alertCount = 0
		exporter.alertLimitNotified = false
	}

	exporter.alertCount++
	return exporter.alertCount > exporter.config.MaxAlertsPerMinute
}
