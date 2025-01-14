package exporters

import (
	"bytes"
	"context"
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

const (
	defaultTimeout         = 5 * time.Second
	defaultMaxAlertsPerMin = 100
	defaultMethod          = "POST"
	alertsEndpoint         = "/v1/runtimealerts"
	malwareRuleID          = "R3000"
	apiVersion             = "kubescape.io/v1"
	runtimeAlertsKind      = "RuntimeAlerts"
)

type AlertType string

const (
	AlertTypeLimitReached AlertType = "AlertLimitReached"
)

type HTTPExporterConfig struct {
	URL                string            `json:"url"`
	Headers            map[string]string `json:"headers"`
	TimeoutSeconds     int               `json:"timeoutSeconds"`
	Method             string            `json:"method"`
	MaxAlertsPerMinute int               `json:"maxAlertsPerMinute"`
}

type HTTPExporter struct {
	config        HTTPExporterConfig
	host          string
	nodeName      string
	clusterName   string
	httpClient    *http.Client
	alertMetrics  *alertMetrics
	cloudMetadata *apitypes.CloudMetadata
}

type alertMetrics struct {
	sync.Mutex
	count      int
	startTime  time.Time
	isNotified bool
}

type HTTPAlertsList struct {
	Kind       string             `json:"kind"`
	APIVersion string             `json:"apiVersion"`
	Spec       HTTPAlertsListSpec `json:"spec"`
}

type HTTPAlertsListSpec struct {
	Alerts        []apitypes.RuntimeAlert `json:"alerts"`
	ProcessTree   apitypes.ProcessTree    `json:"processTree"`
	CloudMetadata apitypes.CloudMetadata  `json:"cloudMetadata"`
}

// NewHTTPExporter creates a new HTTPExporter instance
func NewHTTPExporter(config HTTPExporterConfig, clusterName, nodeName string, cloudMetadata *apitypes.CloudMetadata) (*HTTPExporter, error) {
	if err := config.validate(); err != nil {
		return nil, fmt.Errorf("invalid config: %w", err)
	}

	return &HTTPExporter{
		config:      config,
		nodeName:    nodeName,
		clusterName: clusterName,
		httpClient: &http.Client{
			Timeout: time.Duration(config.TimeoutSeconds) * time.Second,
		},
		alertMetrics:  &alertMetrics{},
		cloudMetadata: cloudMetadata,
	}, nil
}

func (config *HTTPExporterConfig) validate() error {
	if config.URL == "" {
		return fmt.Errorf("URL is required")
	}

	if config.Method == "" {
		config.Method = defaultMethod
	} else if config.Method != "POST" && config.Method != "PUT" {
		return fmt.Errorf("method must be POST or PUT")
	}

	if config.TimeoutSeconds == 0 {
		config.TimeoutSeconds = int(defaultTimeout.Seconds())
	}

	if config.MaxAlertsPerMinute == 0 {
		config.MaxAlertsPerMinute = defaultMaxAlertsPerMin
	}

	if config.Headers == nil {
		config.Headers = make(map[string]string)
	}

	return nil
}

// SendRuleAlert implements the Exporter interface
func (e *HTTPExporter) SendRuleAlert(failedRule ruleengine.RuleFailure) {
	ctx, cancel := context.WithTimeout(context.Background(), time.Duration(e.config.TimeoutSeconds)*time.Second)
	defer cancel()

	if err := e.sendRuleAlertWithContext(ctx, failedRule); err != nil {
		logger.L().Warning("HTTPExporter.SendRuleAlert - failed to send rule alert", helpers.Error(err))
	}
}

// SendMalwareAlert implements the Exporter interface
func (e *HTTPExporter) SendMalwareAlert(malwareResult malwaremanager.MalwareResult) {
	ctx, cancel := context.WithTimeout(context.Background(), time.Duration(e.config.TimeoutSeconds)*time.Second)
	defer cancel()

	if err := e.sendMalwareAlertWithContext(ctx, malwareResult); err != nil {
		logger.L().Warning("HTTPExporter.SendRuleAlert - failed to send malware alert", helpers.Error(err))
	}
}

// Internal methods with context support
func (e *HTTPExporter) sendRuleAlertWithContext(ctx context.Context, failedRule ruleengine.RuleFailure) error {
	if e.shouldSendLimitAlert() {
		return e.sendAlertLimitReached(ctx)
	}

	alert := e.createRuleAlert(failedRule)
	return e.sendAlert(ctx, alert, failedRule.GetRuntimeProcessDetails(), failedRule.GetCloudServices())
}

func (e *HTTPExporter) sendMalwareAlertWithContext(ctx context.Context, result malwaremanager.MalwareResult) error {
	if e.shouldSendLimitAlert() {
		return e.sendAlertLimitReached(ctx)
	}

	alert := e.createMalwareAlert(result)
	return e.sendAlert(ctx, alert, result.GetRuntimeProcessDetails(), nil)
}

func (e *HTTPExporter) createRuleAlert(failedRule ruleengine.RuleFailure) apitypes.RuntimeAlert {
	k8sDetails := failedRule.GetRuntimeAlertK8sDetails()
	k8sDetails.NodeName = e.nodeName
	k8sDetails.ClusterName = e.clusterName

	return apitypes.RuntimeAlert{
		Message:                failedRule.GetRuleAlert().RuleDescription,
		HostName:               e.host,
		AlertType:              apitypes.AlertTypeRule,
		BaseRuntimeAlert:       failedRule.GetBaseRuntimeAlert(),
		RuntimeAlertK8sDetails: k8sDetails,
		RuleAlert:              failedRule.GetRuleAlert(),
		RuleID:                 failedRule.GetRuleId(),
	}
}

func (e *HTTPExporter) createMalwareAlert(result malwaremanager.MalwareResult) apitypes.RuntimeAlert {
	k8sDetails := result.GetRuntimeAlertK8sDetails()
	k8sDetails.NodeName = e.nodeName
	k8sDetails.ClusterName = e.clusterName

	return apitypes.RuntimeAlert{
		Message:                fmt.Sprintf("Malware detected: %s", result.GetBasicRuntimeAlert().AlertName),
		HostName:               e.host,
		AlertType:              apitypes.AlertTypeMalware,
		BaseRuntimeAlert:       result.GetBasicRuntimeAlert(),
		RuntimeAlertK8sDetails: k8sDetails,
		MalwareAlert:           result.GetMalwareRuntimeAlert(),
		RuleID:                 malwareRuleID,
	}
}

func (e *HTTPExporter) sendAlert(ctx context.Context, alert apitypes.RuntimeAlert, processTree apitypes.ProcessTree, cloudServices []string) error {
	payload := e.createAlertPayload(alert, processTree, cloudServices)
	return e.sendHTTPRequest(ctx, payload)
}

func (e *HTTPExporter) createAlertPayload(alert apitypes.RuntimeAlert, processTree apitypes.ProcessTree, cloudServices []string) HTTPAlertsList {
	cloudMetadata := e.getCloudMetadata(cloudServices)

	return HTTPAlertsList{
		Kind:       runtimeAlertsKind,
		APIVersion: apiVersion,
		Spec: HTTPAlertsListSpec{
			Alerts:        []apitypes.RuntimeAlert{alert},
			ProcessTree:   processTree,
			CloudMetadata: cloudMetadata,
		},
	}
}

func (e *HTTPExporter) getCloudMetadata(cloudServices []string) apitypes.CloudMetadata {
	if e.cloudMetadata == nil {
		return apitypes.CloudMetadata{}
	}

	metadata := *e.cloudMetadata
	metadata.Services = cloudServices
	return metadata
}

func (e *HTTPExporter) sendHTTPRequest(ctx context.Context, payload HTTPAlertsList) error {
	body, err := json.Marshal(payload)
	if err != nil {
		return fmt.Errorf("failed to marshal payload: %w", err)
	}

	req, err := http.NewRequestWithContext(ctx,
		e.config.Method,
		e.config.URL+alertsEndpoint,
		bytes.NewReader(body))
	if err != nil {
		return fmt.Errorf("failed to create request: %w", err)
	}

	for key, value := range e.config.Headers {
		req.Header.Set(key, value)
	}

	resp, err := e.httpClient.Do(req)
	if err != nil {
		return fmt.Errorf("failed to send request: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return fmt.Errorf("received non-2xx status code: %d", resp.StatusCode)
	}

	if _, err := io.Copy(io.Discard, resp.Body); err != nil {
		logger.L().Debug("HTTPExporter.sendHTTPRequest - failed to drain response body", helpers.Error(err))
	}

	return nil
}

func (e *HTTPExporter) shouldSendLimitAlert() bool {
	e.alertMetrics.Lock()
	defer e.alertMetrics.Unlock()

	if e.alertMetrics.startTime.IsZero() {
		e.alertMetrics.startTime = time.Now()
	}

	if time.Since(e.alertMetrics.startTime) > time.Minute {
		e.resetAlertMetrics()
		return false
	}

	e.alertMetrics.count++
	return e.alertMetrics.count > e.config.MaxAlertsPerMinute && !e.alertMetrics.isNotified
}

func (e *HTTPExporter) resetAlertMetrics() {
	e.alertMetrics.startTime = time.Now()
	e.alertMetrics.count = 0
	e.alertMetrics.isNotified = false
}

func (e *HTTPExporter) sendAlertLimitReached(ctx context.Context) error {
	e.alertMetrics.Lock()
	e.alertMetrics.isNotified = true
	e.alertMetrics.Unlock()

	alert := apitypes.RuntimeAlert{
		Message:   "Alert limit reached",
		HostName:  e.host,
		AlertType: apitypes.AlertTypeRule,
		BaseRuntimeAlert: apitypes.BaseRuntimeAlert{
			AlertName:      string(AlertTypeLimitReached),
			Severity:       ruleenginev1.RulePrioritySystemIssue,
			FixSuggestions: "Check logs for more information",
		},
		RuntimeAlertK8sDetails: apitypes.RuntimeAlertK8sDetails{
			NodeName:    e.nodeName,
			ClusterName: e.clusterName,
		},
	}

	logger.L().Warning("Alert limit reached",
		helpers.Int("alerts", e.alertMetrics.count),
		helpers.String("since", e.alertMetrics.startTime.Format(time.RFC3339)))

	return e.sendAlert(ctx, alert, apitypes.ProcessTree{}, nil)
}
