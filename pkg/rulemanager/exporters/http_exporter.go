package exporters

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"node-agent/pkg/malwaremanager"
	"node-agent/pkg/ruleengine"
	ruleenginev1 "node-agent/pkg/ruleengine/v1"
	"sync"
	"time"

	"github.com/kubescape/go-logger"
	"github.com/kubescape/go-logger/helpers"
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
	Host       string
	NodeName   string
	config     HTTPExporterConfig
	httpClient *http.Client
	// alertCount is the number of alerts sent in the last minute, used to limit the number of alerts sent so we don't overload the system or reach the rate limit
	alertCount      int
	alertCountLock  sync.Mutex
	alertCountStart time.Time
}

type HTTPAlertsList struct {
	Kind       string             `json:"kind"`
	ApiVersion string             `json:"apiVersion"`
	Spec       HTTPAlertsListSpec `json:"spec"`
}

type HTTPAlertsListSpec struct {
	Alerts []HTTPAlert `json:"alerts"`
}

type RuleAlert struct {
	Severity       int    `json:"severity,omitempty"`    // PriorityToStatus(failedRule.Priority()),
	ProcessName    string `json:"processName,omitempty"` // failedRule.Event().Comm,
	FixSuggestions string `json:"fixSuggestions,omitempty"`
	PID            uint32 `json:"pid,omitempty"`
	PPID           uint32 `json:"ppid,omitempty"` //  Parent Process ID
	UID            uint32 `json:"uid,omitempty"`  // User ID of the process
	GID            uint32 `json:"gid,omitempty"`  // Group ID of the process
}

type MalwareAlert struct {
	MalwareName        string `json:"malwareName,omitempty"`
	MalwareDescription string `json:"malwareDescription,omitempty"`
	// Path to the file that was infected
	Path string `json:"path,omitempty"`
	// MD5 Hash of the file that was infected
	MD5Hash string `json:"md5hash,omitempty"`
	// SHA1 Hash of the file that was infected
	SHA1Hash string `json:"sha1hash,omitempty"`
	// SHA256 Hash of the file that was infected
	SHA256Hash string `json:"sha256hash,omitempty"`
	// Size of the file that was infected
	Size string `json:"size,omitempty"`
	// Is part of the image
	IsPartOfImage bool `json:"isPartOfImage,omitempty"`
	// K8s container image that was infected
	ContainerImage string `json:"containerImage,omitempty"`
	// K8s container image digest that was infected
	ContainerImageDigest string `json:"containerImageDigest,omitempty"`
}

type HTTPAlert struct {
	RuleAlert     `json:",inline"`
	MalwareAlert  `json:",inline"`
	RuleName      string `json:"ruleName"`
	RuleID        string `json:"ruleID"`
	Message       string `json:"message"`
	ContainerID   string `json:"containerID,omitempty"`
	ContainerName string `json:"containerName,omitempty"`
	PodNamespace  string `json:"podNamespace,omitempty"`
	PodName       string `json:"podName,omitempty"`
	HostName      string `json:"hostName"`
	NodeName      string `json:"nodeName"`
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
		config.MaxAlertsPerMinute = 10000
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
func InitHTTPExporter(config HTTPExporterConfig) (*HTTPExporter, error) {
	if err := config.Validate(); err != nil {
		return nil, err
	}

	return &HTTPExporter{
		config: config,
		httpClient: &http.Client{
			Timeout: time.Duration(config.TimeoutSeconds) * time.Second,
		},
	}, nil
}

func (exporter *HTTPExporter) sendAlertLimitReached() {
	httpAlert := HTTPAlert{
		Message:  "Alert limit reached",
		RuleName: "AlertLimitReached",
		HostName: exporter.Host,
		NodeName: exporter.NodeName,
		RuleAlert: RuleAlert{
			Severity:       ruleenginev1.RulePrioritySystemIssue,
			FixSuggestions: "Check logs for more information",
		},
	}
	logger.L().Error("Alert limit reached", helpers.Int("alerts", exporter.alertCount), helpers.String("since", exporter.alertCountStart.Format(time.RFC3339)))
	exporter.sendInAlertList(httpAlert)
}

func (exporter *HTTPExporter) SendRuleAlert(failedRule ruleengine.RuleFailure) {
	isLimitReached := exporter.checkAlertLimit()
	if isLimitReached {
		exporter.sendAlertLimitReached()
		return
	}
	// populate the HTTPAlert struct with the data from the failedRule
	httpAlert := HTTPAlert{
		Message:       failedRule.Error(),
		RuleName:      failedRule.Name(),
		RuleID:        failedRule.ID(),
		ContainerID:   failedRule.Event().ContainerID,
		ContainerName: failedRule.Event().ContainerName,
		PodNamespace:  failedRule.Event().Namespace,
		PodName:       failedRule.Event().PodName,
		HostName:      exporter.Host,
		NodeName:      exporter.NodeName,
		RuleAlert: RuleAlert{
			Severity:       failedRule.Priority(),
			FixSuggestions: failedRule.FixSuggestion(),
			PID:            failedRule.Event().Pid,
			PPID:           failedRule.Event().Ppid,
			ProcessName:    failedRule.Event().Comm,
			UID:            failedRule.Event().Uid,
			GID:            failedRule.Event().Gid,
		},
	}
	exporter.sendInAlertList(httpAlert)
}

func (exporter *HTTPExporter) sendInAlertList(httpAlert HTTPAlert) {
	// create the HTTPAlertsListSpec struct
	// TODO: accumulate alerts and send them in a batch
	httpAlertsListSpec := HTTPAlertsListSpec{
		Alerts: []HTTPAlert{httpAlert},
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
	req, err := http.NewRequest(exporter.config.Method, exporter.config.URL, bodyReader)
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
	if isLimitReached {
		exporter.sendAlertLimitReached()
		return
	}
	httpAlert := HTTPAlert{
		RuleName:      "KubescapeMalwareDetected",
		HostName:      exporter.Host,
		NodeName:      exporter.NodeName,
		ContainerID:   malwareResult.GetContainerID(),
		ContainerName: malwareResult.GetContainerName(),
		PodNamespace:  malwareResult.GetNamespace(),
		PodName:       malwareResult.GetPodName(),
		MalwareAlert: MalwareAlert{
			MalwareName:          malwareResult.GetMalwareName(),
			MalwareDescription:   malwareResult.GetDescription(),
			Path:                 malwareResult.GetPath(),
			MD5Hash:              malwareResult.GetMD5Hash(),
			SHA256Hash:           malwareResult.GetSHA256Hash(),
			SHA1Hash:             malwareResult.GetSHA1Hash(),
			Size:                 malwareResult.GetSize(),
			IsPartOfImage:        malwareResult.GetIsPartOfImage(),
			ContainerImage:       malwareResult.GetContainerImage(),
			ContainerImageDigest: malwareResult.GetContainerImageDigest(),
		},
	}
	exporter.sendInAlertList(httpAlert)
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
	}

	exporter.alertCount++
	return exporter.alertCount > exporter.config.MaxAlertsPerMinute
}
