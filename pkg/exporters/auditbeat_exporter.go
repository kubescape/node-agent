package exporters

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/kubescape/node-agent/pkg/auditmanager"
	"github.com/kubescape/node-agent/pkg/malwaremanager"
	"github.com/kubescape/node-agent/pkg/ruleengine"

	"github.com/kubescape/go-logger"
	"github.com/kubescape/go-logger/helpers"

	apitypes "github.com/armosec/armoapi-go/armotypes"
)

const (
	defaultAuditbeatTimeout         = 5 * time.Second
	defaultAuditbeatMaxEventsPerMin = 1000
	defaultAuditbeatMethod          = "POST"
	defaultAuditbeatBatchSize       = 10
	auditbeatEndpoint               = "/auditbeat/events"
	uidUnset                        = "unset"
)

// AuditbeatEvent represents a metricbeat-compatible event structure
// This mimics the mb.Event structure from metricbeat
type AuditbeatEvent struct {
	timestamp    time.Time              `json:"-"`
	rootFields   map[string]interface{} `json:"-"`
	moduleFields map[string]interface{} `json:"-"`
	error        error                  `json:"-"`
}

// MarshalJSON customizes JSON marshaling to merge rootFields and moduleFields
func (e *AuditbeatEvent) MarshalJSON() ([]byte, error) {
	// Create a map to hold all fields
	result := make(map[string]interface{})

	// Add timestamp
	result["@timestamp"] = e.timestamp

	// Add root fields
	for k, v := range e.rootFields {
		result[k] = v
	}

	// Add module fields with "auditd" prefix to match metricbeat structure
	if len(e.moduleFields) > 0 {
		result["auditd"] = e.moduleFields
	}

	// Add error if present
	if e.error != nil {
		result["error"] = e.error.Error()
	}

	return json.Marshal(result)
}

// AuditbeatExporterConfig contains configuration for the auditbeat exporter
type AuditbeatExporterConfig struct {
	URL                string          `json:"url"`
	Path               *string         `json:"path,omitempty"`
	QueryParams        []HTTPKeyValues `json:"queryParams,omitempty"`
	Headers            []HTTPKeyValues `json:"headers"`
	TimeoutSeconds     int             `json:"timeoutSeconds"`
	Method             string          `json:"method"`
	MaxEventsPerMinute int             `json:"maxEventsPerMinute"`
	BatchSize          int             `json:"batchSize"`
	EnableBatching     bool            `json:"enableBatching"`
	ResolveIDs         bool            `json:"resolveIds"`
	Warnings           bool            `json:"warnings"`
	RawMessage         bool            `json:"rawMessage"`
}

// AuditbeatExporter implements the Exporter interface for auditbeat-compatible events
type AuditbeatExporter struct {
	config        AuditbeatExporterConfig
	host          string
	nodeName      string
	clusterName   string
	httpClient    *http.Client
	eventMetrics  *eventMetrics
	cloudMetadata *apitypes.CloudMetadata
	batchBuffer   []AuditbeatEvent
	batchMutex    sync.Mutex
}

type eventMetrics struct {
	sync.Mutex
	count      int
	startTime  time.Time
	isNotified bool
}

// NewAuditbeatExporter creates a new AuditbeatExporter instance
func NewAuditbeatExporter(config AuditbeatExporterConfig, clusterName, nodeName string, cloudMetadata *apitypes.CloudMetadata) (*AuditbeatExporter, error) {
	if err := config.Validate(); err != nil {
		return nil, fmt.Errorf("invalid config: %w", err)
	}

	return &AuditbeatExporter{
		config:      config,
		nodeName:    nodeName,
		clusterName: clusterName,
		httpClient: &http.Client{
			Timeout: time.Duration(config.TimeoutSeconds) * time.Second,
		},
		eventMetrics:  &eventMetrics{},
		cloudMetadata: cloudMetadata,
		batchBuffer:   make([]AuditbeatEvent, 0, config.BatchSize),
	}, nil
}

func (config *AuditbeatExporterConfig) Validate() error {
	if config.URL == "" {
		return fmt.Errorf("URL is required")
	}

	if config.Method == "" {
		config.Method = defaultAuditbeatMethod
	} else if config.Method != "POST" && config.Method != "PUT" {
		return fmt.Errorf("method must be POST or PUT")
	}

	if config.TimeoutSeconds == 0 {
		config.TimeoutSeconds = int(defaultAuditbeatTimeout.Seconds())
	}

	if config.MaxEventsPerMinute == 0 {
		config.MaxEventsPerMinute = defaultAuditbeatMaxEventsPerMin
	}

	if config.BatchSize == 0 {
		config.BatchSize = defaultAuditbeatBatchSize
	}

	if config.Headers == nil {
		config.Headers = []HTTPKeyValues{}
	}

	if config.QueryParams == nil {
		config.QueryParams = []HTTPKeyValues{}
	}

	return nil
}

// SendRuleAlert implements the Exporter interface (not used for auditbeat)
func (e *AuditbeatExporter) SendRuleAlert(failedRule ruleengine.RuleFailure) {
	// Auditbeat exporter is specifically for audit events, not rule alerts
	logger.L().Debug("AuditbeatExporter.SendRuleAlert - ignoring rule alert (auditbeat exporter is for audit events only)")
}

// SendMalwareAlert implements the Exporter interface (not used for auditbeat)
func (e *AuditbeatExporter) SendMalwareAlert(malwareResult malwaremanager.MalwareResult) {
	// Auditbeat exporter is specifically for audit events, not malware alerts
	logger.L().Debug("AuditbeatExporter.SendMalwareAlert - ignoring malware alert (auditbeat exporter is for audit events only)")
}

// SendAuditAlert implements the Exporter interface
func (e *AuditbeatExporter) SendAuditAlert(auditResult auditmanager.AuditResult) {
	ctx, cancel := context.WithTimeout(context.Background(), time.Duration(e.config.TimeoutSeconds)*time.Second)
	defer cancel()

	if err := e.sendAuditAlertWithContext(ctx, auditResult); err != nil {
		logger.L().Warning("AuditbeatExporter.SendAuditAlert - failed to send audit alert", helpers.Error(err))
	}
}

// sendAuditAlertWithContext sends an audit alert with context support
func (e *AuditbeatExporter) sendAuditAlertWithContext(ctx context.Context, auditResult auditmanager.AuditResult) error {
	if e.shouldSendLimitAlert() {
		return e.sendEventLimitReached(ctx)
	}

	auditbeatEvent := e.convertToAuditbeatEvent(auditResult)

	if e.config.EnableBatching {
		return e.addToBatch(ctx, auditbeatEvent)
	}

	return e.sendSingleEvent(ctx, auditbeatEvent)
}

// convertToAuditbeatEvent converts an AuditResult to an AuditbeatEvent (metricbeat format)
// This function mimics the buildMetricbeatEvent function from audit_linux.go
func (e *AuditbeatExporter) convertToAuditbeatEvent(auditResult auditmanager.AuditResult) AuditbeatEvent {
	auditEvent := auditResult.GetAuditEvent()

	// Create the base metricbeat event structure
	eventOutcome := "success"
	if !auditEvent.Success {
		eventOutcome = "failure"
	}

	out := AuditbeatEvent{
		timestamp:    time.Unix(0, int64(auditEvent.Timestamp)),
		rootFields:   make(map[string]interface{}),
		moduleFields: make(map[string]interface{}),
	}

	// Add event information (mimics the event structure from buildMetricbeatEvent)
	out.rootFields["event"] = map[string]interface{}{
		"category": e.determineEventCategory(auditEvent),
		"action":   e.determineEventAction(auditEvent),
		"outcome":  eventOutcome,
		"kind":     "event",
		"type":     []string{e.determineEventType(auditEvent)},
		"dataset":  "auditd.auditd",
	}

	// Add module fields (mimics ModuleFields from buildMetricbeatEvent)
	out.moduleFields["message_type"] = strings.ToLower(auditEvent.Type.String())
	out.moduleFields["sequence"] = auditEvent.Sequence
	out.moduleFields["result"] = eventOutcome
	out.moduleFields["data"] = e.createAuditdData(auditEvent.Data)

	// Add session information if available
	if auditEvent.SessionID != 0 {
		out.moduleFields["session"] = strconv.FormatUint(uint64(auditEvent.SessionID), 10)
	}

	// Add root level fields (mimics the addUser, addProcess, etc. functions)
	e.addUser(auditEvent, out.rootFields)
	e.addProcess(auditEvent, out.rootFields)
	e.addFile(auditEvent, out.rootFields)
	e.addNetwork(auditEvent, out.rootFields)
	e.addKubernetes(auditEvent, out.rootFields)
	e.addHost(auditEvent, out.rootFields)
	e.addAgent(auditEvent, out.rootFields)

	// Add tags if available
	if len(auditEvent.Keys) > 0 {
		out.rootFields["tags"] = auditEvent.Keys
	}

	// Add warnings if enabled and available
	if e.config.Warnings && len(auditEvent.Data) > 0 {
		// For now, we don't have warnings in our audit event structure
		// This would be populated if we had warning information
	}

	// Add raw message if enabled
	if e.config.RawMessage && auditEvent.RawMessage != "" {
		out.rootFields["event.original"] = auditEvent.RawMessage
	}

	// Add module fields (summary information)
	e.addSummary(auditEvent, out.moduleFields)

	// Normalize event fields
	e.normalizeEventFields(auditEvent, out.rootFields)

	return out
}

// createAuditdData creates the auditd data structure (mimics createAuditdData from audit_linux.go)
func (e *AuditbeatExporter) createAuditdData(data map[string]string) map[string]interface{} {
	out := make(map[string]interface{}, len(data))
	for key, v := range data {
		if strings.HasPrefix(key, "socket_") {
			out["socket."+key[7:]] = v
			continue
		}
		out[key] = v
	}
	return out
}

// addUser adds user information to the event (mimics addUser from audit_linux.go)
func (e *AuditbeatExporter) addUser(auditEvent *auditmanager.AuditEvent, root map[string]interface{}) {
	if auditEvent.UID == 0 && auditEvent.EUID == 0 {
		return
	}

	user := make(map[string]interface{})
	root["user"] = user

	// Primary user ID
	if auditEvent.UID != 0 {
		user["id"] = strconv.FormatUint(uint64(auditEvent.UID), 10)
	}

	// Group ID
	if auditEvent.GID != 0 {
		user["group.id"] = strconv.FormatUint(uint64(auditEvent.GID), 10)
	}

	// Effective user ID
	if auditEvent.EUID != 0 && auditEvent.EUID != auditEvent.UID {
		user["effective.id"] = strconv.FormatUint(uint64(auditEvent.EUID), 10)
	}

	// Effective group ID
	if auditEvent.EGID != 0 && auditEvent.EGID != auditEvent.GID {
		user["effective.group.id"] = strconv.FormatUint(uint64(auditEvent.EGID), 10)
	}

	// Saved UID/GID
	if auditEvent.SUID != 0 {
		user["saved.id"] = strconv.FormatUint(uint64(auditEvent.SUID), 10)
	}
	if auditEvent.SGID != 0 {
		user["saved.group.id"] = strconv.FormatUint(uint64(auditEvent.SGID), 10)
	}

	// Filesystem UID/GID
	if auditEvent.FSUID != 0 {
		user["filesystem.id"] = strconv.FormatUint(uint64(auditEvent.FSUID), 10)
	}
	if auditEvent.FSGID != 0 {
		user["filesystem.group.id"] = strconv.FormatUint(uint64(auditEvent.FSGID), 10)
	}

	// Audit UID
	if auditEvent.LoginUID != 0 {
		user["audit.id"] = strconv.FormatUint(uint64(auditEvent.LoginUID), 10)
	}

	// SELinux context
	if auditEvent.SELinuxContext != "" {
		user["selinux"] = auditEvent.SELinuxContext
	}
}

// addProcess adds process information to the event (mimics addProcess from audit_linux.go)
func (e *AuditbeatExporter) addProcess(auditEvent *auditmanager.AuditEvent, root map[string]interface{}) {
	if auditEvent.PID == 0 {
		return
	}

	process := make(map[string]interface{})
	root["process"] = process

	if auditEvent.PID != 0 {
		process["pid"] = int(auditEvent.PID)
	}

	if auditEvent.PPID != 0 {
		process["parent"] = map[string]interface{}{
			"pid": int(auditEvent.PPID),
		}
	}

	if auditEvent.Comm != "" {
		process["name"] = auditEvent.Comm
	}

	if auditEvent.Exe != "" {
		process["executable"] = auditEvent.Exe
	}

	if auditEvent.CWD != "" {
		process["working_directory"] = auditEvent.CWD
	}

	if len(auditEvent.Args) > 0 {
		process["args"] = auditEvent.Args
	}

	if auditEvent.ProcTitle != "" {
		process["title"] = auditEvent.ProcTitle
	}
}

// addFile adds file information to the event (mimics addFile from audit_linux.go)
func (e *AuditbeatExporter) addFile(auditEvent *auditmanager.AuditEvent, root map[string]interface{}) {
	if auditEvent.Path == "" {
		return
	}

	file := make(map[string]interface{})
	root["file"] = file

	if auditEvent.Path != "" {
		file["path"] = auditEvent.Path
	}

	if auditEvent.DevMajor != 0 && auditEvent.DevMinor != 0 {
		file["device"] = fmt.Sprintf("%d:%d", auditEvent.DevMajor, auditEvent.DevMinor)
	}

	if auditEvent.Inode != 0 {
		file["inode"] = strconv.FormatUint(auditEvent.Inode, 10)
	}

	if auditEvent.Mode != 0 {
		file["mode"] = fmt.Sprintf("%04o", auditEvent.Mode)
	}

	if auditEvent.UID != 0 {
		file["uid"] = strconv.FormatUint(uint64(auditEvent.UID), 10)
	}

	if auditEvent.GID != 0 {
		file["gid"] = strconv.FormatUint(uint64(auditEvent.GID), 10)
	}

	if auditEvent.SELinuxContext != "" {
		file["selinux"] = auditEvent.SELinuxContext
	}
}

// addNetwork adds network information to the event (mimics addNetwork from audit_linux.go)
func (e *AuditbeatExporter) addNetwork(auditEvent *auditmanager.AuditEvent, root map[string]interface{}) {
	if auditEvent.SockFamily == "" {
		return
	}

	network := map[string]interface{}{
		"direction": "unknown", // We don't have direction info in our audit event
	}
	root["network"] = network

	if auditEvent.SockFamily != "" {
		switch auditEvent.SockFamily {
		case "unix":
			network["transport"] = "unix"
		case "inet", "inet6":
			network["transport"] = "tcp"
			network["protocol"] = "tcp"
		}
	}
}

// addKubernetes adds Kubernetes context to the event
func (e *AuditbeatExporter) addKubernetes(auditEvent *auditmanager.AuditEvent, root map[string]interface{}) {
	if auditEvent.Pod == "" && auditEvent.Namespace == "" {
		return
	}

	k8s := make(map[string]interface{})
	root["kubernetes"] = k8s

	if auditEvent.Pod != "" {
		k8s["pod.name"] = auditEvent.Pod
	}

	if auditEvent.Namespace != "" {
		k8s["namespace.name"] = auditEvent.Namespace
	}

	if e.nodeName != "" {
		k8s["node.name"] = e.nodeName
	}
}

// addHost adds host information to the event
func (e *AuditbeatExporter) addHost(auditEvent *auditmanager.AuditEvent, root map[string]interface{}) {
	if e.nodeName != "" {
		root["host.name"] = e.nodeName
	}
}

// addAgent adds agent information to the event
func (e *AuditbeatExporter) addAgent(auditEvent *auditmanager.AuditEvent, root map[string]interface{}) {
	agent := map[string]interface{}{
		"type":    "kubescape-node-agent",
		"version": "1.0.0", // TODO: Get from build info
	}
	root["agent"] = agent
}

// addSummary adds summary information to the module fields (mimics summary handling from buildMetricbeatEvent)
func (e *AuditbeatExporter) addSummary(auditEvent *auditmanager.AuditEvent, module map[string]interface{}) {
	summary := make(map[string]interface{})

	// Actor information
	if auditEvent.Comm != "" || auditEvent.UID != 0 {
		actor := make(map[string]interface{})
		if auditEvent.Comm != "" {
			actor["primary"] = auditEvent.Comm
		}
		if auditEvent.UID == 0 {
			actor["secondary"] = "root"
		}
		summary["actor"] = actor
	}

	// Object information
	if auditEvent.Path != "" {
		object := map[string]interface{}{
			"primary": auditEvent.Path,
			"type":    "file",
		}
		summary["object"] = object
	}

	if len(summary) > 0 {
		module["summary"] = summary
	}
}

// normalizeEventFields normalizes event fields according to ECS (mimics normalizeEventFields from audit_linux.go)
func (e *AuditbeatExporter) normalizeEventFields(auditEvent *auditmanager.AuditEvent, root map[string]interface{}) {
	root["event.kind"] = "event"

	// Add service information
	root["service.type"] = "auditd"
}

// Helper methods for determining event characteristics
func (e *AuditbeatExporter) determineEventCategory(auditEvent *auditmanager.AuditEvent) string {
	switch {
	case auditEvent.Syscall != "":
		return "process"
	case auditEvent.Path != "":
		return "file"
	case auditEvent.SockFamily != "":
		return "network"
	default:
		return "system"
	}
}

func (e *AuditbeatExporter) determineEventAction(auditEvent *auditmanager.AuditEvent) string {
	switch {
	case auditEvent.Syscall != "":
		return "executed"
	case auditEvent.Path != "":
		switch auditEvent.Operation {
		case "read":
			return "accessed"
		case "write":
			return "modified"
		case "create":
			return "created"
		case "delete":
			return "deleted"
		default:
			return "accessed"
		}
	case auditEvent.SockFamily != "":
		return "connected"
	default:
		return "executed"
	}
}

func (e *AuditbeatExporter) determineEventType(auditEvent *auditmanager.AuditEvent) string {
	switch {
	case auditEvent.Syscall != "":
		return "start"
	case auditEvent.Path != "":
		return "change"
	default:
		return "info"
	}
}

// Batch handling methods
func (e *AuditbeatExporter) addToBatch(ctx context.Context, event AuditbeatEvent) error {
	e.batchMutex.Lock()
	defer e.batchMutex.Unlock()

	e.batchBuffer = append(e.batchBuffer, event)

	if len(e.batchBuffer) >= e.config.BatchSize {
		return e.flushBatch(ctx)
	}

	return nil
}

func (e *AuditbeatExporter) flushBatch(ctx context.Context) error {
	if len(e.batchBuffer) == 0 {
		return nil
	}

	events := make([]AuditbeatEvent, len(e.batchBuffer))
	copy(events, e.batchBuffer)
	e.batchBuffer = e.batchBuffer[:0]

	return e.sendBatch(ctx, events)
}

// HTTP sending methods
func (e *AuditbeatExporter) sendSingleEvent(ctx context.Context, event AuditbeatEvent) error {
	return e.sendBatch(ctx, []AuditbeatEvent{event})
}

func (e *AuditbeatExporter) sendBatch(ctx context.Context, events []AuditbeatEvent) error {
	// Use direct MarshalJSON calls since json.Marshal doesn't recognize our custom method
	var jsonParts []string
	for _, event := range events {
		eventJSON, err := event.MarshalJSON()
		if err != nil {
			return fmt.Errorf("failed to marshal event: %w", err)
		}
		jsonParts = append(jsonParts, string(eventJSON))
	}

	// Create JSON array
	body := []byte("[" + strings.Join(jsonParts, ",") + "]")

	var url string
	if e.config.Path != nil {
		url = fmt.Sprintf("%s%s", e.config.URL, *e.config.Path)
	} else {
		url = e.config.URL + auditbeatEndpoint
	}

	if len(e.config.QueryParams) > 0 {
		var queryParamList []string
		for _, queryParam := range e.config.QueryParams {
			if queryParam.Value == "<env>" {
				envKey := strings.ReplaceAll(strings.ToUpper(queryParam.Key), "-", "_")
				queryParam.Value = os.Getenv(envKey)
				if queryParam.Value == "" {
					logger.L().Warning("AuditbeatExporter.sendBatch - query param value is empty", helpers.String("key", queryParam.Key))
					continue
				}
			}
			queryParamList = append(queryParamList, fmt.Sprintf("%s=%s", queryParam.Key, queryParam.Value))
		}
		url = fmt.Sprintf("%s?%s", url, strings.Join(queryParamList, "&"))
	}

	req, err := http.NewRequestWithContext(ctx,
		e.config.Method,
		url,
		bytes.NewReader(body))
	if err != nil {
		return fmt.Errorf("failed to create request: %w", err)
	}

	// Set default content type
	req.Header.Set("Content-Type", "application/json")

	// Add custom headers
	for _, header := range e.config.Headers {
		if header.Value == "<env>" {
			envKey := strings.ReplaceAll(strings.ToUpper(header.Key), "-", "_")
			header.Value = os.Getenv(envKey)
			if header.Value == "" {
				logger.L().Warning("AuditbeatExporter.sendBatch - header value is empty", helpers.String("key", header.Key))
				continue
			}
		}
		req.Header.Set(header.Key, header.Value)
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
		logger.L().Debug("AuditbeatExporter.sendBatch - failed to drain response body", helpers.Error(err))
	}

	return nil
}

// Rate limiting methods
func (e *AuditbeatExporter) shouldSendLimitAlert() bool {
	e.eventMetrics.Lock()
	defer e.eventMetrics.Unlock()

	if e.eventMetrics.startTime.IsZero() {
		e.eventMetrics.startTime = time.Now()
	}

	if time.Since(e.eventMetrics.startTime) > time.Minute {
		e.resetEventMetrics()
		return false
	}

	e.eventMetrics.count++
	return e.eventMetrics.count > e.config.MaxEventsPerMinute && !e.eventMetrics.isNotified
}

func (e *AuditbeatExporter) resetEventMetrics() {
	e.eventMetrics.startTime = time.Now()
	e.eventMetrics.count = 0
	e.eventMetrics.isNotified = false
}

func (e *AuditbeatExporter) sendEventLimitReached(ctx context.Context) error {
	e.eventMetrics.Lock()
	e.eventMetrics.isNotified = true
	e.eventMetrics.Unlock()

	logger.L().Warning("Audit event limit reached",
		helpers.Int("events", e.eventMetrics.count),
		helpers.String("since", e.eventMetrics.startTime.Format(time.RFC3339)))

	// Create a limit reached event
	limitEvent := AuditbeatEvent{
		timestamp:    time.Now(),
		rootFields:   make(map[string]interface{}),
		moduleFields: make(map[string]interface{}),
	}

	limitEvent.rootFields["event"] = map[string]interface{}{
		"category": []string{"system"},
		"action":   "limit_reached",
		"outcome":  "success",
		"kind":     "event",
		"type":     []string{"info"},
		"dataset":  "auditd.auditd",
	}
	limitEvent.rootFields["service"] = map[string]interface{}{
		"type": "auditd",
	}

	limitEvent.moduleFields["message_type"] = "limit"
	limitEvent.moduleFields["sequence"] = 0
	limitEvent.moduleFields["result"] = "success"
	limitEvent.moduleFields["data"] = map[string]interface{}{
		"message": "Audit event rate limit reached",
		"count":   e.eventMetrics.count,
	}

	return e.sendSingleEvent(ctx, limitEvent)
}
