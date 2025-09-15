package v1

import (
	"context"
	"fmt"
	"strings"
	"sync"
	"time"

	"github.com/elastic/go-libaudit/v2"
	"github.com/elastic/go-libaudit/v2/rule"
	"github.com/elastic/go-libaudit/v2/rule/flags"
	"github.com/kubescape/go-logger"
	"github.com/kubescape/go-logger/helpers"
	"github.com/kubescape/node-agent/pkg/auditmanager"
	"github.com/kubescape/node-agent/pkg/exporters"
	"github.com/kubescape/node-agent/pkg/utils"
)

// AuditManagerV1 implements the AuditManagerClient interface using go-libaudit
type AuditManagerV1 struct {
	// Configuration
	enabled bool

	// go-libaudit client
	auditClient *libaudit.AuditClient

	// Event processing
	eventChan chan *AuditEvent
	exporter  *exporters.ExporterBus // Direct connection to exporters

	// Rule management
	loadedRules []*AuditRule

	// State management
	ctx     context.Context
	cancel  context.CancelFunc
	wg      sync.WaitGroup
	mutex   sync.RWMutex
	running bool

	// Statistics
	stats auditmanager.AuditManagerStatus
}

// NewAuditManagerV1 creates a new audit manager instance
func NewAuditManagerV1(exporter *exporters.ExporterBus) (*AuditManagerV1, error) {
	if exporter == nil {
		return nil, fmt.Errorf("exporter cannot be nil")
	}

	return &AuditManagerV1{
		enabled:   true,
		eventChan: make(chan *AuditEvent, 1000), // Buffered channel for events
		exporter:  exporter,
		stats: auditmanager.AuditManagerStatus{
			IsRunning:    false,
			RulesLoaded:  0,
			EventsTotal:  0,
			EventsErrors: 0,
		},
	}, nil
}

// Start begins the audit manager and starts listening for audit events
func (am *AuditManagerV1) Start(ctx context.Context) error {
	am.mutex.Lock()
	defer am.mutex.Unlock()

	if am.running {
		return fmt.Errorf("audit manager is already running")
	}

	if !am.enabled {
		logger.L().Info("audit manager is disabled, skipping start")
		return nil
	}

	// Create context for this manager
	am.ctx, am.cancel = context.WithCancel(ctx)

	// Initialize the audit client
	if err := am.initializeAuditClient(); err != nil {
		return fmt.Errorf("failed to initialize audit client: %w", err)
	}

	// Load hardcoded rules
	if err := am.loadRules(); err != nil {
		return fmt.Errorf("failed to load audit rules: %w", err)
	}

	// Start event processing goroutine
	am.wg.Add(1)
	go am.eventProcessingLoop()

	// Start audit event listening goroutine
	am.wg.Add(1)
	go am.auditEventListener()

	am.running = true
	am.stats.IsRunning = true

	logger.L().Info("audit manager started successfully",
		helpers.Int("rulesLoaded", len(am.loadedRules)))

	return nil
}

// Stop gracefully shuts down the audit manager
func (am *AuditManagerV1) Stop() error {
	am.mutex.Lock()
	defer am.mutex.Unlock()

	if !am.running {
		return nil
	}

	logger.L().Info("stopping audit manager...")

	// Cancel context to signal all goroutines to stop
	if am.cancel != nil {
		am.cancel()
	}

	// Close the audit client
	if am.auditClient != nil {
		am.auditClient.Close()
	}

	// Wait for all goroutines to finish
	am.wg.Wait()

	// Close event channel
	close(am.eventChan)

	am.running = false
	am.stats.IsRunning = false

	logger.L().Info("audit manager stopped successfully")
	return nil
}

// ReportEvent is called when an audit event should be processed
// This follows the pattern used by other managers in the node-agent
func (am *AuditManagerV1) ReportEvent(eventType utils.EventType, event utils.K8sEvent, containerID string, comm string) {
	// For audit manager, we generate events internally from kernel audit subsystem
	// This method is here to satisfy the interface but isn't used in the same way
	// as other managers that receive events from eBPF tracers
	logger.L().Debug("audit manager ReportEvent called",
		helpers.String("eventType", string(eventType)),
		helpers.String("containerID", containerID),
		helpers.String("comm", comm))
}

// GetStatus returns the current status of the audit manager
func (am *AuditManagerV1) GetStatus() auditmanager.AuditManagerStatus {
	am.mutex.RLock()
	defer am.mutex.RUnlock()

	// Update rules loaded count
	am.stats.RulesLoaded = len(am.loadedRules)

	return am.stats
}

// initializeAuditClient sets up the go-libaudit client
func (am *AuditManagerV1) initializeAuditClient() error {
	var err error

	// Create audit client
	am.auditClient, err = libaudit.NewAuditClient(nil)
	if err != nil {
		return fmt.Errorf("failed to create audit client: %w", err)
	}

	// Get audit status
	status, err := am.auditClient.GetStatus()
	if err != nil {
		return fmt.Errorf("failed to get audit status: %w", err)
	}

	logger.L().Info("audit subsystem status",
		helpers.String("enabled", fmt.Sprintf("%v", status.Enabled == 1)),
		helpers.Int("pid", int(status.PID)),
		helpers.Int("rateLimit", int(status.RateLimit)))

	// Enable audit subsystem if not already enabled
	if status.Enabled != 1 {
		err = am.auditClient.SetEnabled(true, libaudit.WaitForReply)
		if err != nil {
			return fmt.Errorf("failed to enable audit subsystem: %w", err)
		}
		logger.L().Info("enabled audit subsystem")
	}

	// Set our PID as the audit daemon PID
	err = am.auditClient.SetPID(libaudit.WaitForReply)
	if err != nil {
		return fmt.Errorf("failed to set audit PID: %w", err)
	}

	return nil
}

// loadRules loads the hardcoded audit rules into the kernel
func (am *AuditManagerV1) loadRules() error {
	rules, err := LoadHardcodedRules()
	if err != nil {
		return fmt.Errorf("failed to load hardcoded rules: %w", err)
	}

	am.loadedRules = rules

	logger.L().Info("loading audit rules into kernel", helpers.Int("count", len(rules)))

	// Clear existing rules first
	_, err = am.auditClient.DeleteRules()
	if err != nil {
		logger.L().Warning("failed to clear existing audit rules", helpers.Error(err))
		// Continue anyway - this might fail if no rules exist
	}

	// Load each rule into the kernel
	for i, rule := range rules {
		logger.L().Debug("loading rule into kernel",
			helpers.Int("index", i),
			helpers.String("description", rule.GetRuleDescription()),
			helpers.String("raw", rule.RawRule))

		err = am.loadRuleIntoKernel(rule)
		if err != nil {
			logger.L().Warning("failed to load rule into kernel",
				helpers.Error(err),
				helpers.String("rule", rule.RawRule))
			// Continue with other rules even if one fails
			continue
		}

		logger.L().Debug("successfully loaded rule into kernel",
			helpers.String("rule", rule.RawRule))
	}

	logger.L().Info("audit rules loaded into kernel", helpers.Int("total", len(rules)))
	return nil
}

// loadRuleIntoKernel loads a single audit rule into the kernel using go-libaudit
func (am *AuditManagerV1) loadRuleIntoKernel(auditRule *AuditRule) error {
	ruleStr := auditRule.RawRule
	logger.L().Debug("adding audit rule to kernel", helpers.String("rule", ruleStr))

	// Parse the raw rule string into a structured rule using go-libaudit
	parsedRule, err := flags.Parse(ruleStr)
	if err != nil {
		return fmt.Errorf("failed to parse audit rule '%s': %w", ruleStr, err)
	}

	logger.L().Debug("successfully parsed audit rule",
		helpers.String("rule", ruleStr),
		helpers.String("type", fmt.Sprintf("%T", parsedRule)))

	// Convert the structured rule to wire format for kernel
	wireFormat, err := rule.Build(parsedRule)
	if err != nil {
		return fmt.Errorf("failed to build wire format for rule '%s': %w", ruleStr, err)
	}

	// Add the rule to the kernel using the audit client
	err = am.auditClient.AddRule(wireFormat)
	if err != nil {
		return fmt.Errorf("failed to add audit rule to kernel '%s': %w", ruleStr, err)
	}

	logger.L().Info("successfully loaded audit rule into kernel",
		helpers.String("rule", ruleStr),
		helpers.String("description", auditRule.GetRuleDescription()))

	return nil
}

// parseAuditMessage parses a raw audit message into an AuditEvent
func (am *AuditManagerV1) parseAuditMessage(rawMessage []byte) (*AuditEvent, error) {
	// Parse the audit message using go-libaudit
	// For now, we'll do basic parsing - in production this would be more robust

	messageStr := string(rawMessage)
	if messageStr == "" {
		return nil, nil // Skip empty messages
	}

	logger.L().Debug("parsing audit message", helpers.String("raw", messageStr))

	// Create a basic audit event from the raw message
	// This is a simplified parser - in production would use go-libaudit's parsing capabilities
	event := NewAuditEvent(0, "KERNEL_AUDIT")
	event.RawMessage = messageStr

	// Basic parsing to extract common fields
	// In production, this would use proper audit message parsing from go-libaudit
	if strings.Contains(messageStr, "type=PATH") {
		event.MessageType = "PATH"
		event.RuleType = "file_watch"

		// Extract path if available
		if pathStart := strings.Index(messageStr, "name="); pathStart != -1 {
			pathStart += 5 // Skip "name="
			if pathStart < len(messageStr) && messageStr[pathStart] == '"' {
				pathStart++ // Skip opening quote
				pathEnd := strings.Index(messageStr[pathStart:], "\"")
				if pathEnd != -1 {
					event.Path = messageStr[pathStart : pathStart+pathEnd]
				}
			}
		}
	} else if strings.Contains(messageStr, "type=SYSCALL") {
		event.MessageType = "SYSCALL"
		event.RuleType = "syscall"

		// Extract syscall name if available
		if syscallStart := strings.Index(messageStr, "syscall="); syscallStart != -1 {
			syscallStart += 8 // Skip "syscall="
			syscallEnd := strings.Index(messageStr[syscallStart:], " ")
			if syscallEnd == -1 {
				syscallEnd = len(messageStr) - syscallStart
			}
			event.Syscall = messageStr[syscallStart : syscallStart+syscallEnd]
		}
	}

	// Extract common fields like pid, uid, etc.
	am.extractCommonFields(event, messageStr)

	return event, nil
}

// extractCommonFields extracts common fields from audit message
func (am *AuditManagerV1) extractCommonFields(event *AuditEvent, messageStr string) {
	// Extract PID
	if pidStart := strings.Index(messageStr, "pid="); pidStart != -1 {
		pidStart += 4 // Skip "pid="
		pidEnd := strings.Index(messageStr[pidStart:], " ")
		if pidEnd == -1 {
			pidEnd = len(messageStr) - pidStart
		}
		if pidStr := messageStr[pidStart : pidStart+pidEnd]; pidStr != "" {
			if pid, err := fmt.Sscanf(pidStr, "%d", &event.PID); err == nil && pid == 1 {
				// Successfully parsed PID
			}
		}
	}

	// Extract UID
	if uidStart := strings.Index(messageStr, "uid="); uidStart != -1 {
		uidStart += 4 // Skip "uid="
		uidEnd := strings.Index(messageStr[uidStart:], " ")
		if uidEnd == -1 {
			uidEnd = len(messageStr) - uidStart
		}
		if uidStr := messageStr[uidStart : uidStart+uidEnd]; uidStr != "" {
			if uid, err := fmt.Sscanf(uidStr, "%d", &event.UID); err == nil && uid == 1 {
				// Successfully parsed UID
			}
		}
	}

	// Extract COMM (command name)
	if commStart := strings.Index(messageStr, "comm="); commStart != -1 {
		commStart += 5 // Skip "comm="
		if commStart < len(messageStr) && messageStr[commStart] == '"' {
			commStart++ // Skip opening quote
			commEnd := strings.Index(messageStr[commStart:], "\"")
			if commEnd != -1 {
				event.Comm = messageStr[commStart : commStart+commEnd]
			}
		}
	}

	// Extract key (audit rule key)
	if keyStart := strings.Index(messageStr, "key="); keyStart != -1 {
		keyStart += 4 // Skip "key="
		if keyStart < len(messageStr) && messageStr[keyStart] == '"' {
			keyStart++ // Skip opening quote
			keyEnd := strings.Index(messageStr[keyStart:], "\"")
			if keyEnd != -1 {
				event.Key = messageStr[keyStart : keyStart+keyEnd]
			}
		}
	}
}

// auditEventListener listens for audit events from the kernel
func (am *AuditManagerV1) auditEventListener() {
	defer am.wg.Done()

	logger.L().Info("starting audit event listener - listening for real kernel events")

	for {
		select {
		case <-am.ctx.Done():
			logger.L().Info("audit event listener stopping due to context cancellation")
			return
		default:
			// Receive real audit events from the kernel
			rawMessage, err := am.auditClient.Receive(false) // non-blocking receive
			if err != nil {
				if err.Error() == "resource temporarily unavailable" {
					// No events available, continue
					time.Sleep(100 * time.Millisecond)
					continue
				}
				logger.L().Warning("error receiving audit event", helpers.Error(err))
				am.stats.EventsErrors++
				time.Sleep(1 * time.Second)
				continue
			}

			// Parse and process the audit message
			auditEvent, err := am.parseAuditMessage(rawMessage.Data)
			if err != nil {
				logger.L().Warning("failed to parse audit message",
					helpers.Error(err),
					helpers.String("rawMessage", string(rawMessage.Data)))
				am.stats.EventsErrors++
				continue
			}

			if auditEvent != nil {
				// Send event to processing channel
				select {
				case am.eventChan <- auditEvent:
					logger.L().Debug("real audit event queued",
						helpers.String("messageType", auditEvent.MessageType),
						helpers.String("key", auditEvent.Key))
				case <-am.ctx.Done():
					return
				default:
					// Channel is full, drop event
					am.stats.EventsErrors++
					logger.L().Warning("audit event channel full, dropping real event")
				}
			}
		}
	}
}

// Note: simulateAuditEvents removed - now using real kernel audit events

// eventProcessingLoop processes audit events from the event channel
func (am *AuditManagerV1) eventProcessingLoop() {
	defer am.wg.Done()

	logger.L().Info("starting audit event processing loop")

	for {
		select {
		case <-am.ctx.Done():
			logger.L().Info("audit event processing loop stopping due to context cancellation")
			return
		case event, ok := <-am.eventChan:
			if !ok {
				logger.L().Info("audit event channel closed, stopping processing loop")
				return
			}

			am.processAuditEvent(event)
		}
	}
}

// processAuditEvent processes a single audit event
func (am *AuditManagerV1) processAuditEvent(event *AuditEvent) {
	am.stats.EventsTotal++

	logger.L().Debug("processing audit event",
		helpers.String("messageType", event.MessageType),
		helpers.String("key", event.Key),
		helpers.String("path", event.Path),
		helpers.String("comm", event.Comm))

	// TODO: Enrich event with Kubernetes context
	// This would involve looking up the PID to find the container and pod

	// Convert v1.AuditEvent to auditmanager.AuditEvent and send directly to exporters (bypassing rule manager)
	auditEvent := &auditmanager.AuditEvent{
		AuditID:     event.AuditID,
		MessageType: event.MessageType,
		PID:         event.PID,
		PPID:        event.PPID,
		UID:         event.UID,
		GID:         event.GID,
		EUID:        event.EUID,
		EGID:        event.EGID,
		Comm:        event.Comm,
		Exe:         event.Exe,
		Syscall:     event.Syscall,
		Args:        event.Args,
		Success:     event.Success,
		Exit:        event.Exit,
		Path:        event.Path,
		Mode:        event.Mode,
		Operation:   event.Operation,
		Key:         event.Key,
		RuleType:    event.RuleType,
		Pod:         event.Pod,
		Namespace:   event.Namespace,
		ContainerID: event.ContainerID,
		RawMessage:  event.RawMessage,
	}
	auditResult := auditmanager.NewAuditResult(auditEvent)
	am.exporter.SendAuditAlert(auditResult)

	logger.L().Debug("audit event processed and sent to exporters",
		helpers.String("auditId", fmt.Sprintf("%d", event.AuditID)))
}
