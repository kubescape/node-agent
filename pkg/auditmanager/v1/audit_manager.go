package v1

import (
	"context"
	"fmt"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/elastic/go-libaudit/v2"
	"github.com/elastic/go-libaudit/v2/auparse"
	"github.com/elastic/go-libaudit/v2/rule"
	"github.com/elastic/go-libaudit/v2/rule/flags"
	"github.com/inspektor-gadget/inspektor-gadget/pkg/types"
	"github.com/kubescape/go-logger"
	"github.com/kubescape/go-logger/helpers"
	"github.com/kubescape/node-agent/pkg/auditmanager"
	"github.com/kubescape/node-agent/pkg/auditmanager/crd"
	"github.com/kubescape/node-agent/pkg/config"
	"github.com/kubescape/node-agent/pkg/exporters"
	"github.com/kubescape/node-agent/pkg/utils"
)

// IndexedRule represents a rule with metadata for management
type IndexedRule struct {
	ID          string     // unique: "crd-name/rule-name" or "hardcoded/rule-name"
	Rule        *AuditRule // parsed rule
	SourceCRD   string     // which CRD it came from (empty for hardcoded)
	SourceType  string     // "hardcoded" or "crd"
	Priority    int        // for ordering
	LastUpdated time.Time  // when it was last updated
}

// RuleChangeSet represents changes to be applied to the kernel
type RuleChangeSet struct {
	ToAdd    []*IndexedRule
	ToRemove []*IndexedRule
	ToUpdate []*IndexedRule
}

// AuditManagerV1 implements the AuditManagerClient interface using go-libaudit
type AuditManagerV1 struct {
	// Configuration
	enabled bool
	config  *config.Config

	// go-libaudit client
	auditClient *libaudit.AuditClient

	// Event processing
	eventChan chan *auditmanager.AuditEvent
	exporter  *exporters.ExporterBus // Direct connection to exporters

	// Rule management
	loadedRules []*AuditRule // Hardcoded rules

	// CRD-based rule management
	crdRules      map[string]*crd.LinuxAuditRule // CRD name -> LinuxAuditRule CRD
	ruleIndex     map[string]*IndexedRule        // rule_id -> rule with metadata
	rulesBySource map[string][]string            // CRD name -> list of rule IDs
	ruleConverter *crd.RuleConverter             // Converts structured rules to auditctl

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
func NewAuditManagerV1(config *config.Config, exporter *exporters.ExporterBus) (*AuditManagerV1, error) {
	if exporter == nil {
		return nil, fmt.Errorf("exporter cannot be nil")
	}
	if config == nil {
		return nil, fmt.Errorf("config cannot be nil")
	}

	return &AuditManagerV1{
		enabled:       true,
		config:        config,
		eventChan:     make(chan *auditmanager.AuditEvent, 1000), // Buffered channel for events
		exporter:      exporter,
		crdRules:      make(map[string]*crd.LinuxAuditRule),
		ruleIndex:     make(map[string]*IndexedRule),
		rulesBySource: make(map[string][]string),
		ruleConverter: crd.NewRuleConverter(),
		loadedRules:   nil, // Don't use hardcoded rules
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

	// Skip loading hardcoded rules, only use CRD rules
	logger.L().Info("skipping hardcoded rules, using CRD rules only")

	// Start event processing goroutine
	am.wg.Add(1)
	go am.eventProcessingLoop()

	// Start audit event listening goroutine
	am.wg.Add(1)
	go am.auditEventListener()

	// Start periodic stats logging
	am.wg.Add(1)
	go am.statsLogger()

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

// LogBackpressureStats logs current backpressure statistics for monitoring
func (am *AuditManagerV1) LogBackpressureStats() {
	am.mutex.RLock()
	defer am.mutex.RUnlock()

	if am.stats.EventsBlocked > 0 && am.stats.EventsTotal > 0 {
		dropRate := float64(am.stats.EventsDropped) / float64(am.stats.EventsTotal) * 100
		avgBlockTime := float64(am.stats.BackpressureTime) / float64(am.stats.EventsBlocked)
		channelUtilization := len(am.eventChan) * 100 / cap(am.eventChan)

		logger.L().Info("audit manager backpressure statistics",
			helpers.String("eventsTotal", fmt.Sprintf("%d", am.stats.EventsTotal)),
			helpers.String("eventsDropped", fmt.Sprintf("%d", am.stats.EventsDropped)),
			helpers.String("eventsBlocked", fmt.Sprintf("%d", am.stats.EventsBlocked)),
			helpers.String("backpressureTimeMs", fmt.Sprintf("%d", am.stats.BackpressureTime)),
			helpers.String("dropRate", fmt.Sprintf("%.2f%%", dropRate)),
			helpers.String("avgBlockTimeMs", fmt.Sprintf("%.1f", avgBlockTime)),
			helpers.Int("channelUtilization", channelUtilization))
	}
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

	// Clear any existing rules
	deletedCount, err := am.auditClient.DeleteRules()
	if err != nil {
		logger.L().Warning("failed to clear existing audit rules during initialization", helpers.Error(err))
		// Continue anyway - this might fail if no rules exist
	} else {
		logger.L().Info("cleared existing audit rules during initialization",
			helpers.Int("deletedRules", deletedCount))
	}

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
func (am *AuditManagerV1) parseAuditMessage(rawMessage *libaudit.RawAuditMessage) (*auditmanager.AuditEvent, error) {
	// Parse the audit message using go-libaudit's auparse
	msg, err := auparse.Parse(rawMessage.Type, string(rawMessage.Data))
	if err != nil {
		return nil, fmt.Errorf("failed to parse audit message: %w", err)
	}

	// Get parsed data
	data, err := msg.Data()
	if err != nil {
		return nil, fmt.Errorf("failed to extract audit message data: %w", err)
	}

	// Create event with header information
	event := &auditmanager.AuditEvent{
		AuditID:    uint64(msg.Sequence),
		Type:       msg.RecordType,
		Timestamp:  types.Time(msg.Timestamp.UnixNano()),
		Sequence:   msg.Sequence,
		RawMessage: msg.RawData,
		Data:       data,
	}

	// Extract fields based on message type
	switch event.Type {
	case auparse.AUDIT_SYSCALL:
		// System call records contain process and syscall information
		am.extractProcessInfo(event, data)
		am.extractSyscallInfo(event, data)
		am.extractSecurityInfo(event, data)

	case auparse.AUDIT_PATH:
		// Path records contain file information
		am.extractFileInfo(event, data)
		am.extractSecurityInfo(event, data)

	case auparse.AUDIT_EXECVE:
		// Execve records contain command arguments
		am.extractProcessInfo(event, data)
		am.extractCommandInfo(event, data)
		am.extractSecurityInfo(event, data)

	case auparse.AUDIT_CWD:
		// Current working directory records
		event.CWD = data["cwd"]
		am.extractSecurityInfo(event, data)

	case auparse.AUDIT_SOCKADDR:
		// Socket address records contain network information
		am.extractNetworkInfo(event, data)
		am.extractSecurityInfo(event, data)

	case auparse.AUDIT_PROCTITLE:
		// Process title records
		am.extractProcessInfo(event, data)
		am.extractSecurityInfo(event, data)

	default:
		// For other types, extract what's available
		am.extractCommonFields(event, data)
	}

	// Set rule type based on message type
	switch event.Type {
	case auparse.AUDIT_PATH:
		event.RuleType = "file_watch"
	case auparse.AUDIT_SYSCALL:
		event.RuleType = "syscall"
	case auparse.AUDIT_SOCKADDR, auparse.AUDIT_SOCKETCALL:
		event.RuleType = "network"
	case auparse.AUDIT_EXECVE, auparse.AUDIT_PROCTITLE:
		event.RuleType = "process"
	case auparse.AUDIT_USER_CMD, auparse.AUDIT_USER_TTY:
		event.RuleType = "user"
	case auparse.AUDIT_NETFILTER_PKT, auparse.AUDIT_NETFILTER_CFG:
		event.RuleType = "netfilter"
	case auparse.AUDIT_MAC_STATUS, auparse.AUDIT_MAC_POLICY_LOAD:
		event.RuleType = "mac"
	case auparse.AUDIT_SECCOMP:
		event.RuleType = "seccomp"
	case auparse.AUDIT_KERNEL_OTHER:
		event.RuleType = "kernel"
	case auparse.AUDIT_CONFIG_CHANGE:
		event.RuleType = "config"
	case auparse.AUDIT_IPC:
		event.RuleType = "ipc"
	default:
		event.RuleType = fmt.Sprintf("%d", event.Type)
	}

	// Get any rule tags
	if tags, err := msg.Tags(); err == nil && len(tags) > 0 {
		event.Tags = tags   // Store all tags
		event.Key = tags[0] // Use first tag as key for backward compatibility
	}

	return event, nil
}

// extractProcessInfo extracts process-related information from audit data
func (am *AuditManagerV1) extractProcessInfo(event *auditmanager.AuditEvent, data map[string]string) {
	// Note: auparse may have already decoded some hex fields automatically
	if pid, err := strconv.ParseUint(data["pid"], 10, 32); err == nil {
		event.PID = uint32(pid)
	}
	if ppid, err := strconv.ParseUint(data["ppid"], 10, 32); err == nil {
		event.PPID = uint32(ppid)
	}
	if uid, err := strconv.ParseUint(data["uid"], 10, 32); err == nil {
		event.UID = uint32(uid)
	}
	if gid, err := strconv.ParseUint(data["gid"], 10, 32); err == nil {
		event.GID = uint32(gid)
	}
	if euid, err := strconv.ParseUint(data["euid"], 10, 32); err == nil {
		event.EUID = uint32(euid)
	}
	if egid, err := strconv.ParseUint(data["egid"], 10, 32); err == nil {
		event.EGID = uint32(egid)
	}
	if suid, err := strconv.ParseUint(data["suid"], 10, 32); err == nil {
		event.SUID = uint32(suid)
	}
	if sgid, err := strconv.ParseUint(data["sgid"], 10, 32); err == nil {
		event.SGID = uint32(sgid)
	}
	if fsuid, err := strconv.ParseUint(data["fsuid"], 10, 32); err == nil {
		event.FSUID = uint32(fsuid)
	}
	if fsgid, err := strconv.ParseUint(data["fsgid"], 10, 32); err == nil {
		event.FSGID = uint32(fsgid)
	}
	if sessionID, err := strconv.ParseUint(data["ses"], 10, 32); err == nil {
		event.SessionID = uint32(sessionID)
	}
	if loginUID, err := strconv.ParseUint(data["auid"], 10, 32); err == nil {
		event.LoginUID = uint32(loginUID)
	}

	// Process context
	event.Comm = data["comm"]
	event.Exe = data["exe"]
	event.TTY = data["tty"]

	// Check if auparse already decoded proctitle, if not decode it manually
	if proctitle := data["proctitle"]; proctitle != "" {
		// Try to use the value as-is first (auparse might have decoded it)
		if strings.Contains(proctitle, "\x00") || !strings.Contains(proctitle, "=") {
			// Looks like decoded content
			event.ProcTitle = strings.ReplaceAll(proctitle, "\x00", " ")
		} else {
			// Looks like hex, decode it manually
			if decoded, err := hexToString(proctitle); err == nil {
				event.ProcTitle = strings.ReplaceAll(decoded, "\x00", " ")
			} else {
				// If decoding fails, use as-is
				event.ProcTitle = proctitle
			}
		}
	}
}

// extractSyscallInfo extracts syscall-related information from audit data
func (am *AuditManagerV1) extractSyscallInfo(event *auditmanager.AuditEvent, data map[string]string) {
	event.Syscall = data["syscall"]
	if syscallNum, err := strconv.ParseInt(data["syscall"], 10, 32); err == nil {
		event.SyscallNum = int32(syscallNum)
	}
	event.Arch = data["arch"]
	event.ErrorCode = data["exit"] // Already enriched by auparse
	if success, err := strconv.ParseBool(data["success"]); err == nil {
		event.Success = success
	}
	if exit, err := strconv.ParseInt(data["exit"], 10, 32); err == nil {
		event.Exit = int32(exit)
	}
}

// extractFileInfo extracts file-related information from audit data
func (am *AuditManagerV1) extractFileInfo(event *auditmanager.AuditEvent, data map[string]string) {
	event.Path = data["name"]                                            // PATH records use 'name' for the path
	if mode, err := strconv.ParseUint(data["mode"], 8, 32); err == nil { // Mode is octal
		event.Mode = uint32(mode)
	}
	if major, err := strconv.ParseUint(data["dev"], 10, 32); err == nil {
		event.DevMajor = uint32(major)
	}
	if minor, err := strconv.ParseUint(data["devminor"], 10, 32); err == nil {
		event.DevMinor = uint32(minor)
	}
	if inode, err := strconv.ParseUint(data["inode"], 10, 64); err == nil {
		event.Inode = inode
	}
}

// extractNetworkInfo extracts network-related information from audit data
func (am *AuditManagerV1) extractNetworkInfo(event *auditmanager.AuditEvent, data map[string]string) {
	if sockaddr, ok := data["saddr"]; ok {
		// Store raw socket address - detailed parsing can be done later if needed
		event.SockAddr = map[string]string{
			"raw": sockaddr,
		}
		// Note: Socket address parsing could be enhanced in the future
		// For now, store the raw hex value for debugging/analysis
	}
}

// extractCommandInfo extracts command/execution information from audit data
func (am *AuditManagerV1) extractCommandInfo(event *auditmanager.AuditEvent, data map[string]string) {
	// EXECVE records contain command arguments in fields like a0, a1, a2, etc.
	var args []string
	for i := 0; i < 20; i++ { // Limit to reasonable number of arguments
		if arg, exists := data[fmt.Sprintf("a%d", i)]; exists && arg != "" {
			// Check if it looks like hex (all uppercase hex chars)
			if len(arg) > 0 && isHexString(arg) {
				if decoded, err := hexToString(arg); err == nil {
					args = append(args, decoded)
				} else {
					args = append(args, arg)
				}
			} else {
				args = append(args, arg)
			}
		} else {
			break // No more arguments
		}
	}
	event.Args = args
}

// isHexString checks if a string looks like hex-encoded data
func isHexString(s string) bool {
	if len(s)%2 != 0 {
		return false
	}
	for _, r := range s {
		if !((r >= '0' && r <= '9') || (r >= 'A' && r <= 'F') || (r >= 'a' && r <= 'f')) {
			return false
		}
	}
	return len(s) > 4 // Only consider longer strings as potential hex
}

// extractSecurityInfo extracts security-related information from audit data
func (am *AuditManagerV1) extractSecurityInfo(event *auditmanager.AuditEvent, data map[string]string) {
	event.Key = data["key"]
	event.SELinuxContext = data["subj"]      // SELinux subject context
	event.AppArmorProfile = data["apparmor"] // AppArmor profile
	event.Capabilities = data["cap_fp"]      // Process capabilities
}

// extractCommonFields extracts commonly available fields for unknown record types
func (am *AuditManagerV1) extractCommonFields(event *auditmanager.AuditEvent, data map[string]string) {
	// Extract basic process info if available
	if data["pid"] != "" {
		am.extractProcessInfo(event, data)
	}

	// Extract file info if available
	if data["name"] != "" {
		am.extractFileInfo(event, data)
	}

	// Extract network info if available
	if data["saddr"] != "" {
		am.extractNetworkInfo(event, data)
	}

	// Always extract security info
	am.extractSecurityInfo(event, data)
}

// auditEventListener listens for audit events from the kernel
func (am *AuditManagerV1) auditEventListener() {
	defer am.wg.Done()

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
			auditEvent, err := am.parseAuditMessage(rawMessage)
			if err != nil {
				logger.L().Warning("failed to parse audit message",
					helpers.Error(err),
					helpers.String("rawMessage", string(rawMessage.Data)))
				am.stats.EventsErrors++
				continue
			}

			if auditEvent != nil {
				// Send event with backpressure timeout
				select {
				case am.eventChan <- auditEvent:

				case <-am.ctx.Done():
					return
				case <-time.After(1 * time.Second):
					// Timeout after 1 second - provides backpressure but prevents indefinite blocking
					am.stats.EventsDropped++
					am.stats.EventsBlocked++
					am.stats.BackpressureTime += 1000 // 1 second in milliseconds
					logger.L().Warning("audit event channel blocked for 1s, dropping event",
						helpers.String("type", auditEvent.Type.String()),
						helpers.String("key", auditEvent.Key),
						helpers.Int("channelLen", len(am.eventChan)),
						helpers.Int("channelCap", cap(am.eventChan)),
						helpers.String("totalBlocked", fmt.Sprintf("%d", am.stats.EventsBlocked)),
						helpers.String("totalBackpressureMs", fmt.Sprintf("%d", am.stats.BackpressureTime)))

					// Optional: slow down reading when consistently blocked to reduce CPU usage
					time.Sleep(100 * time.Millisecond)
				}
			}
		}
	}
}

// statsLogger periodically logs backpressure and performance statistics
func (am *AuditManagerV1) statsLogger() {
	defer am.wg.Done()

	ticker := time.NewTicker(30 * time.Second) // Log stats every 30 seconds
	defer ticker.Stop()

	for {
		select {
		case <-am.ctx.Done():
			logger.L().Debug("audit stats logger stopping due to context cancellation")
			return
		case <-ticker.C:
			am.LogBackpressureStats()
		}
	}
}

// Note: simulateAuditEvents removed - now using real kernel audit events

// eventProcessingLoop processes audit events from the event channel
func (am *AuditManagerV1) eventProcessingLoop() {
	defer am.wg.Done()

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

// shouldExportEvent determines if an event should be exported based on configuration
func (am *AuditManagerV1) shouldExportEvent(event *auditmanager.AuditEvent) bool {
	// Always export rule-based events (events with a key)
	if event.Key != "" {
		return true
	}

	// Check if this event type is in the include list
	for _, includeType := range am.config.AuditDetection.EventFilter.IncludeTypes {
		if event.Type == includeType {
			return true
		}
	}

	return false
}

// processAuditEvent processes a single audit event
func (am *AuditManagerV1) processAuditEvent(event *auditmanager.AuditEvent) {
	am.stats.EventsTotal++

	// TODO: Enrich event with Kubernetes context
	// This would involve looking up the PID to find the container and pod

	// Check if we should export this event
	if !am.shouldExportEvent(event) {
		return
	}

	// Convert v1.AuditEvent to auditmanager.AuditEvent and send directly to exporters (bypassing rule manager)
	auditEvent := &auditmanager.AuditEvent{
		AuditID:     event.AuditID,
		Type:        event.Type,
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
}

// CRD-based rule management methods implementation

// UpdateRules processes a new or updated AuditRule CRD
func (am *AuditManagerV1) UpdateRules(ctx context.Context, crdName string, crdRules interface{}) error {
	auditRule, ok := crdRules.(*crd.LinuxAuditRule)
	if !ok {
		return fmt.Errorf("invalid rule type: expected *crd.LinuxAuditRule, got %T", crdRules)
	}

	am.mutex.Lock()
	defer am.mutex.Unlock()

	logger.L().Info("updating audit rules from CRD",
		helpers.String("crdName", crdName),
		helpers.Int("ruleCount", len(auditRule.Spec.Rules)))

	// Calculate what changed
	changeSet := am.calculateRuleChanges(crdName, auditRule)

	// Apply incremental changes
	if err := am.applyIncrementalChanges(changeSet); err != nil {
		logger.L().Warning("incremental update failed, falling back to full reload", helpers.Error(err))
		// Store the CRD first, then reload
		am.crdRules[crdName] = auditRule
		am.updateRuleIndex(crdName, auditRule)
		return am.reloadAllRules()
	}

	// Update internal state
	am.crdRules[crdName] = auditRule
	am.updateRuleIndex(crdName, auditRule)

	logger.L().Info("successfully updated audit rules from CRD",
		helpers.String("crdName", crdName),
		helpers.Int("added", len(changeSet.ToAdd)),
		helpers.Int("removed", len(changeSet.ToRemove)),
		helpers.Int("updated", len(changeSet.ToUpdate)))

	return nil
}

// RemoveRules removes all rules associated with a CRD
func (am *AuditManagerV1) RemoveRules(ctx context.Context, crdName string) error {
	am.mutex.Lock()
	defer am.mutex.Unlock()

	logger.L().Info("removing audit rules", helpers.String("crdName", crdName))

	// Remove from CRD cache
	delete(am.crdRules, crdName)

	// Remove from rule index and get rules to remove
	rulesToRemove := am.removeRulesBySource(crdName)

	// Apply removal to kernel
	if len(rulesToRemove) > 0 {
		changeSet := &RuleChangeSet{ToRemove: rulesToRemove}
		if err := am.applyIncrementalChanges(changeSet); err != nil {
			logger.L().Warning("incremental removal failed, falling back to full reload", helpers.Error(err))
			return am.reloadAllRules()
		}
	}

	logger.L().Info("successfully removed audit rules",
		helpers.String("crdName", crdName),
		helpers.Int("removedCount", len(rulesToRemove)))

	return nil
}

// ListActiveRules returns information about currently active rules
func (am *AuditManagerV1) ListActiveRules() []auditmanager.ActiveRule {
	am.mutex.RLock()
	defer am.mutex.RUnlock()

	var activeRules []auditmanager.ActiveRule

	// Only list CRD rules
	for _, indexedRule := range am.ruleIndex {
		source := "crd"
		if indexedRule.SourceCRD != "" {
			source = fmt.Sprintf("crd:%s", indexedRule.SourceCRD)
		}

		activeRule := auditmanager.ActiveRule{
			ID:          indexedRule.ID,
			Name:        indexedRule.Rule.GetRuleDescription(),
			Source:      source,
			SourceCRD:   indexedRule.SourceCRD,
			Status:      "active",
			RuleType:    indexedRule.Rule.RuleType,
			Priority:    indexedRule.Priority,
			Key:         indexedRule.Rule.Key,
			Description: indexedRule.Rule.GetRuleDescription(),
			LastUpdated: indexedRule.LastUpdated,
			ErrorMsg:    "",
		}
		activeRules = append(activeRules, activeRule)
	}

	return activeRules
}

// ValidateRules validates rule definitions without applying them
func (am *AuditManagerV1) ValidateRules(crdRules interface{}) []auditmanager.RuleValidationError {
	auditRule, ok := crdRules.(*crd.LinuxAuditRule)
	if !ok {
		return []auditmanager.RuleValidationError{
			{
				RuleName: "unknown",
				Field:    "type",
				Error:    fmt.Sprintf("invalid rule type: expected *crd.LinuxAuditRule, got %T", crdRules),
			},
		}
	}

	var errors []auditmanager.RuleValidationError

	for _, ruleDef := range auditRule.Spec.Rules {
		ruleErrors := am.ruleConverter.ValidateRuleDefinition(ruleDef)
		for _, err := range ruleErrors {
			errors = append(errors, auditmanager.RuleValidationError{
				RuleName: err.RuleName,
				Field:    err.Field,
				Error:    err.Error,
			})
		}
	}

	return errors
}

// calculateRuleChanges determines what rules need to be added, removed, or updated
func (am *AuditManagerV1) calculateRuleChanges(crdName string, newCRD *crd.LinuxAuditRule) *RuleChangeSet {
	changeSet := &RuleChangeSet{}

	oldCRD, exists := am.crdRules[crdName]
	if !exists {
		// New CRD - all rules are additions
		for _, ruleDef := range newCRD.Spec.Rules {
			if !ruleDef.Enabled {
				continue
			}
			if indexedRule, err := am.convertCRDRule(crdName, ruleDef); err == nil {
				changeSet.ToAdd = append(changeSet.ToAdd, indexedRule)
			}
		}
		return changeSet
	}

	// Create maps for comparison
	oldRules := make(map[string]crd.AuditRuleDefinition)
	newRules := make(map[string]crd.AuditRuleDefinition)

	for _, rule := range oldCRD.Spec.Rules {
		oldRules[rule.Name] = rule
	}
	for _, rule := range newCRD.Spec.Rules {
		newRules[rule.Name] = rule
	}

	// Find additions and modifications
	for name, newRule := range newRules {
		if oldRule, exists := oldRules[name]; exists {
			// Check if rule changed
			if !am.rulesEqual(oldRule, newRule) {
				// Only update if the rule is enabled
				if newRule.Enabled {
					if indexedRule, err := am.convertCRDRule(crdName, newRule); err == nil {
						changeSet.ToUpdate = append(changeSet.ToUpdate, indexedRule)
					}
				} else {
					// Rule was disabled, treat it as a removal
					if indexedRule, err := am.convertCRDRule(crdName, oldRule); err == nil {
						changeSet.ToRemove = append(changeSet.ToRemove, indexedRule)
					}
				}
			}
		} else {
			// New rule
			if newRule.Enabled {
				if indexedRule, err := am.convertCRDRule(crdName, newRule); err == nil {
					changeSet.ToAdd = append(changeSet.ToAdd, indexedRule)
				}
			}
		}
	}

	// Find deletions
	for name, oldRule := range oldRules {
		if _, exists := newRules[name]; !exists {
			if indexedRule, err := am.convertCRDRule(crdName, oldRule); err == nil {
				changeSet.ToRemove = append(changeSet.ToRemove, indexedRule)
			}
		}
	}

	return changeSet
}

// applyIncrementalChanges applies rule changes to the kernel
func (am *AuditManagerV1) applyIncrementalChanges(changeSet *RuleChangeSet) error {
	// For now, we'll do a full reload since individual rule removal is complex
	// In a full implementation, you'd track kernel rule IDs and remove them individually
	if len(changeSet.ToRemove) > 0 || len(changeSet.ToUpdate) > 0 {
		return am.reloadAllRules()
	}

	// Add new rules
	for _, rule := range changeSet.ToAdd {
		if err := am.loadRuleIntoKernel(rule.Rule); err != nil {
			return fmt.Errorf("failed to add rule %s: %w", rule.ID, err)
		}
	}

	return nil
}

// reloadAllRules clears all kernel rules and reloads everything
func (am *AuditManagerV1) reloadAllRules() error {
	// Clear existing kernel rules
	if am.auditClient != nil {
		if _, err := am.auditClient.DeleteRules(); err != nil {
			logger.L().Warning("failed to clear existing audit rules", helpers.Error(err))
		}
	}

	// Skip hardcoded rules, only reload CRD rules (sorted by priority)
	var allIndexedRules []*IndexedRule
	for _, indexedRule := range am.ruleIndex {
		allIndexedRules = append(allIndexedRules, indexedRule)
	}

	// Sort by priority
	sort.Slice(allIndexedRules, func(i, j int) bool {
		if allIndexedRules[i].Priority == allIndexedRules[j].Priority {
			return allIndexedRules[i].ID < allIndexedRules[j].ID
		}
		return allIndexedRules[i].Priority < allIndexedRules[j].Priority
	})

	// Load CRD rules into kernel
	for _, indexedRule := range allIndexedRules {
		if err := am.loadRuleIntoKernel(indexedRule.Rule); err != nil {
			logger.L().Warning("failed to load CRD rule into kernel",
				helpers.Error(err),
				helpers.String("ruleID", indexedRule.ID))
		}
	}

	totalRules := len(am.loadedRules) + len(allIndexedRules)
	logger.L().Info("reloaded all audit rules into kernel", helpers.Int("count", totalRules))
	return nil
}

// updateRuleIndex updates the rule index with rules from a CRD
func (am *AuditManagerV1) updateRuleIndex(crdName string, auditRule *crd.LinuxAuditRule) {
	// Remove old rules for this CRD
	am.removeRulesBySource(crdName)

	// Add new rules
	var ruleIDs []string
	for _, ruleDef := range auditRule.Spec.Rules {
		if !ruleDef.Enabled {
			continue
		}

		indexedRule, err := am.convertCRDRule(crdName, ruleDef)
		if err != nil {
			logger.L().Warning("failed to convert CRD rule",
				helpers.Error(err),
				helpers.String("crdName", crdName),
				helpers.String("ruleName", ruleDef.Name))
			continue
		}

		am.ruleIndex[indexedRule.ID] = indexedRule
		ruleIDs = append(ruleIDs, indexedRule.ID)
	}

	am.rulesBySource[crdName] = ruleIDs
}

// removeRulesBySource removes rules from the index by source CRD
func (am *AuditManagerV1) removeRulesBySource(crdName string) []*IndexedRule {
	var removedRules []*IndexedRule

	if ruleIDs, exists := am.rulesBySource[crdName]; exists {
		for _, ruleID := range ruleIDs {
			if indexedRule, exists := am.ruleIndex[ruleID]; exists {
				removedRules = append(removedRules, indexedRule)
				delete(am.ruleIndex, ruleID)
			}
		}
		delete(am.rulesBySource, crdName)
	}

	return removedRules
}

// convertCRDRule converts a CRD rule definition to an IndexedRule
func (am *AuditManagerV1) convertCRDRule(crdName string, ruleDef crd.AuditRuleDefinition) (*IndexedRule, error) {
	// Convert structured rule to auditctl format
	auditctlRules, err := am.ruleConverter.ConvertRule(ruleDef)
	if err != nil {
		return nil, fmt.Errorf("failed to convert rule %s: %w", ruleDef.Name, err)
	}

	// For now, take the first rule (most rules convert to a single auditctl rule)
	if len(auditctlRules) == 0 {
		return nil, fmt.Errorf("no auditctl rules generated for rule %s", ruleDef.Name)
	}

	auditctlRule := auditctlRules[0]

	// Parse the auditctl rule
	auditRule, err := parseAuditRule(auditctlRule)
	if err != nil {
		return nil, fmt.Errorf("failed to parse generated auditctl rule for %s: %w", ruleDef.Name, err)
	}

	// Create indexed rule
	indexedRule := &IndexedRule{
		ID:          fmt.Sprintf("%s/%s", crdName, ruleDef.Name),
		Rule:        auditRule,
		SourceCRD:   crdName,
		SourceType:  "crd",
		Priority:    ruleDef.Priority,
		LastUpdated: time.Now(),
	}

	return indexedRule, nil
}

// rulesEqual compares two rule definitions for equality
func (am *AuditManagerV1) rulesEqual(rule1, rule2 crd.AuditRuleDefinition) bool {
	// This is a simplified comparison - in a full implementation you'd do deep comparison
	return rule1.Name == rule2.Name &&
		rule1.Description == rule2.Description &&
		rule1.Enabled == rule2.Enabled &&
		rule1.Priority == rule2.Priority &&
		rule1.RawRule == rule2.RawRule &&
		am.slicesEqual(rule1.Tags, rule2.Tags)
}

// slicesEqual compares two string slices for equality
func (am *AuditManagerV1) slicesEqual(a, b []string) bool {
	if len(a) != len(b) {
		return false
	}
	for i, v := range a {
		if v != b[i] {
			return false
		}
	}
	return true
}
