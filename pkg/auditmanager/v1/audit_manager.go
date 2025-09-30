package v1

import (
	"context"
	"fmt"
	"os"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/elastic/go-libaudit/v2"
	"github.com/elastic/go-libaudit/v2/auparse"
	"github.com/elastic/go-libaudit/v2/rule"
	"github.com/elastic/go-libaudit/v2/rule/flags"
	"github.com/hashicorp/golang-lru/v2/expirable"
	containercollection "github.com/inspektor-gadget/inspektor-gadget/pkg/container-collection"
	"github.com/inspektor-gadget/inspektor-gadget/pkg/types"
	"github.com/kubescape/go-logger"
	"github.com/kubescape/go-logger/helpers"
	"github.com/kubescape/node-agent/pkg/auditmanager"
	"github.com/kubescape/node-agent/pkg/auditmanager/crd"
	"github.com/kubescape/node-agent/pkg/config"
	"github.com/kubescape/node-agent/pkg/exporters"
	"github.com/kubescape/node-agent/pkg/processtree"
	"github.com/kubescape/node-agent/pkg/utils"
)

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

	// For kubernetes enrichment
	processTreeManager processtree.ProcessTreeManager

	// Kubernetes enrichment
	containerCollection *containercollection.ContainerCollection
	pidToMntnsCache     *expirable.LRU[uint32, uint64] // PID -> mount namespace ID cache

	// Message reassembly
	reassembler *libaudit.Reassembler // Aggregates related audit messages

	// Rule management
	loadedRules []*AuditRule // Hardcoded rules

	// CRD-based rule management
	crdRules      map[string]*crd.LinuxAuditRule // CRD name -> LinuxAuditRule CRD
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
func NewAuditManagerV1(config *config.Config, exporter *exporters.ExporterBus, processTreeManager processtree.ProcessTreeManager) (*AuditManagerV1, error) {
	if exporter == nil {
		return nil, fmt.Errorf("exporter cannot be nil")
	}
	if config == nil {
		return nil, fmt.Errorf("config cannot be nil")
	}

	// Create PID to mount namespace cache with 5-minute TTL and max 1000 entries
	pidToMntnsCache := expirable.NewLRU[uint32, uint64](1000, nil, 5*time.Minute)

	auditManager := &AuditManagerV1{
		enabled:             true,
		config:              config,
		eventChan:           make(chan *auditmanager.AuditEvent, 1000), // Buffered channel for events
		exporter:            exporter,
		processTreeManager:  processTreeManager,
		containerCollection: nil, // Will be set later via SetContainerCollection
		pidToMntnsCache:     pidToMntnsCache,
		crdRules:            make(map[string]*crd.LinuxAuditRule),
		ruleConverter:       crd.NewRuleConverter(),
		loadedRules:         nil, // Don't use hardcoded rules
		stats: auditmanager.AuditManagerStatus{
			IsRunning:    false,
			RulesLoaded:  0,
			EventsTotal:  0,
			EventsErrors: 0,
		},
	}

	// Initialize the reassembler with reasonable defaults
	// maxInFlight: 1000 concurrent event sequences
	// timeout: 5 seconds to wait for event completion
	stream := &AuditStream{manager: auditManager}
	reassembler, err := libaudit.NewReassembler(1000, 5*time.Second, stream)
	if err != nil {
		return nil, fmt.Errorf("failed to create audit reassembler: %w", err)
	}
	auditManager.reassembler = reassembler

	return auditManager, nil
}

// AuditStream implements the libaudit.Stream interface for handling reassembled audit events
type AuditStream struct {
	manager *AuditManagerV1
}

// ReassemblyComplete is called when a complete group of audit messages has been received
func (s *AuditStream) ReassemblyComplete(msgs []*auparse.AuditMessage) {
	logger.L().Debug("ReassemblyComplete called",
		helpers.Int("messageCount", len(msgs)))

	if len(msgs) == 0 {
		return
	}

	// Log the message types in the sequence
	var msgTypes []string
	var sequence uint32
	for _, msg := range msgs {
		msgTypes = append(msgTypes, msg.RecordType.String())
		sequence = msg.Sequence
	}

	logger.L().Debug("processing complete audit sequence",
		helpers.Int("sequence", int(sequence)),
		helpers.Interface("messageTypes", msgTypes))

	// Create aggregated event from the message sequence
	event := s.manager.parseAggregatedAuditMessages(msgs)
	if event != nil {
		s.manager.processAuditEvent(event)
	} else {
		logger.L().Warning("parseAggregatedAuditMessages returned nil event",
			helpers.Int("sequence", int(sequence)))
	}
}

// EventsLost is called when audit events are detected as lost
func (s *AuditStream) EventsLost(count int) {
	logger.L().Warning("audit events lost due to gaps in sequence numbers",
		helpers.Int("lostCount", count))
	// TODO: Add metric for lost events
}

// SetContainerCollection sets the container collection for Kubernetes enrichment
func (am *AuditManagerV1) SetContainerCollection(containerCollection *containercollection.ContainerCollection) {
	am.mutex.Lock()
	defer am.mutex.Unlock()
	am.containerCollection = containerCollection
}

// parseAggregatedAuditMessages creates an AuditEvent from a sequence of related audit messages
func (am *AuditManagerV1) parseAggregatedAuditMessages(msgs []*auparse.AuditMessage) *auditmanager.AuditEvent {
	if len(msgs) == 0 {
		logger.L().Debug("parseAggregatedAuditMessages: empty message list")
		return nil
	}

	logger.L().Debug("parseAggregatedAuditMessages: starting to parse",
		helpers.Int("messageCount", len(msgs)))

	// Find the primary message (usually SYSCALL, or first message if no SYSCALL)
	var primaryMsg *auparse.AuditMessage

	for _, msg := range msgs {
		if msg.RecordType == auparse.AUDIT_SYSCALL {
			primaryMsg = msg
			break
		}
	}

	// If no SYSCALL message, use the first message
	if primaryMsg == nil {
		primaryMsg = msgs[0]
	}

	// Create base event from primary message
	event := &auditmanager.AuditEvent{
		AuditID:   uint64(primaryMsg.Sequence),
		Type:      primaryMsg.RecordType,
		Timestamp: types.Time(primaryMsg.Timestamp.UnixNano()),
		Sequence:  primaryMsg.Sequence,
		Success:   true, // Default to success, will be overridden if "success" field is present
	}

	// Extract keys from the message sequence (prioritize SYSCALL messages)
	event.Keys = am.extractKeysFromMessageSequence(msgs)

	// Merge data from all messages in the sequence
	allData := make(map[string]string)
	for _, msg := range msgs {
		if data, err := msg.Data(); err == nil {
			for k, v := range data {
				allData[k] = v // Later messages override earlier ones
			}
		}
	}
	event.Data = allData

	// Set rule type based on event type
	am.setRuleType(event)

	// Extract all fields using merged data
	am.extractProcessInfo(event, allData)
	am.extractSyscallInfo(event, allData)
	am.extractFileInfo(event, allData)
	am.extractNetworkInfo(event, allData)
	am.extractCommandInfo(event, allData)
	am.extractSecurityInfo(event, allData)

	// Store raw message from primary message for debugging
	event.RawMessage = primaryMsg.RawData

	// Enrich with Kubernetes context
	am.enrichWithKubernetesContext(event)

	return event
}

// extractKeysFromMessageSequence extracts all audit rule keys/tags from a sequence of messages
func (am *AuditManagerV1) extractKeysFromMessageSequence(msgs []*auparse.AuditMessage) []string {
	// Priority 1: SYSCALL message (most reliable for keys)
	for _, msg := range msgs {
		if msg.RecordType == auparse.AUDIT_SYSCALL {
			// Use the proper Tags() method to get all keys
			if tags, err := msg.Tags(); err == nil && len(tags) > 0 {
				return tags
			}
		}
	}

	// Priority 2: PATH message (for file watch rules)
	for _, msg := range msgs {
		if msg.RecordType == auparse.AUDIT_PATH {
			// Use the proper Tags() method to get all keys
			if tags, err := msg.Tags(); err == nil && len(tags) > 0 {
				return tags
			}
		}
	}

	// Priority 3: Any message with keys
	for _, msg := range msgs {
		// Use the proper Tags() method to get all keys
		if tags, err := msg.Tags(); err == nil && len(tags) > 0 {
			return tags
		}
	}

	return []string{}
}

// setRuleType sets the rule type based on the audit event type
func (am *AuditManagerV1) setRuleType(event *auditmanager.AuditEvent) {
	switch event.Type {
	case auparse.AUDIT_SYSCALL:
		event.RuleType = "syscall"
	case auparse.AUDIT_PATH:
		event.RuleType = "file_watch"
	case auparse.AUDIT_SOCKADDR:
		event.RuleType = "network"
	case auparse.AUDIT_EXECVE:
		event.RuleType = "process"
	case auparse.AUDIT_USER_CMD:
		event.RuleType = "user"
	case auparse.AUDIT_NETFILTER_PKT:
		event.RuleType = "netfilter"
	case auparse.AUDIT_MAC_STATUS:
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

	// Load all rules at startup
	if err := am.loadAllRules(); err != nil {
		logger.L().Warning("failed to load initial rules at startup", helpers.Error(err))
	}

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
func (am *AuditManagerV1) loadRuleIntoKernel(auditRule *AuditRule, auditClient *libaudit.AuditClient) error {
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
	err = auditClient.AddRule(wireFormat)
	if err != nil {
		return fmt.Errorf("failed to add audit rule to kernel '%s': %w", ruleStr, err)
	}

	logger.L().Info("successfully loaded audit rule into kernel",
		helpers.String("rule", ruleStr),
		helpers.String("description", auditRule.GetRuleDescription()))

	return nil
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
	if uid, err := strconv.ParseUint(data["auid"], 10, 32); err == nil {
		event.AUID = uint32(uid)
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

	// Parse success field - auparse transforms "success=yes/no" to "result=success/fail"
	if resultStr := data["result"]; resultStr != "" {
		event.Success = (resultStr == "success")
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
	// Keys are now extracted via extractKeysFromMessageSequence, not from data["key"]
	event.SELinuxContext = data["subj"]      // SELinux subject context
	event.AppArmorProfile = data["apparmor"] // AppArmor profile
	event.Capabilities = data["cap_fp"]      // Process capabilities
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

			// Filter out non-audit messages (type < 1000)
			if uint16(rawMessage.Type) < 1000 {
				logger.L().Debug("skipping non-audit message",
					helpers.String("type", rawMessage.Type.String()),
					helpers.Int("typeNum", int(rawMessage.Type)))
				continue
			}

			// Debug: Log what we're about to parse
			logger.L().Debug("received raw audit message for reassembler",
				helpers.String("type", rawMessage.Type.String()),
				helpers.Int("typeNum", int(rawMessage.Type)),
				helpers.Int("dataLen", len(rawMessage.Data)),
				helpers.String("rawData", string(rawMessage.Data)))

			// Feed the raw message to the reassembler
			// The reassembler will aggregate related messages and call our Stream interface
			if err := am.reassembler.Push(rawMessage.Type, rawMessage.Data); err != nil {
				logger.L().Warning("failed to push audit message to reassembler",
					helpers.Error(err),
					helpers.String("type", rawMessage.Type.String()),
					helpers.Int("typeNum", int(rawMessage.Type)),
					helpers.Int("dataLen", len(rawMessage.Data)),
					helpers.String("rawData", string(rawMessage.Data)))
				am.stats.EventsErrors++
				continue
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
	// Always export rule-based events (events with keys)
	if len(event.Keys) > 0 {
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
		// Header information
		AuditID:   event.AuditID,
		Timestamp: event.Timestamp, // FIXED: Copy the timestamp!
		Sequence:  event.Sequence,
		Type:      event.Type,

		// Process information
		PID:       event.PID,
		PPID:      event.PPID,
		AUID:      event.AUID,
		UID:       event.UID,
		GID:       event.GID,
		EUID:      event.EUID,
		EGID:      event.EGID,
		SUID:      event.SUID,
		SGID:      event.SGID,
		FSUID:     event.FSUID,
		FSGID:     event.FSGID,
		Comm:      event.Comm,
		Exe:       event.Exe,
		CWD:       event.CWD,
		TTY:       event.TTY,
		ProcTitle: event.ProcTitle,
		SessionID: event.SessionID,
		LoginUID:  event.LoginUID,

		// Syscall information
		Syscall:    event.Syscall,
		SyscallNum: event.SyscallNum,
		Arch:       event.Arch,
		Args:       event.Args,
		Success:    event.Success,
		Exit:       event.Exit,
		ErrorCode:  event.ErrorCode,

		// File information
		Path:      event.Path,
		Mode:      event.Mode,
		DevMajor:  event.DevMajor,
		DevMinor:  event.DevMinor,
		Inode:     event.Inode,
		Operation: event.Operation,

		// Network information
		SockAddr:   event.SockAddr,
		SockFamily: event.SockFamily,
		SockPort:   event.SockPort,

		// Security information
		Keys:            event.Keys,
		Tags:            event.Tags,
		RuleType:        event.RuleType,
		SELinuxContext:  event.SELinuxContext,
		AppArmorProfile: event.AppArmorProfile,
		Capabilities:    event.Capabilities,

		// Kubernetes context
		Pod:         event.Pod,
		Namespace:   event.Namespace,
		ContainerID: event.ContainerID,

		// Raw data
		RawMessage: event.RawMessage,
		Data:       event.Data,
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

	// Store the CRD
	am.crdRules[crdName] = auditRule

	// Always do a full reload - simple and eventually consistent
	if err := am.loadAllRules(); err != nil {
		logger.L().Error("failed to load all rules after CRD update", helpers.Error(err))
		return fmt.Errorf("failed to load all rules: %w", err)
	}

	logger.L().Info("successfully updated audit rules from CRD",
		helpers.String("crdName", crdName),
		helpers.Int("totalRules", len(auditRule.Spec.Rules)))

	return nil
}

// RemoveRules removes all rules associated with a CRD
func (am *AuditManagerV1) RemoveRules(ctx context.Context, crdName string) error {
	am.mutex.Lock()
	defer am.mutex.Unlock()

	logger.L().Info("removing audit rules", helpers.String("crdName", crdName))

	// Remove from CRD cache
	delete(am.crdRules, crdName)

	// Always do a full reload - simple and eventually consistent
	if err := am.loadAllRules(); err != nil {
		logger.L().Error("failed to load all rules after CRD removal", helpers.Error(err))
		return fmt.Errorf("failed to load all rules: %w", err)
	}

	logger.L().Info("successfully removed audit rules",
		helpers.String("crdName", crdName))

	return nil
}

// ListActiveRules returns information about currently active rules
func (am *AuditManagerV1) ListActiveRules() []auditmanager.ActiveRule {
	am.mutex.RLock()
	defer am.mutex.RUnlock()

	var activeRules []auditmanager.ActiveRule

	// Collect all rules from all CRDs
	for crdName, auditRule := range am.crdRules {
		for _, ruleDef := range auditRule.Spec.Rules {
			if !ruleDef.Enabled {
				continue
			}

			// Convert to auditctl format to get the rule description
			auditctlRules, err := am.ruleConverter.ConvertRule(ruleDef)
			if err != nil {
				logger.L().Warning("failed to convert rule for listing",
					helpers.Error(err),
					helpers.String("crdName", crdName),
					helpers.String("ruleName", ruleDef.Name))
				continue
			}

			for i, auditctlRule := range auditctlRules {
				parsedRule, err := parseAuditRule(auditctlRule)
				if err != nil {
					logger.L().Warning("failed to parse rule for listing",
						helpers.Error(err),
						helpers.String("auditctlRule", auditctlRule))
					continue
				}

				ruleID := fmt.Sprintf("%s/%s", crdName, ruleDef.Name)
				if len(auditctlRules) > 1 {
					ruleID = fmt.Sprintf("%s/%s[%d]", crdName, ruleDef.Name, i)
				}

				activeRule := auditmanager.ActiveRule{
					ID:          ruleID,
					Name:        parsedRule.GetRuleDescription(),
					Source:      fmt.Sprintf("crd:%s", crdName),
					SourceCRD:   crdName,
					Status:      "active",
					RuleType:    parsedRule.RuleType,
					Priority:    ruleDef.Priority,
					Keys:        parsedRule.Keys,
					Description: parsedRule.GetRuleDescription(),
					LastUpdated: time.Now(),
					ErrorMsg:    "",
				}
				activeRules = append(activeRules, activeRule)
			}
		}
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

// loadAllRules is the simplified rule loading process
// This function:
// 1. Deletes all current rules in the kernel
// 2. Gets all rules from all CRDs (that are enabled)
// 3. Orders them by priority (those without priority go to the end)
// 4. Loads the rules to the kernel in order
func (am *AuditManagerV1) loadAllRules() error {
	logger.L().Info("starting loadAllRules process")

	auditClient, err := libaudit.NewAuditClient(nil)
	if err != nil || auditClient == nil {
		return fmt.Errorf("failed to create audit client in loadAllRules: %w", err)
	}
	defer auditClient.Close()

	// Step 1: Delete all current rules in the kernel
	deletedCount, err := auditClient.DeleteRules()
	if err != nil {
		logger.L().Warning("failed to clear existing audit rules", helpers.Error(err))
	} else {
		logger.L().Info("cleared existing audit rules", helpers.Int("deletedCount", deletedCount))
	}

	// Step 2: Collect all enabled rules from all CRDs
	type RuleWithPriority struct {
		Rule     *AuditRule
		Priority int
		CRDName  string
		RuleName string
	}

	var allRules []RuleWithPriority

	for crdName, auditRule := range am.crdRules {
		for _, ruleDef := range auditRule.Spec.Rules {
			if !ruleDef.Enabled {
				continue
			}

			// Convert CRD rule to auditctl format
			auditctlRules, err := am.ruleConverter.ConvertRule(ruleDef)
			if err != nil {
				logger.L().Warning("failed to convert CRD rule",
					helpers.Error(err),
					helpers.String("crdName", crdName),
					helpers.String("ruleName", ruleDef.Name))
				continue
			}

			// Parse each generated auditctl rule
			for _, auditctlRule := range auditctlRules {
				parsedRule, err := parseAuditRule(auditctlRule)
				if err != nil {
					logger.L().Warning("failed to parse generated auditctl rule",
						helpers.Error(err),
						helpers.String("auditctlRule", auditctlRule),
						helpers.String("crdName", crdName),
						helpers.String("ruleName", ruleDef.Name))
					continue
				}

				allRules = append(allRules, RuleWithPriority{
					Rule:     parsedRule,
					Priority: ruleDef.Priority,
					CRDName:  crdName,
					RuleName: ruleDef.Name,
				})
			}
		}
	}

	// Step 3: Order rules by priority (those without priority go to the end)
	sort.Slice(allRules, func(i, j int) bool {
		// Rules with priority 0 are treated as "no priority" and go to the end
		priI := allRules[i].Priority
		priJ := allRules[j].Priority

		// If both have no priority (0), sort by CRD name and rule name
		if priI == 0 && priJ == 0 {
			if allRules[i].CRDName == allRules[j].CRDName {
				return allRules[i].RuleName < allRules[j].RuleName
			}
			return allRules[i].CRDName < allRules[j].CRDName
		}

		// If only one has no priority, the one with priority comes first
		if priI == 0 {
			return false
		}
		if priJ == 0 {
			return true
		}

		// Both have priority, sort by priority, then by CRD name and rule name
		if priI == priJ {
			if allRules[i].CRDName == allRules[j].CRDName {
				return allRules[i].RuleName < allRules[j].RuleName
			}
			return allRules[i].CRDName < allRules[j].CRDName
		}
		return priI < priJ
	})

	// Step 4: Load rules to the kernel in order
	successCount := 0
	for _, ruleWithPriority := range allRules {
		if err := am.loadRuleIntoKernel(ruleWithPriority.Rule, auditClient); err != nil {
			logger.L().Warning("failed to load rule into kernel",
				helpers.Error(err),
				helpers.String("crdName", ruleWithPriority.CRDName),
				helpers.String("ruleName", ruleWithPriority.RuleName),
				helpers.String("rule", ruleWithPriority.Rule.RawRule))
		} else {
			successCount++
		}
	}

	logger.L().Info("completed loadAllRules process",
		helpers.Int("totalRules", len(allRules)),
		helpers.Int("successCount", successCount),
		helpers.Int("failedCount", len(allRules)-successCount))

	return nil
}

// getMountNamespaceForPID gets the mount namespace ID for a given PID with caching
func (am *AuditManagerV1) getMountNamespaceForPID(pid uint32) (uint64, error) {
	// Check cache first
	if mntns, ok := am.pidToMntnsCache.Get(pid); ok {
		return mntns, nil
	}

	// Read mount namespace from /proc/{pid}/ns/mnt
	nsPath := fmt.Sprintf("/proc/%d/ns/mnt", pid)
	linkTarget, err := os.Readlink(nsPath)
	if err != nil {
		return 0, fmt.Errorf("failed to read mount namespace for PID %d: %w", pid, err)
	}

	// Parse namespace ID from link target (format: "mnt:[4026531840]")
	var mntns uint64
	if n, err := fmt.Sscanf(linkTarget, "mnt:[%d]", &mntns); err != nil || n != 1 {
		return 0, fmt.Errorf("failed to parse mount namespace from %s", linkTarget)
	}

	// Cache the result
	am.pidToMntnsCache.Add(pid, mntns)

	return mntns, nil
}

// enrichWithKubernetesContext enriches audit events with Kubernetes context information
func (am *AuditManagerV1) enrichWithKubernetesContext(event *auditmanager.AuditEvent) {

	// Get container ID from process tree manager
	containerID, err := am.processTreeManager.GetContainerIDForPid(event.PID)
	if err != nil {
		logger.L().Debug("failed to get container ID from process tree manager",
			helpers.Int("pid", int(event.PID)),
			helpers.Error(err))
		return
	}

	// Skip if no PID or no container collection available
	if event.PID == 0 || containerID == "" {
		logger.L().Debug("skipping Kubernetes enrichment",
			helpers.String("reason", "no PID or no container ID"),
			helpers.Int("pid", int(event.PID)),
			helpers.String("containerID", containerID))
		return
	}

	// Lookup container by mount namespace
	container := am.containerCollection.GetContainer(containerID)
	if container == nil {
		// Process is not in a tracked container - this is normal for host processes
		return
	}

	// Enrich event with Kubernetes context
	event.Pod = container.K8s.PodName
	event.Namespace = container.K8s.Namespace
	event.ContainerID = container.Runtime.ContainerID
}
