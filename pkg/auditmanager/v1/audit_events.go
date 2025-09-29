package v1

import (
	"time"

	"github.com/elastic/go-libaudit/v2/auparse"
	"github.com/inspektor-gadget/inspektor-gadget/pkg/types"
	"github.com/kubescape/node-agent/pkg/utils"
)

// AuditEvent represents a Linux audit event that implements the K8sEvent interface
type AuditEvent struct {
	// Basic event information
	Timestamp types.Time               `json:"timestamp"`
	AuditID   uint64                   `json:"auditId"`
	Type      auparse.AuditMessageType `json:"type"`

	// Process information
	PID  uint32 `json:"pid"`
	PPID uint32 `json:"ppid"`
	UID  uint32 `json:"uid"`
	GID  uint32 `json:"gid"`
	EUID uint32 `json:"euid"`
	EGID uint32 `json:"egid"`
	Comm string `json:"comm"`
	Exe  string `json:"exe"`

	// Syscall information (for syscall events)
	Syscall string   `json:"syscall,omitempty"`
	Args    []string `json:"args,omitempty"`
	Success bool     `json:"success"`
	Exit    int32    `json:"exit"`

	// File information (for file watch events)
	Path      string `json:"path,omitempty"`
	Mode      uint32 `json:"mode,omitempty"`
	Operation string `json:"operation,omitempty"` // read, write, attribute, etc.

	// Audit rule information
	Keys     []string `json:"keys,omitempty"`     // The -k keys from audit rule (multiple tags)
	RuleType string   `json:"ruleType,omitempty"` // "file_watch" or "syscall"

	// Kubernetes context (will be enriched)
	Pod         string `json:"pod,omitempty"`
	Namespace   string `json:"namespace,omitempty"`
	ContainerID string `json:"containerId,omitempty"`

	// Raw audit message for debugging
	RawMessage string `json:"rawMessage,omitempty"`
}

// GetPod implements the K8sEvent interface
func (ae *AuditEvent) GetPod() string {
	return ae.Pod
}

// GetNamespace implements the K8sEvent interface
func (ae *AuditEvent) GetNamespace() string {
	return ae.Namespace
}

// GetTimestamp implements the K8sEvent interface
func (ae *AuditEvent) GetTimestamp() types.Time {
	return ae.Timestamp
}

// GetEventType returns the audit event type
func (ae *AuditEvent) GetEventType() utils.EventType {
	return utils.AuditEventType
}

// GetProcessInfo returns process information in a structured format
func (ae *AuditEvent) GetProcessInfo() ProcessInfo {
	return ProcessInfo{
		PID:  ae.PID,
		PPID: ae.PPID,
		UID:  ae.UID,
		GID:  ae.GID,
		EUID: ae.EUID,
		EGID: ae.EGID,
		Comm: ae.Comm,
		Exe:  ae.Exe,
	}
}

// ProcessInfo contains process-related information from audit events
type ProcessInfo struct {
	PID  uint32 `json:"pid"`
	PPID uint32 `json:"ppid"`
	UID  uint32 `json:"uid"`
	GID  uint32 `json:"gid"`
	EUID uint32 `json:"euid"`
	EGID uint32 `json:"egid"`
	Comm string `json:"comm"`
	Exe  string `json:"exe"`
}

// NewAuditEvent creates a new audit event with current timestamp
func NewAuditEvent(auditID uint64, msgType auparse.AuditMessageType) *AuditEvent {
	return &AuditEvent{
		Timestamp: types.Time(time.Now().UnixNano()),
		AuditID:   auditID,
		Type:      msgType,
		Success:   true, // Default to success, will be overridden if needed
	}
}

// IsFileWatchEvent returns true if this is a file watch audit event
func (ae *AuditEvent) IsFileWatchEvent() bool {
	return ae.RuleType == "file_watch" || ae.Path != ""
}

// IsSyscallEvent returns true if this is a syscall audit event
func (ae *AuditEvent) IsSyscallEvent() bool {
	return ae.RuleType == "syscall" || ae.Syscall != ""
}

// SetKubernetesContext sets the Kubernetes context for the event
func (ae *AuditEvent) SetKubernetesContext(pod, namespace, containerID string) {
	ae.Pod = pod
	ae.Namespace = namespace
	ae.ContainerID = containerID
}
