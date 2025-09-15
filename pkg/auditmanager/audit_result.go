package auditmanager

import (
	apitypes "github.com/armosec/armoapi-go/armotypes"
)

// AuditEvent represents the core audit event data without v1 dependency
type AuditEvent struct {
	AuditID     uint64
	MessageType string
	PID         uint32
	PPID        uint32
	UID         uint32
	GID         uint32
	EUID        uint32
	EGID        uint32
	Comm        string
	Exe         string
	Syscall     string
	Args        []string
	Success     bool
	Exit        int32
	Path        string
	Mode        uint32
	Operation   string
	Key         string
	RuleType    string
	Pod         string
	Namespace   string
	ContainerID string
	RawMessage  string
}

// AuditResult represents an audit event result that should be exported
// This follows the same pattern as MalwareResult
type AuditResult interface {
	// GetAuditEvent returns the underlying audit event
	GetAuditEvent() *AuditEvent

	// GetBaseRuntimeAlert returns the basic runtime alert information
	GetBaseRuntimeAlert() apitypes.BaseRuntimeAlert

	// GetRuntimeProcessDetails returns process details for the alert
	GetRuntimeProcessDetails() apitypes.ProcessTree

	// GetRuntimeAlertK8sDetails returns Kubernetes context for the alert
	GetRuntimeAlertK8sDetails() apitypes.RuntimeAlertK8sDetails

	// GetAlertType returns the type of audit alert
	GetAlertType() string
}

// AuditResultImpl implements AuditResult interface
type AuditResultImpl struct {
	auditEvent            *AuditEvent
	baseRuntimeAlert      apitypes.BaseRuntimeAlert
	runtimeProcessDetails apitypes.ProcessTree
	k8sDetails            apitypes.RuntimeAlertK8sDetails
	alertType             string
}

// NewAuditResult creates a new audit result from an audit event
func NewAuditResult(event *AuditEvent) *AuditResultImpl {
	return &AuditResultImpl{
		auditEvent: event,
		baseRuntimeAlert: apitypes.BaseRuntimeAlert{
			AlertName:      "Linux Audit Event",
			InfectedPID:    uint32(event.PID),
			FixSuggestions: "Review audit event details and investigate if this activity is expected",
			Severity:       determineSeverity(event),
		},
		runtimeProcessDetails: apitypes.ProcessTree{
			ProcessTree: apitypes.Process{
				PID:  uint32(event.PID),
				PPID: uint32(event.PPID),
				Comm: event.Comm,
				Path: event.Exe,
				Uid:  &event.UID,
				Gid:  &event.GID,
			},
		},
		k8sDetails: apitypes.RuntimeAlertK8sDetails{
			PodName:   event.Pod,
			Namespace: event.Namespace,
		},
		alertType: "RuntimeIncident",
	}
}

// GetAuditEvent returns the underlying audit event
func (ar *AuditResultImpl) GetAuditEvent() *AuditEvent {
	return ar.auditEvent
}

// GetBaseRuntimeAlert returns the basic runtime alert information
func (ar *AuditResultImpl) GetBaseRuntimeAlert() apitypes.BaseRuntimeAlert {
	return ar.baseRuntimeAlert
}

// GetRuntimeProcessDetails returns process details for the alert
func (ar *AuditResultImpl) GetRuntimeProcessDetails() apitypes.ProcessTree {
	return ar.runtimeProcessDetails
}

// GetRuntimeAlertK8sDetails returns Kubernetes context for the alert
func (ar *AuditResultImpl) GetRuntimeAlertK8sDetails() apitypes.RuntimeAlertK8sDetails {
	return ar.k8sDetails
}

// GetAlertType returns the type of audit alert
func (ar *AuditResultImpl) GetAlertType() string {
	return ar.alertType
}

// IsFileWatchEvent returns true if this is a file watch audit event
func (ae *AuditEvent) IsFileWatchEvent() bool {
	return ae.RuleType == "file_watch" || ae.Path != ""
}

// determineSeverity determines the severity based on audit event characteristics
func determineSeverity(event *AuditEvent) int {
	// Higher severity for privileged operations
	if event.UID == 0 { // root user
		return 8 // High severity
	}

	// Higher severity for sensitive file access
	if event.IsFileWatchEvent() {
		switch event.Path {
		case "/etc/passwd", "/etc/shadow", "/etc/sudoers":
			return 7 // Medium-high severity
		case "/etc/ssh/sshd_config":
			return 6 // Medium severity
		}
	}

	// Default severity for other audit events
	return 5 // Medium severity
}
