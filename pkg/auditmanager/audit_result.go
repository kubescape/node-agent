package auditmanager

import (
	apitypes "github.com/armosec/armoapi-go/armotypes"
	"github.com/elastic/go-libaudit/v2/auparse"
	"github.com/inspektor-gadget/inspektor-gadget/pkg/types"
)

// AuditEvent represents the core audit event data without v1 dependency
type AuditEvent struct {
	// Header information
	AuditID   uint64
	Timestamp types.Time
	Sequence  uint32
	Type      auparse.AuditMessageType

	// Process information
	PID       uint32
	PPID      uint32
	AUID      uint32 // Audit User ID (original user who logged in)
	UID       uint32 // Real User ID (who owns the process)
	GID       uint32
	EUID      uint32 // Effective User ID (current privileges)
	EGID      uint32
	SUID      uint32 // Saved UID
	SGID      uint32 // Saved GID
	FSUID     uint32 // Filesystem UID
	FSGID     uint32 // Filesystem GID
	Comm      string
	Exe       string
	CWD       string // Current working directory
	TTY       string // Terminal device
	ProcTitle string // Decoded process title (command line)
	SessionID uint32 // Audit session ID
	LoginUID  uint32 // Login user ID

	// Syscall information
	Syscall    string
	SyscallNum int32  // Raw syscall number
	Arch       string // Architecture (e.g., b64)
	Args       []string
	Success    bool
	Exit       int32
	ErrorCode  string // Named error code (e.g., ENOENT)

	// File information
	Path      string
	Mode      uint32
	DevMajor  uint32 // Device major number
	DevMinor  uint32 // Device minor number
	Inode     uint64 // Inode number
	Operation string

	// Network information
	SockAddr   map[string]string // Socket address details
	SockFamily string            // Socket family (e.g., unix, inet)
	SockPort   uint32            // Socket port number

	// Security information
	Keys            []string // Multiple keys/tags from the audit rule
	Tags            []string // All audit rule tags
	RuleType        string
	SELinuxContext  string // SELinux security context
	AppArmorProfile string // AppArmor profile
	Capabilities    string // Process capabilities

	// Kubernetes context
	Pod         string
	Namespace   string
	ContainerID string

	// Raw data
	RawMessage string            // Original audit message
	Data       map[string]string // All parsed key-value pairs
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
			InfectedPID:    event.PID,
			FixSuggestions: "Review audit event details and investigate if this activity is expected",
			Severity:       determineSeverity(event),
		},
		runtimeProcessDetails: apitypes.ProcessTree{
			ProcessTree: apitypes.Process{
				PID:  event.PID,
				PPID: event.PPID,
				Comm: event.Comm,
				Path: event.Exe,
				Uid:  &event.EUID,
				Gid:  &event.EGID,
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
	if event.EUID == 0 { // root user
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
