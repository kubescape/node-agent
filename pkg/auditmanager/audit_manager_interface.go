package auditmanager

import (
	"context"
	"time"

	"github.com/kubescape/node-agent/pkg/utils"
)

//go:generate mockgen -source=audit_manager_interface.go -destination=audit_manager_mock.go

// AuditManagerClient defines the interface for managing Linux audit events
type AuditManagerClient interface {
	// Start begins the audit manager and starts listening for audit events
	Start(ctx context.Context) error

	// Stop gracefully shuts down the audit manager
	Stop() error

	// ReportEvent is called when an audit event should be processed
	// This follows the pattern used by other managers in the node-agent
	ReportEvent(eventType utils.EventType, event utils.K8sEvent, containerID string, comm string)

	// GetStatus returns the current status of the audit manager
	GetStatus() AuditManagerStatus

	// CRD-based rule management methods
	// UpdateRules processes a new or updated AuditRule CRD
	UpdateRules(ctx context.Context, crdName string, crdRules interface{}) error

	// RemoveRules removes all rules associated with a CRD
	RemoveRules(ctx context.Context, crdName string) error

	// ListActiveRules returns information about currently active rules
	ListActiveRules() []ActiveRule

	// ValidateRules validates rule definitions without applying them
	ValidateRules(crdRules interface{}) []RuleValidationError
}

// AuditManagerStatus represents the current state of the audit manager
type AuditManagerStatus struct {
	IsRunning        bool
	RulesLoaded      int
	EventsTotal      uint64
	EventsErrors     uint64
	EventsDropped    uint64 // Events dropped due to channel full
	EventsBlocked    uint64 // Events that experienced backpressure blocking
	BackpressureTime uint64 // Total milliseconds spent in backpressure
}

// ActiveRule represents information about a currently active audit rule
type ActiveRule struct {
	ID          string    // Unique rule identifier (crd-name/rule-name or hardcoded-rule-name)
	Name        string    // Human-readable rule name
	Source      string    // Source of the rule: "hardcoded", "crd:<crd-name>"
	SourceCRD   string    // Name of the CRD if source is CRD
	Status      string    // Status: "active", "failed", "disabled"
	RuleType    string    // Type: "file_watch", "syscall", "network", "process"
	Priority    int       // Rule priority for ordering
	Key         string    // Audit key for event identification
	Description string    // Human-readable description
	LastUpdated time.Time // When the rule was last updated
	ErrorMsg    string    // Error message if status is "failed"
}

// RuleValidationError represents a validation error for a rule
type RuleValidationError struct {
	RuleName string // Name of the rule that failed validation
	Field    string // Field that caused the error
	Error    string // Error message
}

// NewAuditManagerMock creates a mock audit manager for testing/disabled state
func NewAuditManagerMock() AuditManagerClient {
	return &AuditManagerMock{}
}

// AuditManagerMock is a no-op implementation of AuditManagerClient
type AuditManagerMock struct{}

func (m *AuditManagerMock) Start(ctx context.Context) error {
	return nil
}

func (m *AuditManagerMock) Stop() error {
	return nil
}

func (m *AuditManagerMock) ReportEvent(eventType utils.EventType, event utils.K8sEvent, containerID string, comm string) {
	// No-op
}

func (m *AuditManagerMock) GetStatus() AuditManagerStatus {
	return AuditManagerStatus{
		IsRunning:    false,
		RulesLoaded:  0,
		EventsTotal:  0,
		EventsErrors: 0,
	}
}

func (m *AuditManagerMock) UpdateRules(ctx context.Context, crdName string, crdRules interface{}) error {
	return nil
}

func (m *AuditManagerMock) RemoveRules(ctx context.Context, crdName string) error {
	return nil
}

func (m *AuditManagerMock) ListActiveRules() []ActiveRule {
	return []ActiveRule{}
}

func (m *AuditManagerMock) ValidateRules(crdRules interface{}) []RuleValidationError {
	return []RuleValidationError{}
}
