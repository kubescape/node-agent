package auditmanager

import (
	"context"

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
