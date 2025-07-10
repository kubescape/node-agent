package containerwatcher

import (
	"github.com/kubescape/node-agent/pkg/applicationprofilemanager"
	"github.com/kubescape/node-agent/pkg/dnsmanager"
	"github.com/kubescape/node-agent/pkg/malwaremanager"
	"github.com/kubescape/node-agent/pkg/metricsmanager"
	"github.com/kubescape/node-agent/pkg/networkmanager"
	"github.com/kubescape/node-agent/pkg/networkstream"
	"github.com/kubescape/node-agent/pkg/rulemanager"
	"github.com/kubescape/node-agent/pkg/utils"
)

// Manager represents a component that can receive events
type Manager interface {
	ReportEvent(eventType utils.EventType, event utils.K8sEvent)
}

// ManagerAdapter adapts different manager interfaces to the common Manager interface
type ManagerAdapter struct {
	reportEventFunc func(eventType utils.EventType, event utils.K8sEvent)
}

// NewManagerAdapter creates a new manager adapter
func NewManagerAdapter(reportEventFunc func(eventType utils.EventType, event utils.K8sEvent)) *ManagerAdapter {
	return &ManagerAdapter{
		reportEventFunc: reportEventFunc,
	}
}

// ReportEvent implements the Manager interface
func (ma *ManagerAdapter) ReportEvent(eventType utils.EventType, event utils.K8sEvent) {
	ma.reportEventFunc(eventType, event)
}

// EventHandlerFactory manages the mapping of event types to their managers
type EventHandlerFactory struct {
	handlers map[utils.EventType][]Manager
}

// NewEventHandlerFactory creates a new event handler factory
func NewEventHandlerFactory(
	applicationProfileManager applicationprofilemanager.ApplicationProfileManagerClient,
	networkManager networkmanager.NetworkManagerClient,
	dnsManager dnsmanager.DNSManagerClient,
	ruleManager rulemanager.RuleManagerClient,
	malwareManager malwaremanager.MalwareManagerClient,
	networkStreamClient networkstream.NetworkStreamClient,
	metrics metricsmanager.MetricsManager,
) *EventHandlerFactory {
	factory := &EventHandlerFactory{
		handlers: make(map[utils.EventType][]Manager),
	}

	// Create adapters for managers that don't implement the Manager interface directly
	appProfileAdapter := NewManagerAdapter(func(eventType utils.EventType, event utils.K8sEvent) {
		// Application profile manager has specific methods for different event types
		// This would need to be implemented based on the specific event types
	})

	networkAdapter := NewManagerAdapter(func(eventType utils.EventType, event utils.K8sEvent) {
		// Network manager has specific methods for different event types
		// This would need to be implemented based on the specific event types
	})

	dnsAdapter := NewManagerAdapter(func(eventType utils.EventType, event utils.K8sEvent) {
		// DNS manager has specific methods for different event types
		// This would need to be implemented based on the specific event types
	})

	metricsAdapter := NewManagerAdapter(func(eventType utils.EventType, event utils.K8sEvent) {
		metrics.ReportEvent(eventType)
	})

	// Register managers for each event type
	factory.registerHandlers(
		appProfileAdapter,
		networkAdapter,
		dnsAdapter,
		ruleManager,
		malwareManager,
		networkStreamClient,
		metricsAdapter,
	)

	return factory
}

// GetManagers returns the managers for a specific event type
func (ehf *EventHandlerFactory) GetManagers(eventType utils.EventType) ([]Manager, bool) {
	managers, exists := ehf.handlers[eventType]
	return managers, exists
}

// ProcessEvent processes an enriched event
func (ehf *EventHandlerFactory) ProcessEvent(enrichedEvent EnrichedEvent) {
	managers, exists := ehf.handlers[enrichedEvent.EventType]
	if !exists {
		return
	}

	// Loop over managers and report the event
	for _, manager := range managers {
		manager.ReportEvent(enrichedEvent.EventType, enrichedEvent.Event)
	}
}

// registerHandlers registers all event type managers
func (ehf *EventHandlerFactory) registerHandlers(
	applicationProfileManager *ManagerAdapter,
	networkManager *ManagerAdapter,
	dnsManager *ManagerAdapter,
	ruleManager rulemanager.RuleManagerClient,
	malwareManager malwaremanager.MalwareManagerClient,
	networkStreamClient networkstream.NetworkStreamClient,
	metrics *ManagerAdapter,
) {
	// Capabilities events
	ehf.handlers[utils.CapabilitiesEventType] = []Manager{applicationProfileManager, ruleManager, metrics}

	// Exec events
	ehf.handlers[utils.ExecveEventType] = []Manager{applicationProfileManager, ruleManager, malwareManager, metrics}

	// Open events
	ehf.handlers[utils.OpenEventType] = []Manager{applicationProfileManager, ruleManager, malwareManager, metrics}

	// Network events
	ehf.handlers[utils.NetworkEventType] = []Manager{networkManager, ruleManager, networkStreamClient, metrics}

	// DNS events
	ehf.handlers[utils.DnsEventType] = []Manager{dnsManager, ruleManager, networkStreamClient, metrics}

	// RandomX events
	ehf.handlers[utils.RandomXEventType] = []Manager{ruleManager, metrics}

	// Symlink events
	ehf.handlers[utils.SymlinkEventType] = []Manager{applicationProfileManager, ruleManager, metrics}

	// Hardlink events
	ehf.handlers[utils.HardlinkEventType] = []Manager{applicationProfileManager, ruleManager, metrics}

	// SSH events
	ehf.handlers[utils.SSHEventType] = []Manager{ruleManager, metrics}

	// HTTP events
	ehf.handlers[utils.HTTPEventType] = []Manager{applicationProfileManager, ruleManager, metrics}

	// Ptrace events
	ehf.handlers[utils.PtraceEventType] = []Manager{ruleManager}

	// IoUring events
	ehf.handlers[utils.IoUringEventType] = []Manager{ruleManager}

	// Fork events
	ehf.handlers[utils.ForkEventType] = []Manager{ruleManager, metrics}

	// Exit events
	ehf.handlers[utils.ExitEventType] = []Manager{ruleManager, metrics}
}
