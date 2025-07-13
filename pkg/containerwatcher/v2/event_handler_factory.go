package containerwatcher

import (
	"fmt"

	mapset "github.com/deckarep/golang-set/v2"
	"github.com/goradd/maps"
	"github.com/kubescape/go-logger"
	"github.com/kubescape/go-logger/helpers"
	"github.com/kubescape/node-agent/pkg/applicationprofilemanager"
	"github.com/kubescape/node-agent/pkg/containerwatcher"
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
	handlers                 map[utils.EventType][]Manager
	thirdPartyEventReceivers *maps.SafeMap[utils.EventType, mapset.Set[containerwatcher.EventReceiver]]
	thirdPartyEnricher       containerwatcher.TaskBasedEnricher
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
	thirdPartyEventReceivers *maps.SafeMap[utils.EventType, mapset.Set[containerwatcher.EventReceiver]],
	thirdPartyEnricher containerwatcher.TaskBasedEnricher,
) *EventHandlerFactory {
	factory := &EventHandlerFactory{
		handlers:                 make(map[utils.EventType][]Manager),
		thirdPartyEventReceivers: thirdPartyEventReceivers,
		thirdPartyEnricher:       thirdPartyEnricher,
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
	// For now, process directly without third party enrichment
	// TODO: Implement proper third party enrichment support
	ehf.processEventWithManagers(enrichedEvent.EventType, enrichedEvent.Event)
}

// processEventWithManagers processes an event with the registered managers and third party receivers
func (ehf *EventHandlerFactory) processEventWithManagers(eventType utils.EventType, event utils.K8sEvent) {
	// Process with registered managers
	managers, exists := ehf.handlers[eventType]
	if exists {
		for _, manager := range managers {
			logger.L().Info("Processing event with manager",
				helpers.String("event", string(eventType)),
				helpers.String("manager", fmt.Sprintf("%T", manager)))
			manager.ReportEvent(eventType, event)
		}
	}

	// Report to third party event receivers
	ehf.reportEventToThirdPartyTracers(eventType, event)
}

// reportEventToThirdPartyTracers reports events to third party event receivers
func (ehf *EventHandlerFactory) reportEventToThirdPartyTracers(eventType utils.EventType, event utils.K8sEvent) {
	if ehf.thirdPartyEventReceivers != nil && ehf.thirdPartyEventReceivers.Has(eventType) {
		for receiver := range ehf.thirdPartyEventReceivers.Get(eventType).Iter() {
			receiver.ReportEvent(eventType, event)
		}
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

	// Procfs events
	ehf.handlers[utils.ProcfsEventType] = []Manager{ruleManager, metrics}
}
