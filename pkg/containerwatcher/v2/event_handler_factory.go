package containerwatcher

import (
	mapset "github.com/deckarep/golang-set/v2"
	"github.com/goradd/maps"
	tracercapabilitiestype "github.com/inspektor-gadget/inspektor-gadget/pkg/gadgets/trace/capabilities/types"
	tracernetworktype "github.com/inspektor-gadget/inspektor-gadget/pkg/gadgets/trace/network/types"
	"github.com/kubescape/node-agent/pkg/containerprofilemanager"
	"github.com/kubescape/node-agent/pkg/containerwatcher"
	"github.com/kubescape/node-agent/pkg/dnsmanager"
	"github.com/kubescape/node-agent/pkg/ebpf/events"
	tracerhardlinktype "github.com/kubescape/node-agent/pkg/ebpf/gadgets/hardlink/types"
	tracerhttptype "github.com/kubescape/node-agent/pkg/ebpf/gadgets/http/types"
	tracersymlinktype "github.com/kubescape/node-agent/pkg/ebpf/gadgets/symlink/types"
	"github.com/kubescape/node-agent/pkg/malwaremanager"

	"github.com/kubescape/node-agent/pkg/metricsmanager"
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
	containerProfileManager containerprofilemanager.ContainerProfileManagerClient,
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
	containerProfileAdapter := NewManagerAdapter(func(eventType utils.EventType, event utils.K8sEvent) {

		switch eventType {
		case utils.CapabilitiesEventType:
			if capEvent, ok := event.(*tracercapabilitiestype.Event); ok {
				containerProfileManager.ReportCapability(capEvent.Runtime.ContainerID, capEvent.CapName)
			}
		case utils.ExecveEventType:
			if execEvent, ok := event.(*events.ExecEvent); ok {
				containerProfileManager.ReportFileExec(execEvent.Runtime.ContainerID, *execEvent)
			}
		case utils.OpenEventType:
			if openEvent, ok := event.(*events.OpenEvent); ok {
				containerProfileManager.ReportFileOpen(openEvent.Runtime.ContainerID, *openEvent)
			}
		case utils.HTTPEventType:
			if httpEvent, ok := event.(*tracerhttptype.Event); ok {
				containerProfileManager.ReportHTTPEvent(httpEvent.Runtime.ContainerID, httpEvent)
			}
		case utils.SymlinkEventType:
			if symlinkEvent, ok := event.(*tracersymlinktype.Event); ok {
				containerProfileManager.ReportSymlinkEvent(symlinkEvent.Runtime.ContainerID, symlinkEvent)
			}
		case utils.HardlinkEventType:
			if hardlinkEvent, ok := event.(*tracerhardlinktype.Event); ok {
				containerProfileManager.ReportHardlinkEvent(hardlinkEvent.Runtime.ContainerID, hardlinkEvent)
			}
		case utils.NetworkEventType:
			if networkEvent, ok := event.(*tracernetworktype.Event); ok {
				containerProfileManager.ReportNetworkEvent(networkEvent.Runtime.ContainerID, networkEvent)
			}
		default:
			// For event types that don't have specific handling, we might need to add them
			// or handle them generically
		}
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
		containerProfileAdapter,
		dnsAdapter,
		ruleManager,
		malwareManager,
		networkStreamClient,
		metricsAdapter,
	)

	return factory
}

// ProcessEvent processes an event through all registered handlers
func (ehf *EventHandlerFactory) ProcessEvent(enrichedEvent *containerwatcher.EnrichedEvent) {
	// Get handlers for this event type
	handlers, exists := ehf.handlers[enrichedEvent.EventType]
	if !exists {
		return
	}

	// Process event through each handler
	for _, handler := range handlers {
		handler.ReportEvent(enrichedEvent.EventType, enrichedEvent.Event)
	}

	// Report to third-party event receivers
	ehf.reportEventToThirdPartyTracers(enrichedEvent.EventType, enrichedEvent.Event)
}

// registerHandlers registers all handlers for different event types
func (ehf *EventHandlerFactory) registerHandlers(
	containerProfileManager *ManagerAdapter,
	dnsManager *ManagerAdapter,
	ruleManager rulemanager.RuleManagerClient,
	malwareManager malwaremanager.MalwareManagerClient,
	networkStreamClient networkstream.NetworkStreamClient,
	metrics *ManagerAdapter,
) {
	// Capabilities events
	ehf.handlers[utils.CapabilitiesEventType] = []Manager{containerProfileManager, ruleManager, metrics}

	// Exec events
	ehf.handlers[utils.ExecveEventType] = []Manager{containerProfileManager, ruleManager, malwareManager, metrics}

	// Open events
	ehf.handlers[utils.OpenEventType] = []Manager{containerProfileManager, ruleManager, malwareManager, metrics}

	// Network events
	ehf.handlers[utils.NetworkEventType] = []Manager{containerProfileManager, ruleManager, networkStreamClient, metrics}

	// DNS events
	ehf.handlers[utils.DnsEventType] = []Manager{dnsManager, ruleManager, networkStreamClient, metrics}

	// RandomX events
	ehf.handlers[utils.RandomXEventType] = []Manager{ruleManager, metrics}

	// Symlink events
	ehf.handlers[utils.SymlinkEventType] = []Manager{containerProfileManager, ruleManager, metrics}

	// Hardlink events
	ehf.handlers[utils.HardlinkEventType] = []Manager{containerProfileManager, ruleManager, metrics}

	// SSH events
	ehf.handlers[utils.SSHEventType] = []Manager{ruleManager, metrics}

	// HTTP events
	ehf.handlers[utils.HTTPEventType] = []Manager{containerProfileManager, ruleManager, metrics}

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

// reportEventToThirdPartyTracers reports events to third-party tracers
func (ehf *EventHandlerFactory) reportEventToThirdPartyTracers(eventType utils.EventType, event utils.K8sEvent) {
	if ehf.thirdPartyEventReceivers != nil && ehf.thirdPartyEventReceivers.Has(eventType) {
		for receiver := range ehf.thirdPartyEventReceivers.Get(eventType).Iter() {
			receiver.ReportEvent(eventType, event)
		}
	}
}
