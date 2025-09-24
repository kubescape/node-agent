package containerwatcher

import (
	mapset "github.com/deckarep/golang-set/v2"
	"github.com/goradd/maps"
	containercollection "github.com/inspektor-gadget/inspektor-gadget/pkg/container-collection"
	"github.com/kubescape/node-agent/pkg/config"
	"github.com/kubescape/node-agent/pkg/containerprofilemanager"
	"github.com/kubescape/node-agent/pkg/containerwatcher"
	"github.com/kubescape/node-agent/pkg/dnsmanager"
	"github.com/kubescape/node-agent/pkg/ebpf/events"
	"github.com/kubescape/node-agent/pkg/eventreporters/rulepolicy"
	"github.com/kubescape/node-agent/pkg/malwaremanager"
	"github.com/kubescape/node-agent/pkg/metricsmanager"
	"github.com/kubescape/node-agent/pkg/networkstream"
	"github.com/kubescape/node-agent/pkg/rulemanager"
	"github.com/kubescape/node-agent/pkg/utils"
)

// Manager represents a component that can receive events
type Manager interface {
	// TODO: Find a better way to handle this
	// containerwatcher.EventReceiver
	// containerwatcher.EnrichedEventReceiver
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
	thirdPartyEventReceivers *maps.SafeMap[utils.EventType, mapset.Set[containerwatcher.GenericEventReceiver]]
	thirdPartyEnricher       containerwatcher.TaskBasedEnricher
	cfg                      config.Config
	containerCollection      *containercollection.ContainerCollection
	containerCache           *maps.SafeMap[string, *containercollection.Container] // Cache for container lookups
}

// NewEventHandlerFactory creates a new event handler factory
func NewEventHandlerFactory(
	cfg config.Config,
	containerCollection *containercollection.ContainerCollection,
	containerProfileManager containerprofilemanager.ContainerProfileManagerClient,
	dnsManager dnsmanager.DNSManagerClient,
	ruleManager rulemanager.RuleManagerClient,
	malwareManager malwaremanager.MalwareManagerClient,
	networkStreamClient networkstream.NetworkStreamClient,
	metrics metricsmanager.MetricsManager,
	thirdPartyEventReceivers *maps.SafeMap[utils.EventType, mapset.Set[containerwatcher.GenericEventReceiver]],
	thirdPartyEnricher containerwatcher.TaskBasedEnricher,
	rulePolicyReporter *rulepolicy.RulePolicyReporter,
) *EventHandlerFactory {
	factory := &EventHandlerFactory{
		handlers:                 make(map[utils.EventType][]Manager),
		thirdPartyEventReceivers: thirdPartyEventReceivers,
		thirdPartyEnricher:       thirdPartyEnricher,
		cfg:                      cfg,
		containerCollection:      containerCollection,
		containerCache:           &maps.SafeMap[string, *containercollection.Container]{},
	}

	// Create adapters for managers that don't implement the Manager interface directly
	containerProfileAdapter := NewManagerAdapter(func(eventType utils.EventType, event utils.K8sEvent) {
		switch eventType {
		case utils.CapabilitiesEventType:
			if capEvent, ok := event.(*utils.DatasourceEvent); ok {
				containerProfileManager.ReportCapability(capEvent.GetContainerID(), capEvent.GetCapability())
			}
		case utils.ExecveEventType:
			if execEvent, ok := event.(*utils.DatasourceEvent); ok {
				containerProfileManager.ReportFileExec(execEvent.GetContainerID(), execEvent)
			}
		case utils.OpenEventType:
			if openEvent, ok := event.(*utils.DatasourceEvent); ok {
				containerProfileManager.ReportFileOpen(openEvent.GetContainerID(), openEvent)
			}
		//case utils.HTTPEventType:
		//	if httpEvent, ok := event.(*tracerhttptype.Event); ok {
		//		containerProfileManager.ReportHTTPEvent(httpEvent.Runtime.ContainerID, httpEvent)
		//	}
		//case utils.SymlinkEventType:
		//	if symlinkEvent, ok := event.(*tracersymlinktype.Event); ok {
		//		containerProfileManager.ReportSymlinkEvent(symlinkEvent.Runtime.ContainerID, symlinkEvent)
		//	}
		//case utils.HardlinkEventType:
		//	if hardlinkEvent, ok := event.(*tracerhardlinktype.Event); ok {
		//		containerProfileManager.ReportHardlinkEvent(hardlinkEvent.Runtime.ContainerID, hardlinkEvent)
		//	}
		case utils.NetworkEventType:
			if networkEvent, ok := event.(*utils.DatasourceEvent); ok {
				containerProfileManager.ReportNetworkEvent(networkEvent.GetContainerID(), networkEvent)
			}
		case utils.SyscallEventType:
			if syscallEvent, ok := event.(*utils.DatasourceEvent); ok {
				containerProfileManager.ReportSyscalls(syscallEvent.GetContainerID(), syscallEvent.GetSyscalls())
			}
		default:
			// For event types that don't have specific handling, we might need to add them
			// or handle them generically
		}
	})

	rulePolicyAdapter := NewManagerAdapter(func(eventType utils.EventType, event utils.K8sEvent) {
		switch eventType {
		// Won't work for 3rd party tracers, we need to extract comm and containerID from the event by interface
		case utils.ExecveEventType:
			if execEvent, ok := event.(*utils.DatasourceEvent); ok {
				rulePolicyReporter.ReportEvent(eventType, event, execEvent.GetContainerID(), execEvent.GetComm())
			}
			//case utils.SymlinkEventType:
			//	if symlinkEvent, ok := event.(*tracersymlinktype.Event); ok {
			//		rulePolicyReporter.ReportEvent(eventType, event, symlinkEvent.Runtime.ContainerID, symlinkEvent.Comm)
			//	}
			//case utils.HardlinkEventType:
			//	if hardlinkEvent, ok := event.(*tracerhardlinktype.Event); ok {
			//		rulePolicyReporter.ReportEvent(eventType, event, hardlinkEvent.Runtime.ContainerID, hardlinkEvent.Comm)
			//	}
			//case utils.IoUringEventType:
			//	if iouringEvent, ok := event.(*traceriouringtype.Event); ok {
			//		rulePolicyReporter.ReportEvent(eventType, event, iouringEvent.Runtime.ContainerID, iouringEvent.Identifier)
			//	}
		}
	})

	dnsAdapter := NewManagerAdapter(func(eventType utils.EventType, event utils.K8sEvent) {
		// DNS manager has specific methods for different event types
		// This would need to be implemented based on the specific event types
		switch eventType {
		case utils.DnsEventType:
			if dnsEvent, ok := event.(*utils.DatasourceEvent); ok {
				dnsManager.ReportEvent(dnsEvent)
			}
		}
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
		rulePolicyAdapter,
	)

	return factory
}

// ProcessEvent processes an event through all registered handlers
func (ehf *EventHandlerFactory) ProcessEvent(enrichedEvent *events.EnrichedEvent) {
	if enrichedEvent.ContainerID == "" {
		return
	}

	// Get container information to check if it should be ignored
	container, err := ehf.getContainerInfo(enrichedEvent.ContainerID)
	if err != nil || container == nil {
		return
	}

	if ehf.cfg.IgnoreContainer(container.K8s.Namespace, container.K8s.PodName, container.K8s.PodLabels) {
		return
	}

	// Get handlers for this event type
	handlers, exists := ehf.handlers[enrichedEvent.EventType]
	if !exists {
		return
	}

	// Process event through each handler
	for _, handler := range handlers {
		if enrichedHandler, ok := handler.(containerwatcher.EnrichedEventReceiver); ok {
			enrichedHandler.ReportEnrichedEvent(enrichedEvent)
		} else if handler, ok := handler.(containerwatcher.EventReceiver); ok {
			handler.ReportEvent(enrichedEvent.EventType, enrichedEvent.Event)
		}
	}

	// Report to third-party event receivers
	ehf.reportEventToThirdPartyTracers(enrichedEvent)
}

// registerHandlers registers all handlers for different event types
func (ehf *EventHandlerFactory) registerHandlers(
	containerProfileManager *ManagerAdapter,
	dnsManager *ManagerAdapter,
	ruleManager rulemanager.RuleManagerClient,
	malwareManager malwaremanager.MalwareManagerClient,
	networkStreamClient networkstream.NetworkStreamClient,
	metrics *ManagerAdapter,
	rulePolicy *ManagerAdapter,
) {
	// Capabilities events
	ehf.handlers[utils.CapabilitiesEventType] = []Manager{containerProfileManager, ruleManager, metrics}

	// Exec events
	ehf.handlers[utils.ExecveEventType] = []Manager{containerProfileManager, ruleManager, malwareManager, metrics, rulePolicy}

	// Open events
	ehf.handlers[utils.OpenEventType] = []Manager{containerProfileManager, ruleManager, malwareManager, metrics}

	// Network events
	ehf.handlers[utils.NetworkEventType] = []Manager{containerProfileManager, ruleManager, networkStreamClient, metrics}

	// DNS events
	ehf.handlers[utils.DnsEventType] = []Manager{dnsManager, ruleManager, networkStreamClient, metrics}

	// RandomX events
	ehf.handlers[utils.RandomXEventType] = []Manager{ruleManager, metrics}

	// Symlink events
	ehf.handlers[utils.SymlinkEventType] = []Manager{containerProfileManager, ruleManager, metrics, rulePolicy}

	// Hardlink events
	ehf.handlers[utils.HardlinkEventType] = []Manager{containerProfileManager, ruleManager, metrics, rulePolicy}

	// SSH events
	ehf.handlers[utils.SSHEventType] = []Manager{ruleManager, metrics}

	// HTTP events
	ehf.handlers[utils.HTTPEventType] = []Manager{containerProfileManager, ruleManager, metrics}

	// Ptrace events
	ehf.handlers[utils.PtraceEventType] = []Manager{ruleManager, metrics}

	// IoUring events
	ehf.handlers[utils.IoUringEventType] = []Manager{ruleManager, metrics, rulePolicy}

	// Syscall events
	ehf.handlers[utils.SyscallEventType] = []Manager{containerProfileManager, ruleManager, metrics}
}

// reportEventToThirdPartyTracers reports events to third-party tracers
func (ehf *EventHandlerFactory) reportEventToThirdPartyTracers(enrichedEvent *events.EnrichedEvent) {
	if ehf.thirdPartyEventReceivers != nil {
		if eventReceivers, ok := ehf.thirdPartyEventReceivers.Load(enrichedEvent.EventType); ok {
			for receiver := range eventReceivers.Iter() {
				if enrichedHandler, ok := receiver.(containerwatcher.EnrichedEventReceiver); ok {
					enrichedHandler.ReportEnrichedEvent(enrichedEvent)
				} else if handler, ok := receiver.(containerwatcher.EventReceiver); ok {
					handler.ReportEvent(enrichedEvent.EventType, enrichedEvent.Event)
				}
			}
		}
	}
}

// getContainerInfo retrieves container information by container ID
func (ehf *EventHandlerFactory) getContainerInfo(containerID string) (*containercollection.Container, error) {
	// Check cache first
	if container := ehf.containerCache.Get(containerID); container != nil {
		return container, nil
	}

	// Get all containers and search for the one with matching ID
	containers := ehf.containerCollection.GetContainersBySelector(&containercollection.ContainerSelector{})
	for _, container := range containers {
		if container.Runtime.ContainerID == containerID {
			// Cache the result
			ehf.containerCache.Set(containerID, container)
			return container, nil
		}
	}
	return nil, nil // Container not found
}
