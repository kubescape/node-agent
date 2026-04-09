package containerwatcher

import (
	mapset "github.com/deckarep/golang-set/v2"
	"github.com/goradd/maps"
	containercollection "github.com/inspektor-gadget/inspektor-gadget/pkg/container-collection"
	"github.com/kubescape/node-agent/pkg/config"
	"github.com/kubescape/node-agent/pkg/containerprofilemanager"
	"github.com/kubescape/node-agent/pkg/containerwatcher"
	"github.com/kubescape/node-agent/pkg/dedupcache"
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

// TTL constants for dedup windows in 64ms buckets.
const (
	dedupTTLOpen         uint16 = 156 // 10s
	dedupTTLNetwork      uint16 = 78  // 5s
	dedupTTLDNS          uint16 = 156 // 10s
	dedupTTLCapabilities uint16 = 156 // 10s
	dedupTTLHTTP         uint16 = 31  // 2s
	dedupTTLSSH          uint16 = 156 // 10s
	dedupTTLSymlink      uint16 = 156 // 10s
	dedupTTLHardlink     uint16 = 156 // 10s
	dedupTTLPtrace       uint16 = 156 // 10s
	dedupTTLSyscall      uint16 = 78  // 5s
)

// EventHandlerFactory manages the mapping of event types to their managers
type EventHandlerFactory struct {
	handlers                 map[utils.EventType][]Manager
	thirdPartyEventReceivers *maps.SafeMap[utils.EventType, mapset.Set[containerwatcher.GenericEventReceiver]]
	thirdPartyEnricher       containerwatcher.TaskBasedEnricher
	cfg                      config.Config
	containerCollection      *containercollection.ContainerCollection
	containerCache           *maps.SafeMap[string, *containercollection.Container] // Cache for container lookups
	containerProfileManager  containerprofilemanager.ContainerProfileManagerClient
	dedupCache               *dedupcache.DedupCache
	metrics                  metricsmanager.MetricsManager
	dedupSkipSet             map[Manager]struct{} // Managers to skip when event is duplicate
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
	dedupCache *dedupcache.DedupCache,
) *EventHandlerFactory {
	factory := &EventHandlerFactory{
		handlers:                 make(map[utils.EventType][]Manager),
		thirdPartyEventReceivers: thirdPartyEventReceivers,
		thirdPartyEnricher:       thirdPartyEnricher,
		cfg:                      cfg,
		containerCollection:      containerCollection,
		containerCache:           &maps.SafeMap[string, *containercollection.Container]{},
		containerProfileManager:  containerProfileManager,
		dedupCache:               dedupCache,
		metrics:                  metrics,
		dedupSkipSet:             make(map[Manager]struct{}),
	}

	// Create adapters for managers that don't implement the Manager interface directly
	containerProfileAdapter := NewManagerAdapter(func(eventType utils.EventType, event utils.K8sEvent) {
		// ContainerProfileManager has specific methods for different event types
		switch eventType {
		case utils.CapabilitiesEventType:
			if capEvent, ok := event.(utils.CapabilitiesEvent); ok {
				containerProfileManager.ReportCapability(capEvent.GetContainerID(), capEvent.GetCapability())
			}
		case utils.ExecveEventType:
			if execEvent, ok := event.(utils.ExecEvent); ok {
				containerProfileManager.ReportFileExec(execEvent.GetContainerID(), execEvent)
			}
		case utils.OpenEventType:
			if openEvent, ok := event.(utils.OpenEvent); ok {
				containerProfileManager.ReportFileOpen(openEvent.GetContainerID(), openEvent)
			}
		case utils.HTTPEventType:
			if httpEvent, ok := event.(utils.HttpEvent); ok {
				containerProfileManager.ReportHTTPEvent(httpEvent.GetContainerID(), httpEvent)
			}
		case utils.SymlinkEventType:
			if symlinkEvent, ok := event.(utils.LinkEvent); ok {
				containerProfileManager.ReportSymlinkEvent(symlinkEvent.GetContainerID(), symlinkEvent)
			}
		case utils.HardlinkEventType:
			if hardlinkEvent, ok := event.(utils.LinkEvent); ok {
				containerProfileManager.ReportHardlinkEvent(hardlinkEvent.GetContainerID(), hardlinkEvent)
			}
		case utils.NetworkEventType:
			if networkEvent, ok := event.(utils.NetworkEvent); ok {
				containerProfileManager.ReportNetworkEvent(networkEvent.GetContainerID(), networkEvent)
			}
		case utils.SyscallEventType:
			if syscallEvent, ok := event.(utils.SyscallEvent); ok {
				containerProfileManager.ReportSyscall(syscallEvent.GetContainerID(), syscallEvent.GetSyscall())
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
			if execEvent, ok := event.(utils.ExecEvent); ok {
				rulePolicyReporter.ReportEvent(eventType, event, execEvent.GetContainerID(), execEvent.GetComm())
			}
		case utils.SymlinkEventType:
			if symlinkEvent, ok := event.(utils.LinkEvent); ok {
				rulePolicyReporter.ReportEvent(eventType, event, symlinkEvent.GetContainerID(), symlinkEvent.GetComm())
			}
		case utils.HardlinkEventType:
			if hardlinkEvent, ok := event.(utils.LinkEvent); ok {
				rulePolicyReporter.ReportEvent(eventType, event, hardlinkEvent.GetContainerID(), hardlinkEvent.GetComm())
			}
		case utils.IoUringEventType:
			if iouringEvent, ok := event.(utils.IOUring); ok {
				rulePolicyReporter.ReportEvent(eventType, event, iouringEvent.GetContainerID(), iouringEvent.GetComm())
			}
		}
	})

	dnsAdapter := NewManagerAdapter(func(eventType utils.EventType, event utils.K8sEvent) {
		// DNS manager has specific methods for different event types
		// This would need to be implemented based on the specific event types
		switch eventType {
		case utils.DnsEventType:
			if dnsEvent, ok := event.(utils.DNSEvent); ok {
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

	// Populate dedupSkipSet: managers that skip processing when event is duplicate.
	// RuleManager checks enrichedEvent.Duplicate internally.
	factory.dedupSkipSet[containerProfileAdapter] = struct{}{}
	factory.dedupSkipSet[malwareManager] = struct{}{}

	return factory
}

// computeEventDedupKey computes a dedup key and TTL for the given event.
// Returns shouldDedup=false for event types that must not be deduplicated.
func computeEventDedupKey(enrichedEvent *events.EnrichedEvent) (key uint64, ttl uint16, shouldDedup bool) {
	event := enrichedEvent.Event
	mntns := enrichedEvent.MountNamespaceID
	if mntns == 0 {
		if ee, ok := event.(utils.EnrichEvent); ok {
			mntns = ee.GetMountNsID()
		}
	}

	switch event.GetEventType() {
	case utils.OpenEventType:
		if e, ok := event.(utils.OpenEvent); ok {
			pid := uint32(0)
			if ee, ok := event.(utils.EnrichEvent); ok {
				pid = ee.GetPID()
			}
			return dedupcache.ComputeOpenKey(mntns, pid, e.GetPath(), e.GetFlagsRaw()), dedupTTLOpen, true
		}
	case utils.NetworkEventType:
		if e, ok := event.(utils.NetworkEvent); ok {
			pid := uint32(0)
			if ee, ok := event.(utils.EnrichEvent); ok {
				pid = ee.GetPID()
			}
			dst := e.GetDstEndpoint()
			return dedupcache.ComputeNetworkKey(mntns, pid, dst.Addr, e.GetDstPort(), e.GetProto()), dedupTTLNetwork, true
		}
	case utils.DnsEventType:
		if e, ok := event.(utils.DNSEvent); ok {
			return dedupcache.ComputeDNSKey(mntns, e.GetDNSName()), dedupTTLDNS, true
		}
	case utils.CapabilitiesEventType:
		if e, ok := event.(utils.CapabilitiesEvent); ok {
			pid := uint32(0)
			if ee, ok := event.(utils.EnrichEvent); ok {
				pid = ee.GetPID()
			}
			return dedupcache.ComputeCapabilitiesKey(mntns, pid, e.GetCapability(), e.GetSyscall()), dedupTTLCapabilities, true
		}
	case utils.HTTPEventType:
		if e, ok := event.(utils.HttpEvent); ok {
			pid := uint32(0)
			if ee, ok := event.(utils.EnrichEvent); ok {
				pid = ee.GetPID()
			}
			req := e.GetRequest()
			if req == nil || req.URL == nil {
				return 0, 0, false
			}
			return dedupcache.ComputeHTTPKey(mntns, pid, string(e.GetDirection()), req.Method, req.Host, req.URL.Path, req.URL.RawQuery), dedupTTLHTTP, true
		}
	case utils.SSHEventType:
		if e, ok := event.(utils.SshEvent); ok {
			return dedupcache.ComputeSSHKey(mntns, e.GetDstIP(), e.GetDstPort()), dedupTTLSSH, true
		}
	case utils.SymlinkEventType:
		if e, ok := event.(utils.LinkEvent); ok {
			pid := uint32(0)
			if ee, ok := event.(utils.EnrichEvent); ok {
				pid = ee.GetPID()
			}
			return dedupcache.ComputeSymlinkKey(mntns, pid, e.GetOldPath(), e.GetNewPath()), dedupTTLSymlink, true
		}
	case utils.HardlinkEventType:
		if e, ok := event.(utils.LinkEvent); ok {
			pid := uint32(0)
			if ee, ok := event.(utils.EnrichEvent); ok {
				pid = ee.GetPID()
			}
			return dedupcache.ComputeHardlinkKey(mntns, pid, e.GetOldPath(), e.GetNewPath()), dedupTTLHardlink, true
		}
	case utils.PtraceEventType:
		if e, ok := event.(utils.PtraceEvent); ok {
			pid := uint32(0)
			if ee, ok := event.(utils.EnrichEvent); ok {
				pid = ee.GetPID()
			}
			return dedupcache.ComputePtraceKey(mntns, pid, e.GetExePath()), dedupTTLPtrace, true
		}
	case utils.SyscallEventType:
		if e, ok := event.(utils.SyscallEvent); ok {
			pid := uint32(0)
			if ee, ok := event.(utils.EnrichEvent); ok {
				pid = ee.GetPID()
			}
			return dedupcache.ComputeSyscallKey(mntns, pid, e.GetSyscall()), dedupTTLSyscall, true
		}
	}
	// exec, exit, fork, randomx, kmod, bpf, unshare, iouring — no dedup
	return 0, 0, false
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

	// Dedup check: compute key and check cache before dispatching to handlers
	if ehf.dedupCache != nil {
		key, ttl, shouldDedup := computeEventDedupKey(enrichedEvent)
		if shouldDedup {
			duplicate := ehf.dedupCache.CheckAndSet(key, ttl, enrichedEvent.DedupBucket)
			if duplicate {
				enrichedEvent.Duplicate = true
			}
			ehf.metrics.ReportDedupEvent(enrichedEvent.Event.GetEventType(), duplicate)
		}
	}

	// Always report dropped events regardless of dedup status
	if enrichedEvent.Event.HasDroppedEvents() {
		ehf.containerProfileManager.ReportDroppedEvent(enrichedEvent.Event.GetContainerID())
	}

	// Get handlers for this event type
	eventType := enrichedEvent.Event.GetEventType()
	handlers, exists := ehf.handlers[eventType]
	if !exists {
		return
	}

	// Process event through each handler
	for _, handler := range handlers {
		if enrichedEvent.Duplicate {
			if _, skip := ehf.dedupSkipSet[handler]; skip {
				continue
			}
		}
		if enrichedHandler, ok := handler.(containerwatcher.EnrichedEventReceiver); ok {
			enrichedHandler.ReportEnrichedEvent(enrichedEvent)
		} else if handler, ok := handler.(containerwatcher.EventReceiver); ok {
			handler.ReportEvent(eventType, enrichedEvent.Event)
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

	// Kmod events
	ehf.handlers[utils.KmodEventType] = []Manager{ruleManager, metrics}

	// Unshare events
	ehf.handlers[utils.UnshareEventType] = []Manager{ruleManager, metrics}

	// Bpf events
	ehf.handlers[utils.BpfEventType] = []Manager{ruleManager, metrics}
}

// reportEventToThirdPartyTracers reports events to third-party tracers
func (ehf *EventHandlerFactory) reportEventToThirdPartyTracers(enrichedEvent *events.EnrichedEvent) {
	if ehf.thirdPartyEventReceivers != nil {
		eventType := enrichedEvent.Event.GetEventType()
		if eventReceivers, ok := ehf.thirdPartyEventReceivers.Load(eventType); ok {
			for receiver := range eventReceivers.Iter() {
				if enrichedHandler, ok := receiver.(containerwatcher.EnrichedEventReceiver); ok {
					enrichedHandler.ReportEnrichedEvent(enrichedEvent)
				} else if handler, ok := receiver.(containerwatcher.EventReceiver); ok {
					handler.ReportEvent(eventType, enrichedEvent.Event)
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
