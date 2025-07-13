package containerwatcher

import (
	"context"
	"fmt"
	"sync"
	"time"

	mapset "github.com/deckarep/golang-set/v2"
	"github.com/goradd/maps"
	containercollection "github.com/inspektor-gadget/inspektor-gadget/pkg/container-collection"
	containerutilsTypes "github.com/inspektor-gadget/inspektor-gadget/pkg/container-utils/types"
	"github.com/inspektor-gadget/inspektor-gadget/pkg/socketenricher"
	tracercollection "github.com/inspektor-gadget/inspektor-gadget/pkg/tracer-collection"
	"github.com/kubescape/go-logger"
	"github.com/kubescape/go-logger/helpers"
	"github.com/kubescape/k8s-interface/k8sinterface"
	"github.com/kubescape/node-agent/pkg/applicationprofilemanager"
	"github.com/kubescape/node-agent/pkg/config"
	"github.com/kubescape/node-agent/pkg/containerwatcher"
	"github.com/kubescape/node-agent/pkg/containerwatcher/v2/tracers"
	"github.com/kubescape/node-agent/pkg/dnsmanager"
	"github.com/kubescape/node-agent/pkg/malwaremanager"
	"github.com/kubescape/node-agent/pkg/metricsmanager"
	"github.com/kubescape/node-agent/pkg/networkmanager"
	"github.com/kubescape/node-agent/pkg/networkstream"
	"github.com/kubescape/node-agent/pkg/objectcache"
	"github.com/kubescape/node-agent/pkg/processtree"
	containerprocesstree "github.com/kubescape/node-agent/pkg/processtree/container"
	"github.com/kubescape/node-agent/pkg/processtree/feeder"
	"github.com/kubescape/node-agent/pkg/rulebindingmanager"
	"github.com/kubescape/node-agent/pkg/rulemanager"
	"github.com/kubescape/node-agent/pkg/sbommanager"
	"github.com/kubescape/node-agent/pkg/utils"
	"github.com/kubescape/workerpool"
	"github.com/panjf2000/ants/v2"
)

// NewContainerWatcher represents the new container watcher implementation
type NewContainerWatcher struct {
	running bool
	// Configuration
	cfg               config.Config
	containerSelector containercollection.ContainerSelector
	ctx               context.Context
	clusterName       string
	agentStartTime    time.Time

	// Clients
	applicationProfileManager applicationprofilemanager.ApplicationProfileManagerClient
	igK8sClient               *containercollection.K8sClient
	k8sClient                 *k8sinterface.KubernetesApi
	networkManager            networkmanager.NetworkManagerClient
	dnsManager                dnsmanager.DNSManagerClient
	ruleManager               rulemanager.RuleManagerClient
	malwareManager            malwaremanager.MalwareManagerClient
	sbomManager               sbommanager.SbomManagerClient
	networkStreamClient       networkstream.NetworkStreamClient
	containerProcessTree      containerprocesstree.ContainerProcessTree

	// IG Collections
	containerCollection *containercollection.ContainerCollection
	tracerCollection    *tracercollection.TracerCollection
	socketEnricher      *socketenricher.SocketEnricher

	// New components
	orderedEventQueue   *OrderedEventQueue
	eventHandlerFactory *EventHandlerFactory
	processTreeManager  processtree.ProcessTreeManager
	processTreeFeeder   *feeder.EventFeeder
	tracerManager       *containerwatcher.TracerManager

	// Managers
	containerManager *ContainerManager
	tracerManagerV2  *V2TracerManager

	// Worker pool for processing events
	workerPool *ants.PoolWithFunc

	// Third party components
	thirdPartyTracers            mapset.Set[containerwatcher.CustomTracer]
	thirdPartyContainerReceivers mapset.Set[containerwatcher.ContainerReceiver]
	thirdPartyEnricher           containerwatcher.TaskBasedEnricher

	// Cache and state
	objectCache          objectcache.ObjectCache
	ruleManagedPods      mapset.Set[string]
	metrics              metricsmanager.MetricsManager
	ruleBindingPodNotify *chan rulebindingmanager.RuleBindingNotify
	runtime              *containerutilsTypes.RuntimeConfig
	pool                 *workerpool.WorkerPool

	// Lifecycle
	mutex sync.RWMutex

	// Container callbacks
	callbacks []containercollection.FuncNotify
}

var _ containerwatcher.ContainerWatcher = (*NewContainerWatcher)(nil)

// CreateNewContainerWatcher creates a new container watcher with the ordered event processing design
func CreateNewContainerWatcher(
	cfg config.Config,
	applicationProfileManager applicationprofilemanager.ApplicationProfileManagerClient,
	k8sClient *k8sinterface.KubernetesApi,
	igK8sClient *containercollection.K8sClient,
	networkManagerClient networkmanager.NetworkManagerClient,
	dnsManagerClient dnsmanager.DNSManagerClient,
	metrics metricsmanager.MetricsManager,
	ruleManager rulemanager.RuleManagerClient,
	malwareManager malwaremanager.MalwareManagerClient,
	sbomManager sbommanager.SbomManagerClient,
	ruleBindingPodNotify *chan rulebindingmanager.RuleBindingNotify,
	runtime *containerutilsTypes.RuntimeConfig,
	thirdPartyEventReceivers *maps.SafeMap[utils.EventType, mapset.Set[containerwatcher.EventReceiver]],
	thirdPartyEnricher containerwatcher.TaskBasedEnricher,
	processTreeManager processtree.ProcessTreeManager,
	clusterName string,
	objectCache objectcache.ObjectCache,
	networkStreamClient networkstream.NetworkStreamClient,
	containerProcessTree containerprocesstree.ContainerProcessTree,
	processTreeFeeder *feeder.EventFeeder,
) (*NewContainerWatcher, error) {

	// Create container collection
	containerCollection := &containercollection.ContainerCollection{}

	// Create tracer collection
	tracerCollection, err := tracercollection.NewTracerCollection(containerCollection)
	if err != nil {
		return nil, fmt.Errorf("creating tracer collection: %w", err)
	}

	// Create ordered event queue (50ms collection interval, default buffer size)
	orderedEventQueue := NewOrderedEventQueue(500*time.Millisecond, 10000, processTreeManager)

	// Create event handler factory
	eventHandlerFactory := NewEventHandlerFactory(
		applicationProfileManager,
		networkManagerClient,
		dnsManagerClient,
		ruleManager,
		malwareManager,
		networkStreamClient,
		metrics,
		thirdPartyEventReceivers,
		thirdPartyEnricher,
	)

	// Create tracer manager
	tracerManager := containerwatcher.NewTracerManager()

	// Create worker pool for processing events
	workerPool, err := ants.NewPoolWithFunc(cfg.WorkerPoolSize, func(i interface{}) {
		enrichedEvents := i.([]*containerwatcher.EnrichedEvent)
		processEvents(enrichedEvents, eventHandlerFactory)
	})
	if err != nil {
		return nil, fmt.Errorf("creating worker pool: %w", err)
	}

	return &NewContainerWatcher{
		// Configuration
		cfg:               cfg,
		containerSelector: containercollection.ContainerSelector{},
		clusterName:       clusterName,
		agentStartTime:    time.Now(),

		// Clients
		applicationProfileManager: applicationProfileManager,
		igK8sClient:               igK8sClient,
		k8sClient:                 k8sClient,
		networkManager:            networkManagerClient,
		dnsManager:                dnsManagerClient,
		ruleManager:               ruleManager,
		malwareManager:            malwareManager,
		sbomManager:               sbomManager,
		networkStreamClient:       networkStreamClient,
		containerProcessTree:      containerProcessTree,

		// IG Collections
		containerCollection: containerCollection,
		tracerCollection:    tracerCollection,

		// New components
		orderedEventQueue:   orderedEventQueue,
		eventHandlerFactory: eventHandlerFactory,
		processTreeManager:  processTreeManager,
		processTreeFeeder:   processTreeFeeder,
		tracerManager:       tracerManager,
		workerPool:          workerPool,

		// Third party components
		thirdPartyTracers:            mapset.NewSet[containerwatcher.CustomTracer](),
		thirdPartyContainerReceivers: mapset.NewSet[containerwatcher.ContainerReceiver](),
		thirdPartyEnricher:           thirdPartyEnricher,

		// Cache and state
		objectCache:          objectCache,
		ruleManagedPods:      mapset.NewSet[string](),
		metrics:              metrics,
		ruleBindingPodNotify: ruleBindingPodNotify,
		runtime:              runtime,
		pool:                 workerpool.NewWithMaxRunningTime(cfg.WorkerPoolSize, 30*time.Second),
	}, nil
}

// CreateIGContainerWatcher creates a new container watcher with the ordered event processing design
// This function maintains compatibility with the v1 API while using the new v2 implementation
func CreateIGContainerWatcher(
	cfg config.Config,
	applicationProfileManager applicationprofilemanager.ApplicationProfileManagerClient,
	k8sClient *k8sinterface.KubernetesApi,
	igK8sClient *containercollection.K8sClient,
	networkManagerClient networkmanager.NetworkManagerClient,
	dnsManagerClient dnsmanager.DNSManagerClient,
	metrics metricsmanager.MetricsManager,
	ruleManager rulemanager.RuleManagerClient,
	malwareManager malwaremanager.MalwareManagerClient,
	sbomManager sbommanager.SbomManagerClient,
	ruleBindingPodNotify *chan rulebindingmanager.RuleBindingNotify,
	runtime *containerutilsTypes.RuntimeConfig,
	thirdPartyEventReceivers *maps.SafeMap[utils.EventType, mapset.Set[containerwatcher.EventReceiver]],
	thirdPartyEnricher containerwatcher.TaskBasedEnricher,
	processTreeManager processtree.ProcessTreeManager,
	clusterName string,
	objectCache objectcache.ObjectCache,
	networkStreamClient networkstream.NetworkStreamClient,
	containerProcessTree containerprocesstree.ContainerProcessTree,
	processTreeFeeder *feeder.EventFeeder,
) (containerwatcher.ContainerWatcher, error) {

	return CreateNewContainerWatcher(
		cfg,
		applicationProfileManager,
		k8sClient,
		igK8sClient,
		networkManagerClient,
		dnsManagerClient,
		metrics,
		ruleManager,
		malwareManager,
		sbomManager,
		ruleBindingPodNotify,
		runtime,
		thirdPartyEventReceivers,
		thirdPartyEnricher,
		processTreeManager,
		clusterName,
		objectCache,
		networkStreamClient,
		containerProcessTree,
		processTreeFeeder,
	)
}

// Start initializes and starts the container watcher
func (ncw *NewContainerWatcher) Start(ctx context.Context) error {
	ncw.mutex.Lock()
	defer ncw.mutex.Unlock()

	if ncw.running {
		return fmt.Errorf("container watcher is already running")
	}

	ncw.ctx = ctx

	// Initialize container manager
	containerManager := NewContainerManager(ncw)
	ncw.containerManager = containerManager

	// Start container collection (similar to v1 startContainerCollection)
	logger.L().TimedWrapper("StartContainerCollection", 5*time.Second, func() {
		if err := containerManager.StartContainerCollection(ctx); err != nil {
			logger.L().Error("error starting container collection", helpers.Error(err))
		}
	})

	// Start ordered event queue BEFORE tracers
	if err := ncw.orderedEventQueue.Start(ctx); err != nil {
		return fmt.Errorf("starting ordered event queue: %w", err)
	}

	// Start event processing loop
	go ncw.eventProcessingLoop()

	// Create tracer factory
	tracerFactory := tracers.NewTracerFactory(
		ncw.containerCollection,
		ncw.tracerCollection,
		ncw.containerSelector,
		ncw.orderedEventQueue,
		ncw.socketEnricher,
		ncw.applicationProfileManager,
		ncw.ruleManager,
		ncw.thirdPartyTracers,
	)

	// Initialize tracer manager
	tracerManagerV2 := NewV2TracerManager(ncw, tracerFactory)
	if err := tracerManagerV2.StartAllTracers(ctx); err != nil {
		return fmt.Errorf("starting tracer manager: %w", err)
	}
	ncw.tracerManagerV2 = tracerManagerV2

	ncw.running = true
	logger.L().Info("NewContainerWatcher started successfully")
	return nil
}

// Stop gracefully stops the container watcher
func (ncw *NewContainerWatcher) Stop() {
	ncw.mutex.Lock()
	defer ncw.mutex.Unlock()

	if !ncw.running {
		return
	}

	logger.L().Info("Stopping NewContainerWatcher...")

	// Stop container manager
	if ncw.containerManager != nil {
		ncw.containerManager.StopContainerCollection()
	}

	// Stop tracer manager
	if ncw.tracerManagerV2 != nil {
		ncw.tracerManagerV2.StopAllTracers()
	}

	// Stop ordered event queue (after tracers are stopped)
	if ncw.orderedEventQueue != nil {
		ncw.orderedEventQueue.Stop()
	}

	// Stop worker pool
	if ncw.workerPool != nil {
		ncw.workerPool.Release()
	}

	ncw.running = false
	logger.L().Info("NewContainerWatcher stopped successfully")
}

// Ready returns true if the container watcher is ready to process events
func (ncw *NewContainerWatcher) Ready() bool {
	ncw.mutex.RLock()
	defer ncw.mutex.RUnlock()
	return ncw.running
}

// GetContainerCollection returns the container collection
func (ncw *NewContainerWatcher) GetContainerCollection() *containercollection.ContainerCollection {
	return ncw.containerCollection
}

// GetTracerCollection returns the tracer collection
func (ncw *NewContainerWatcher) GetTracerCollection() *tracercollection.TracerCollection {
	return ncw.tracerCollection
}

// GetSocketEnricher returns the socket enricher
func (ncw *NewContainerWatcher) GetSocketEnricher() *socketenricher.SocketEnricher {
	return ncw.socketEnricher
}

// GetContainerSelector returns the container selector
func (ncw *NewContainerWatcher) GetContainerSelector() *containercollection.ContainerSelector {
	return &ncw.containerSelector
}

// RegisterCustomTracer registers a custom tracer
func (ncw *NewContainerWatcher) RegisterCustomTracer(tracer containerwatcher.CustomTracer) error {
	ncw.thirdPartyTracers.Add(tracer)
	return nil
}

// UnregisterCustomTracer unregisters a custom tracer
func (ncw *NewContainerWatcher) UnregisterCustomTracer(tracer containerwatcher.CustomTracer) error {
	ncw.thirdPartyTracers.Remove(tracer)
	return nil
}

// RegisterContainerReceiver registers a container receiver
func (ncw *NewContainerWatcher) RegisterContainerReceiver(receiver containerwatcher.ContainerReceiver) {
	ncw.thirdPartyContainerReceivers.Add(receiver)
}

// UnregisterContainerReceiver unregisters a container receiver
func (ncw *NewContainerWatcher) UnregisterContainerReceiver(receiver containerwatcher.ContainerReceiver) {
	ncw.thirdPartyContainerReceivers.Remove(receiver)
}

func processEvents(enrichedEvents []*containerwatcher.EnrichedEvent, eventHandlerFactory *EventHandlerFactory) {
	// Process events through the event handler factory
	for _, event := range enrichedEvents {
		if event.EventType == utils.ExecveEventType {
			logger.L().Info("Processing execve event", helpers.String("event", fmt.Sprintf("%+v", event)), helpers.String("processTree", fmt.Sprintf("%+v", event.ProcessTree)))
		}
		eventHandlerFactory.ProcessEvent(event)
	}
}

// eventProcessingLoop continuously processes events from the ordered event queue
func (ncw *NewContainerWatcher) eventProcessingLoop() {
	for {
		select {
		case <-ncw.ctx.Done():
			return
		case events := <-ncw.orderedEventQueue.GetOutputChannel():
			ncw.enrichAndProcess(events)
		}
	}
}

// enrichAndProcess processes a batch of events
func (ncw *NewContainerWatcher) enrichAndProcess(events []eventEntry) {
	// Enrich events with additional data
	enrichedEvents := ncw.enrichEvents(events)
	// logger.L().Info("Enriched events", helpers.Int("count", len(enrichedEvents)))

	// Submit to worker pool for processing
	if err := ncw.workerPool.Invoke(enrichedEvents); err != nil {
		logger.L().Error("Failed to submit events to worker pool", helpers.Error(err))
	}
}

// enrichEvents enriches events with additional data like process tree information
func (ncw *NewContainerWatcher) enrichEvents(events []eventEntry) []*containerwatcher.EnrichedEvent {
	enrichedEvents := make([]*containerwatcher.EnrichedEvent, 0, len(events))

	for _, entry := range events {
		event := entry.Event
		eventType := entry.EventType

		// Enrich with process tree data if it's a process-related event
		if isProcessTreeEvent(eventType) {
			ncw.processTreeFeeder.ReportEvent(eventType, event)
		}

		if eventType == utils.ProcfsEventType {
			continue
		}

		processTree, _ := ncw.processTreeManager.GetContainerProcessTree(entry.ContainerID, entry.ProcessID)

		enrichedEvents = append(enrichedEvents, &containerwatcher.EnrichedEvent{
			Event:       event,
			EventType:   eventType,
			ProcessTree: processTree,
			ContainerID: entry.ContainerID,
			Timestamp:   entry.Timestamp,
		})
	}

	return enrichedEvents
}

// isProcessTreeEvent checks if an event type is related to process tree
func isProcessTreeEvent(eventType utils.EventType) bool {
	return eventType == utils.ExecveEventType ||
		eventType == utils.ExitEventType ||
		eventType == utils.ForkEventType ||
		eventType == utils.ProcfsEventType
}
