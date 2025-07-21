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
	"github.com/kubescape/node-agent/pkg/config"
	"github.com/kubescape/node-agent/pkg/containerprofilemanager"
	"github.com/kubescape/node-agent/pkg/containerwatcher"
	"github.com/kubescape/node-agent/pkg/containerwatcher/v2/tracers"
	"github.com/kubescape/node-agent/pkg/dnsmanager"
	"github.com/kubescape/node-agent/pkg/eventreporters/rulepolicy"
	"github.com/kubescape/node-agent/pkg/malwaremanager"
	"github.com/kubescape/node-agent/pkg/metricsmanager"
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

// ContainerWatcher represents the new container watcher implementation
type ContainerWatcher struct {
	running bool
	// Configuration
	cfg               config.Config
	containerSelector containercollection.ContainerSelector
	ctx               context.Context
	clusterName       string
	agentStartTime    time.Time

	// Clients
	containerProfileManager containerprofilemanager.ContainerProfileManagerClient
	igK8sClient             *containercollection.K8sClient
	k8sClient               *k8sinterface.KubernetesApi
	dnsManager              dnsmanager.DNSManagerClient
	ruleManager             rulemanager.RuleManagerClient
	malwareManager          malwaremanager.MalwareManagerClient
	sbomManager             sbommanager.SbomManagerClient
	networkStreamClient     networkstream.NetworkStreamClient
	containerProcessTree    containerprocesstree.ContainerProcessTree

	// IG Collections
	containerCollection *containercollection.ContainerCollection
	tracerCollection    *tracercollection.TracerCollection
	socketEnricher      *socketenricher.SocketEnricher

	// New components
	orderedEventQueue   *OrderedEventQueue
	eventHandlerFactory *EventHandlerFactory
	processTreeManager  processtree.ProcessTreeManager
	processTreeFeeder   *feeder.EventFeeder
	eventEnricher       *EventEnricher

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

var _ containerwatcher.ContainerWatcher = (*ContainerWatcher)(nil)

// CreateContainerWatcher creates a new container watcher with the ordered event processing design
func CreateContainerWatcher(
	cfg config.Config,
	containerProfileManager containerprofilemanager.ContainerProfileManagerClient,
	k8sClient *k8sinterface.KubernetesApi,
	igK8sClient *containercollection.K8sClient,
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
) (*ContainerWatcher, error) {

	// Create container collection
	containerCollection := &containercollection.ContainerCollection{}

	// Create tracer collection
	tracerCollection, err := tracercollection.NewTracerCollection(containerCollection)
	if err != nil {
		return nil, fmt.Errorf("creating tracer collection: %w", err)
	}

	// Create ordered event queue (50ms collection interval, increased buffer size)
	orderedEventQueue := NewOrderedEventQueue(250*time.Millisecond, 100000, processTreeManager)

	rulePolicyReporter := rulepolicy.NewRulePolicyReporter(ruleManager, containerProfileManager)

	// Create event handler factory
	eventHandlerFactory := NewEventHandlerFactory(
		cfg,
		containerCollection,
		containerProfileManager,
		dnsManagerClient,
		ruleManager,
		malwareManager,
		networkStreamClient,
		metrics,
		thirdPartyEventReceivers,
		thirdPartyEnricher,
		rulePolicyReporter,
	)

	// Create event enricher
	eventEnricher := NewEventEnricher(processTreeManager)

	// Create worker pool for processing individual events
	workerPool, err := ants.NewPoolWithFunc(cfg.WorkerPoolSize, func(i interface{}) {
		enrichedEvent := i.(*containerwatcher.EnrichedEvent)
		eventHandlerFactory.ProcessEvent(enrichedEvent)
	})
	if err != nil {
		return nil, fmt.Errorf("creating worker pool: %w", err)
	}

	return &ContainerWatcher{
		// Configuration
		cfg:               cfg,
		containerSelector: containercollection.ContainerSelector{},
		clusterName:       clusterName,
		agentStartTime:    time.Now(),

		// Clients
		containerProfileManager: containerProfileManager,
		igK8sClient:             igK8sClient,
		k8sClient:               k8sClient,
		dnsManager:              dnsManagerClient,
		ruleManager:             ruleManager,
		malwareManager:          malwareManager,
		sbomManager:             sbomManager,
		networkStreamClient:     networkStreamClient,
		containerProcessTree:    containerProcessTree,

		// IG Collections
		containerCollection: containerCollection,
		tracerCollection:    tracerCollection,

		// New components
		orderedEventQueue:   orderedEventQueue,
		eventHandlerFactory: eventHandlerFactory,
		processTreeManager:  processTreeManager,
		eventEnricher:       eventEnricher,
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
	containerProfileManager containerprofilemanager.ContainerProfileManagerClient,
	k8sClient *k8sinterface.KubernetesApi,
	igK8sClient *containercollection.K8sClient,
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
) (containerwatcher.ContainerWatcher, error) {

	return CreateContainerWatcher(
		cfg,
		containerProfileManager,
		k8sClient,
		igK8sClient,
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
	)
}

// Start initializes and starts the container watcher
func (ncw *ContainerWatcher) Start(ctx context.Context) error {
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
		ncw.containerProfileManager,
		ncw.ruleManager,
		ncw.thirdPartyTracers,
		ncw.thirdPartyEnricher,
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
func (ncw *ContainerWatcher) Stop() {
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
func (ncw *ContainerWatcher) Ready() bool {
	ncw.mutex.RLock()
	defer ncw.mutex.RUnlock()
	return ncw.running
}

// GetContainerCollection returns the container collection
func (ncw *ContainerWatcher) GetContainerCollection() *containercollection.ContainerCollection {
	return ncw.containerCollection
}

// GetTracerCollection returns the tracer collection
func (ncw *ContainerWatcher) GetTracerCollection() *tracercollection.TracerCollection {
	return ncw.tracerCollection
}

// GetSocketEnricher returns the socket enricher
func (ncw *ContainerWatcher) GetSocketEnricher() *socketenricher.SocketEnricher {
	return ncw.socketEnricher
}

// GetContainerSelector returns the container selector
func (ncw *ContainerWatcher) GetContainerSelector() *containercollection.ContainerSelector {
	return &ncw.containerSelector
}

// RegisterCustomTracer registers a custom tracer
func (ncw *ContainerWatcher) RegisterCustomTracer(tracer containerwatcher.CustomTracer) error {
	ncw.thirdPartyTracers.Add(tracer)
	return nil
}

// UnregisterCustomTracer unregisters a custom tracer
func (ncw *ContainerWatcher) UnregisterCustomTracer(tracer containerwatcher.CustomTracer) error {
	ncw.thirdPartyTracers.Remove(tracer)
	return nil
}

// RegisterContainerReceiver registers a container receiver
func (ncw *ContainerWatcher) RegisterContainerReceiver(receiver containerwatcher.ContainerReceiver) {
	ncw.thirdPartyContainerReceivers.Add(receiver)
}

// UnregisterContainerReceiver unregisters a container receiver
func (ncw *ContainerWatcher) UnregisterContainerReceiver(receiver containerwatcher.ContainerReceiver) {
	ncw.thirdPartyContainerReceivers.Remove(receiver)
}

// eventProcessingLoop continuously processes events from the ordered event queue
func (ncw *ContainerWatcher) eventProcessingLoop() {
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
func (ncw *ContainerWatcher) enrichAndProcess(events []eventEntry) {
	// Enrich events with additional data
	exec := 0
	for _, event := range events {
		if event.EventType == utils.ExecveEventType {
			exec++
		}
	}

	enrichedEvents := ncw.eventEnricher.EnrichEvents(events)
	enrichedExec := 0
	for _, event := range enrichedEvents {
		if event.EventType == utils.ExecveEventType {
			enrichedExec++
		}
	}

	if exec != enrichedExec {
		logger.L().Error("AFEK - Execve events mismatch", helpers.Int("exec", exec), helpers.Int("enrichedExec", enrichedExec))
	}

	for _, enrichedEvent := range enrichedEvents {
		err := ncw.workerPool.Invoke(enrichedEvent)
		if err != nil {
			logger.L().Error("AFEK - Failed to submit event to worker pool", helpers.String("eventType", string(enrichedEvent.EventType)), helpers.String("containerID", enrichedEvent.ContainerID), helpers.Error(err))
		}
	}
}
