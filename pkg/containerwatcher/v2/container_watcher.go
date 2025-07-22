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
	"github.com/kubescape/node-agent/pkg/ebpf/events"
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
	tracerManagerV2 *TracerManager

	// Worker pool for processing events
	workerPool *ants.PoolWithFunc
	workerChan chan *events.EnrichedEvent // Channel for worker pool invocation

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
	orderedEventQueue := NewOrderedEventQueue(50*time.Millisecond, 1000000, processTreeManager)

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
		enrichedEvent := i.(*events.EnrichedEvent)
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
		workerChan:          make(chan *events.EnrichedEvent, cfg.WorkerPoolSize*4), // Buffer size 4x worker pool size

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

	// Start container collection (similar to v1 startContainerCollection)
	logger.L().TimedWrapper("StartContainerCollection", 5*time.Second, func() {
		if err := ncw.StartContainerCollection(ctx); err != nil {
			logger.L().Error("error starting container collection", helpers.Error(err))
		}
	})

	// Start ordered event queue BEFORE tracers
	// No need to start queue anymore - it's just a data structure

	// Start event processing loop
	go ncw.eventProcessingLoop()

	// Start worker pool goroutine
	go ncw.workerPoolLoop()

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
	tracerManagerV2 := NewTracerManager(ncw.cfg, tracerFactory)
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
	ncw.StopContainerCollection()

	// Stop tracer manager
	if ncw.tracerManagerV2 != nil {
		ncw.tracerManagerV2.StopAllTracers()
	}

	// No need to stop queue - it's just a data structure

	// Close worker channel to signal worker goroutine to stop
	if ncw.workerChan != nil {
		close(ncw.workerChan)
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

func (ncw *ContainerWatcher) eventProcessingLoop() {
	ticker := time.NewTicker(50 * time.Millisecond)
	defer ticker.Stop()

	for {
		select {
		case <-ncw.ctx.Done():
			return
		case <-ticker.C:
			ncw.processQueueBatch()
		case <-ncw.orderedEventQueue.GetFullQueueAlertChannel():
			logger.L().Warning("ContainerWatcher - Processing events due to full queue alert")
			ncw.processQueueBatch()
		}
	}
}

func (ncw *ContainerWatcher) workerPoolLoop() {
	for {
		select {
		case <-ncw.ctx.Done():
			return
		case enrichedEvent := <-ncw.workerChan:
			ncw.workerPool.Invoke(enrichedEvent)
		}
	}
}

func (ncw *ContainerWatcher) processQueueBatch() {
	const batchSize = 1000
	processedCount := 0
	for !ncw.orderedEventQueue.Empty() && processedCount < batchSize {
		event, ok := ncw.orderedEventQueue.PopEvent()
		if !ok {
			break
		}
		ncw.enrichAndProcess(event)
		processedCount++
	}

}

func (ncw *ContainerWatcher) enrichAndProcess(event eventEntry) {
	enrichedEvent := ncw.eventEnricher.EnrichEvents(event)

	select {
	case ncw.workerChan <- enrichedEvent:
	default:
		logger.L().Warning("ContainerWatcher - Worker channel full, dropping event",
			helpers.String("eventType", string(event.EventType)),
			helpers.String("containerID", event.ContainerID))
	}
}
