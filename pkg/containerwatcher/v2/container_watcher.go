package containerwatcher

import (
	"context"
	"fmt"
	"sync"
	"time"

	mapset "github.com/deckarep/golang-set/v2"
	containercollection "github.com/inspektor-gadget/inspektor-gadget/pkg/container-collection"
	containerutilsTypes "github.com/inspektor-gadget/inspektor-gadget/pkg/container-utils/types"
	apihelpers "github.com/inspektor-gadget/inspektor-gadget/pkg/gadget-service/api-helpers"
	"github.com/inspektor-gadget/inspektor-gadget/pkg/operators/kubemanager"
	"github.com/inspektor-gadget/inspektor-gadget/pkg/runtime"
	"github.com/inspektor-gadget/inspektor-gadget/pkg/runtime/local"
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
	"github.com/kubescape/node-agent/pkg/rulebindingmanager"
	"github.com/kubescape/node-agent/pkg/rulemanager"
	"github.com/kubescape/node-agent/pkg/sbommanager"
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
	eventEnricher       *EventEnricher

	// Managers
	tracerManagerV2 *TracerManager

	// Worker pool for processing events
	workerPool *ants.PoolWithFunc
	workerChan chan *events.EnrichedEvent // Channel for worker pool invocation

	// Third party components
	thirdPartyTracersInitializers mapset.Set[containerwatcher.CustomTracerInitializer]
	thirdPartyEnricher            containerwatcher.TaskBasedEnricher
	thirdPartyContainerReceivers  mapset.Set[containerwatcher.ContainerReceiver]

	// Cache and state
	objectCache          objectcache.ObjectCache
	ruleManagedPods      mapset.Set[string]
	metrics              metricsmanager.MetricsManager
	ruleBindingPodNotify *chan rulebindingmanager.RuleBindingNotify
	runtime              *containerutilsTypes.RuntimeConfig
	pool                 *workerpool.WorkerPool

	// Lifecycle
	gadgetRuntime                   runtime.Runtime
	mutex                           sync.RWMutex
	containerEolNotificationChannel chan *containercollection.Container

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
	thirdPartyEnricher containerwatcher.TaskBasedEnricher,
	processTreeManager processtree.ProcessTreeManager,
	clusterName string,
	objectCache objectcache.ObjectCache,
	networkStreamClient networkstream.NetworkStreamClient,
	containerProcessTree containerprocesstree.ContainerProcessTree,
	thirdPartyTracers containerwatcher.ThirdPartyTracers,
) (*ContainerWatcher, error) {

	// Create container collection
	containerCollection := &containercollection.ContainerCollection{}

	// Create tracer collection
	tracerCollection, err := tracercollection.NewTracerCollection(containerCollection)
	if err != nil {
		return nil, fmt.Errorf("creating tracer collection: %w", err)
	}

	// Create ordered event queue (50ms collection interval, increased buffer size)
	orderedEventQueue := NewOrderedEventQueue(cfg.OrderedEventQueue.CollectionDelay, cfg.OrderedEventQueue.Size, processTreeManager)

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
		thirdPartyTracers.ThirdPartyEventReceivers,
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
		workerChan:          make(chan *events.EnrichedEvent, cfg.WorkerChannelSize),

		// Third party components
		thirdPartyTracersInitializers: thirdPartyTracers.ThirdPartyTracersInitializers,
		thirdPartyEnricher:            thirdPartyEnricher,
		thirdPartyContainerReceivers:  mapset.NewSet[containerwatcher.ContainerReceiver](),

		// Cache and state
		objectCache:          objectCache,
		ruleManagedPods:      mapset.NewSet[string](),
		metrics:              metrics,
		ruleBindingPodNotify: ruleBindingPodNotify,
		runtime:              runtime,
		pool:                 workerpool.NewWithMaxRunningTime(cfg.WorkerPoolSize, 5*time.Second),

		// Lifecycle
		containerEolNotificationChannel: make(chan *containercollection.Container),
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
	thirdPartyEnricher containerwatcher.TaskBasedEnricher,
	processTreeManager processtree.ProcessTreeManager,
	clusterName string,
	objectCache objectcache.ObjectCache,
	networkStreamClient networkstream.NetworkStreamClient,
	containerProcessTree containerprocesstree.ContainerProcessTree,
	thirdPartyTracers containerwatcher.ThirdPartyTracers,
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
		thirdPartyEnricher,
		processTreeManager,
		clusterName,
		objectCache,
		networkStreamClient,
		containerProcessTree,
		thirdPartyTracers,
	)
}

// Start initializes and starts the container watcher
func (cw *ContainerWatcher) Start(ctx context.Context) error {
	cw.mutex.Lock()
	defer cw.mutex.Unlock()

	if cw.running {
		return fmt.Errorf("container watcher is already running")
	}

	cw.ctx = ctx

	go func() {
		// Read from the container EOL notification channel and call unregisterContainer
		for {
			select {
			case container := <-cw.containerEolNotificationChannel:
				if container != nil {
					logger.L().Debug("Container EOL notification received", helpers.String("containerID", container.Runtime.ContainerID))
					cw.unregisterContainer(container)
				}
			case <-ctx.Done():
				logger.L().Ctx(ctx).Info("Stopping container EOL notification handler")
				return
			}
		}
	}()

	cw.containerProfileManager.RegisterForContainerEndOfLife(cw.containerEolNotificationChannel)

	// Start container collection (similar to v1 startContainerCollection)
	logger.L().TimedWrapper("StartContainerCollection", 5*time.Second, func() {
		if err := cw.StartContainerCollection(ctx); err != nil {
			logger.L().Error("error starting container collection", helpers.Error(err))
		}
	})

	// Start ordered event queue BEFORE tracers

	// Start event processing loop
	go cw.eventProcessingLoop()

	// Start worker pool goroutine
	go cw.workerPoolLoop()

	cw.gadgetRuntime = local.New()
	if err := cw.gadgetRuntime.Init(nil); err != nil {
		logger.L().Fatal("runtime init", helpers.Error(err))
	}

	param := apihelpers.ToParamDescs(kubemanager.KubeManagerOperator.GlobalParams()).ToParams()
	if err := param.Set(kubemanager.ParamHookMode, "fanotify+ebpf"); err != nil {
		return fmt.Errorf("setting kube-manager hook mode: %w", err)
	}
	if err := kubemanager.KubeManagerOperator.Init(param); err != nil {
		return fmt.Errorf("initializing kube-manager operator: %w", err)
	}

	// Create tracer factory
	tracerFactory := tracers.NewTracerFactory(
		cw.containerCollection,
		cw.tracerCollection,
		cw.containerSelector,
		cw.orderedEventQueue,
		cw.socketEnricher,
		cw.containerProfileManager,
		cw.ruleManager,
		cw.thirdPartyTracersInitializers,
		cw.thirdPartyEnricher,
		cw.cfg,
		cw.processTreeManager,
		cw.gadgetRuntime,
	)

	// Initialize tracer manager
	tracerManagerV2 := NewTracerManager(cw.cfg, tracerFactory)
	if err := tracerManagerV2.StartAllTracers(ctx); err != nil {
		return fmt.Errorf("starting tracer manager: %w", err)
	}
	cw.tracerManagerV2 = tracerManagerV2

	cw.running = true
	logger.L().Info("ContainerWatcher started successfully")
	return nil
}

// Stop gracefully stops the container watcher
func (cw *ContainerWatcher) Stop() {
	cw.mutex.Lock()
	defer cw.mutex.Unlock()

	if !cw.running {
		return
	}

	logger.L().Info("Stopping ContainerWatcher...")

	// Stop container manager
	cw.StopContainerCollection()

	// Stop tracer manager
	if cw.tracerManagerV2 != nil {
		cw.tracerManagerV2.StopAllTracers()
	}

	cw.gadgetRuntime.Close()

	// Close worker channel to signal worker goroutine to stop
	if cw.workerChan != nil {
		close(cw.workerChan)
	}

	// Stop worker pool
	if cw.workerPool != nil {
		cw.workerPool.Release()
	}

	cw.running = false
	logger.L().Info("ContainerWatcher stopped successfully")
}

// Ready returns true if the container watcher is ready to process events
func (cw *ContainerWatcher) Ready() bool {
	cw.mutex.RLock()
	defer cw.mutex.RUnlock()
	return cw.running
}

// GetContainerCollection returns the container collection
func (cw *ContainerWatcher) GetContainerCollection() *containercollection.ContainerCollection {
	return cw.containerCollection
}

// GetTracerCollection returns the tracer collection
func (cw *ContainerWatcher) GetTracerCollection() *tracercollection.TracerCollection {
	return cw.tracerCollection
}

// GetSocketEnricher returns the socket enricher
func (cw *ContainerWatcher) GetSocketEnricher() *socketenricher.SocketEnricher {
	return cw.socketEnricher
}

// GetContainerSelector returns the container selector
func (cw *ContainerWatcher) GetContainerSelector() *containercollection.ContainerSelector {
	return &cw.containerSelector
}

func (cw *ContainerWatcher) RegisterContainerReceiver(receiver containerwatcher.ContainerReceiver) {
	cw.thirdPartyContainerReceivers.Add(receiver)
}

// UnregisterContainerReceiver unregisters a container receiver
func (cw *ContainerWatcher) UnregisterContainerReceiver(receiver containerwatcher.ContainerReceiver) {
	cw.thirdPartyContainerReceivers.Remove(receiver)
}

func (cw *ContainerWatcher) eventProcessingLoop() {
	ticker := time.NewTicker(50 * time.Millisecond)
	defer ticker.Stop()

	for {
		select {
		case <-cw.ctx.Done():
			return
		case <-ticker.C:
			cw.processQueueBatch()
		case <-cw.orderedEventQueue.GetFullQueueAlertChannel():
			logger.L().Warning("ContainerWatcher - Processing events due to full queue alert")
			cw.processQueueBatch()
		}
	}
}

func (cw *ContainerWatcher) workerPoolLoop() {
	for {
		select {
		case <-cw.ctx.Done():
			return
		case enrichedEvent := <-cw.workerChan:
			cw.workerPool.Invoke(enrichedEvent)
		}
	}
}

func (cw *ContainerWatcher) processQueueBatch() {
	batchSize := cw.cfg.EventBatchSize
	processedCount := 0
	for !cw.orderedEventQueue.Empty() && processedCount < batchSize {
		event, ok := cw.orderedEventQueue.PopEvent()
		if !ok {
			break
		}
		cw.enrichAndProcess(event)
		processedCount++
	}

}

func (cw *ContainerWatcher) enrichAndProcess(entry EventEntry) {
	enrichedEvent := cw.eventEnricher.EnrichEvents(entry)

	select {
	case cw.workerChan <- enrichedEvent:
	default:
		if cw.cfg.BlockEvents {
			logger.L().Warning("ContainerWatcher - Worker channel full, blocking until space available",
				helpers.String("eventType", string(entry.EventType)),
				helpers.String("containerID", entry.ContainerID))
			cw.workerChan <- enrichedEvent
		} else {
			logger.L().Warning("ContainerWatcher - Worker channel full, dropping event",
				helpers.String("eventType", string(entry.EventType)),
				helpers.String("containerID", entry.ContainerID))
		}
	}
}
