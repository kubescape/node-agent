package containerprofilemanager

import (
	"context"
	"fmt"
	"os"
	"strconv"
	"sync"
	"sync/atomic"
	"time"

	"github.com/armosec/armoapi-go/armotypes"
	mapset "github.com/deckarep/golang-set/v2"
	"github.com/goradd/maps"
	containercollection "github.com/inspektor-gadget/inspektor-gadget/pkg/container-collection"
	"github.com/inspektor-gadget/inspektor-gadget/pkg/operators/common"
	"github.com/kubescape/go-logger"
	"github.com/kubescape/go-logger/helpers"
	"github.com/kubescape/node-agent/pkg/config"
	"github.com/kubescape/node-agent/pkg/containerprofilemanager"
	"github.com/kubescape/node-agent/pkg/containerprofilemanager/v1/queue"
	"github.com/kubescape/node-agent/pkg/dnsmanager"
	"github.com/kubescape/node-agent/pkg/k8sclient"
	"github.com/kubescape/node-agent/pkg/objectcache"
	"github.com/kubescape/node-agent/pkg/otelsetup"
	"github.com/kubescape/node-agent/pkg/rulebindingmanager"
	"github.com/kubescape/node-agent/pkg/seccompmanager"
	"github.com/kubescape/node-agent/pkg/storage"
	"github.com/kubescape/node-agent/pkg/utils"
	"github.com/kubescape/storage/pkg/apis/softwarecomposition/v1beta1"
)

// ContainerEntry holds container data with its own mutex for fine-grained locking
type ContainerEntry struct {
	data *containerData
	mu   sync.RWMutex
	// ready channel is used to signal when the container entry is fully initialized
	ready chan struct{}
	// readyOnce ensures the ready channel is closed exactly once
	readyOnce sync.Once
}

// containerData contains all the monitored data for a single container
type containerData struct {
	// Core container information
	watchedContainerData *objectcache.WatchedContainerData
	queueErrors          chan error // One retained terminal verdict; accessed under the entry lock.
	monitorDone          chan struct{}
	monitorDoneOnce      sync.Once

	// Apparent size of observations collected since the last flush; deferred peers
	// remain in networks without being charged to each new active batch.
	size atomic.Int64

	// Cleanup resources
	timer *time.Timer // For max sniffing time

	// Events reported for this container that need to be saved to the profile
	capabilites          mapset.Set[string]
	syscalls             mapset.Set[string]
	endpoints            *maps.SafeMap[string, *v1beta1.HTTPEndpoint]
	execs                *maps.SafeMap[string, []string]                     // Map of execs, key is SHA256 hash
	opens                *maps.SafeMap[string, mapset.Set[string]]           // Map of opens, key is file path
	rulePolicies         *maps.SafeMap[string, *v1beta1.RulePolicy]          // Map of rule policies, key is rule ID
	callStacks           *maps.SafeMap[string, *v1beta1.IdentifiedCallStack] // Map of callstacks, key is SHA256 hash
	networks             mapset.Set[NetworkEvent]                            // Union used for deduplication and interval/final retries.
	activeNetworks       mapset.Set[NetworkEvent]                            // Newly collected observations since the last flush.
	networkFlushForSize  bool                                                // Size-triggered saves visit only activeNetworks.
	deferredNetworks     mapset.Set[NetworkEvent]
	prevDeferredNetworks mapset.Set[NetworkEvent]
	droppedEvents        bool // Indicates if any events were dropped during monitoring

	// Positive durations give unresolved peers an informer catch-up window across rapid saves.
	networkDeferralDuration time.Duration
	networkDeferredUntil    map[NetworkEvent]time.Time
	// Deferred admission is tracked independently from the active flush budget.
	networkDeferredSizeLimit int64
	networkDeferredSize      int64
	networkDeferredSizes     map[NetworkEvent]int64

	// Service port snapshots keep report-time accounting and serialization consistent.
	servicePorts map[NetworkEvent][]uint16

	// Last reported completion/statuses
	lastReportedCompletion string
	lastReportedStatus     string
}

// stopMonitoring unblocks lifecycle signal producers before terminal cleanup.
func (data *containerData) stopMonitoring() {
	if data.monitorDone != nil {
		data.monitorDoneOnce.Do(func() { close(data.monitorDone) })
	}
}

// ContainerProfileManager manages container profiles and their lifecycle
type ContainerProfileManager struct {
	lifecycleQueue    utils.LifecycleQueue
	pendingAdds       utils.PendingAdds
	ctx               context.Context
	cfg               config.Config
	k8sClient         k8sclient.K8sClientInterface
	k8sObjectCache    objectcache.K8sObjectCache
	k8sInventory      common.K8sInventoryCache
	storageClient     storage.ProfileCreator
	dnsResolverClient dnsmanager.DNSResolver
	seccompManager    seccompmanager.SeccompManagerClient
	enricher          containerprofilemanager.Enricher
	ruleBindingCache  rulebindingmanager.RuleBindingCache
	queueData         *queue.QueueData

	// Cloud metadata for annotation population
	cloudMetadata *armotypes.CloudMetadata

	// Container storage with embedded locking
	containers   map[string]*ContainerEntry
	containersMu sync.RWMutex

	// Notification channels for container end of life
	maxSniffTimeNotificationChan []chan *containercollection.Container
	notificationMu               sync.RWMutex

	completionNotifier objectcache.CompletionNotifier

	lifecycleTracker *otelsetup.ProfileLifecycleTracker

	// syscallFlusher, if set, is called right before a container's final forced profile
	// save to request an immediate out-of-band fetch of its not-yet-polled syscalls. See
	// SetSyscallFlusher and kubescape/node-agent#922. Stored via atomic.Pointer: it's written
	// once during startup wiring (TracerFactory.CreateAllTracers, after StartContainerCollection
	// has already begun enumerating containers), and flushAndSettle reads it from whatever
	// per-container monitorContainer goroutine happens to be running at that time - a plain
	// field would be an unsynchronized data race between that write and those concurrent reads.
	syscallFlusher atomic.Pointer[func()]
}

func (cpm *ContainerProfileManager) SetCompletionNotifier(n objectcache.CompletionNotifier) {
	cpm.completionNotifier = n
}

// SetK8sInventory sets the k8s inventory cache (primarily used in tests)
func (cpm *ContainerProfileManager) SetK8sInventory(k8sInventory common.K8sInventoryCache) {
	cpm.k8sInventory = k8sInventory
}

// SetSyscallFlusher implements containerprofilemanager.ContainerProfileManagerClient.
func (cpm *ContainerProfileManager) SetSyscallFlusher(flush func()) {
	cpm.syscallFlusher.Store(&flush)
}

func (cpm *ContainerProfileManager) notifyCompleted(containerID string) {
	if cpm.completionNotifier != nil {
		cpm.completionNotifier.NotifyContainerCompleted(containerID)
	}
}

// NewContainerProfileManager creates a new container profile manager
func NewContainerProfileManager(
	ctx context.Context,
	cfg config.Config,
	k8sClient k8sclient.K8sClientInterface,
	k8sObjectCache objectcache.K8sObjectCache,
	storageClient storage.ProfileCreator,
	dnsResolverClient dnsmanager.DNSResolver,
	seccompManager seccompmanager.SeccompManagerClient,
	enricher containerprofilemanager.Enricher,
	ruleBindingCache rulebindingmanager.RuleBindingCache,
	cloudMetadata *armotypes.CloudMetadata,
) (*ContainerProfileManager, error) {
	containerProfileManager := &ContainerProfileManager{
		ctx:                          ctx,
		cfg:                          cfg,
		k8sClient:                    k8sClient,
		k8sObjectCache:               k8sObjectCache,
		storageClient:                storageClient,
		dnsResolverClient:            dnsResolverClient,
		seccompManager:               seccompManager,
		enricher:                     enricher,
		ruleBindingCache:             ruleBindingCache,
		containers:                   make(map[string]*ContainerEntry),
		maxSniffTimeNotificationChan: make([]chan *containercollection.Container, 0),
		cloudMetadata:                cloudMetadata,
		lifecycleTracker:             otelsetup.NewProfileLifecycleTracker(),
	}

	if cfg.KubernetesMode {
		if k8sInventory, err := common.GetK8sInventoryCache(); err == nil && k8sInventory != nil {
			containerProfileManager.k8sInventory = k8sInventory
			k8sInventory.Start()
		} else if err != nil {
			logger.L().Debug("failed to initialize k8s inventory cache in container profile manager", helpers.Error(err))
		}
	}

	// Initialize queue
	queueDir := os.Getenv("QUEUE_DIR")
	if queueDir == "" {
		queueDir = queue.DefaultQueueDir
		logger.L().Info("QUEUE_DIR is not set, using default directory", helpers.String("default", queue.DefaultQueueDir))
	}

	// Get max queue size from environment or use default
	maxQueueSize := queue.DefaultMaxQueueSize
	if maxSizeStr := os.Getenv("MAX_QUEUE_SIZE"); maxSizeStr != "" {
		if size, err := strconv.Atoi(maxSizeStr); err == nil && size > 0 {
			maxQueueSize = size
		}
	}

	// Initialize queue with storage as the ProfileCreator
	queueData, err := queue.NewQueueData(ctx, storageClient, queue.QueueConfig{
		QueueName:       queue.DefaultQueueName,
		QueueDir:        queueDir,
		MaxQueueSize:    maxQueueSize,
		RetryInterval:   queue.DefaultRetryInterval,
		ItemsPerSegment: queue.ItemsPerSegment,
		ErrorCallback:   containerProfileManager,
	})
	if err != nil {
		return nil, fmt.Errorf("failed to initialize queue: %w", err)
	}

	containerProfileManager.queueData = queueData

	// Start queue processing
	containerProfileManager.queueData.Start()

	logger.L().Info("container profile manager initialized with persistent queue",
		helpers.String("queueDir", queueDir),
		helpers.Int("maxQueueSize", maxQueueSize),
		helpers.Int("currentQueueSize", queueData.GetQueueSize()))

	return containerProfileManager, nil
}

// Close stops container timers, the persistent queue, and the Kubernetes inventory.
func (cpm *ContainerProfileManager) Close() {
	// Stop all container timers and clear container map
	cpm.containersMu.Lock()
	for containerID, entry := range cpm.containers {
		entry.mu.Lock()
		if entry.data != nil && entry.data.timer != nil {
			entry.data.timer.Stop()
			entry.data.timer = nil
		}
		entry.mu.Unlock()
		delete(cpm.containers, containerID)
	}
	cpm.containersMu.Unlock()

	if cpm.queueData != nil {
		_ = cpm.queueData.Close()
	}

	if cpm.k8sInventory != nil {
		cpm.k8sInventory.Stop()
	}
}

var _ containerprofilemanager.ContainerProfileManagerClient = (*ContainerProfileManager)(nil)
var _ queue.ErrorCallback = (*ContainerProfileManager)(nil)
