package containerprofilemanager

import (
	"context"
	"fmt"
	"os"
	"strconv"
	"sync"
	"sync/atomic"
	"time"

	mapset "github.com/deckarep/golang-set/v2"
	"github.com/goradd/maps"
	containercollection "github.com/inspektor-gadget/inspektor-gadget/pkg/container-collection"
	"github.com/kubescape/go-logger"
	"github.com/kubescape/go-logger/helpers"
	"github.com/kubescape/node-agent/pkg/config"
	"github.com/kubescape/node-agent/pkg/containerprofilemanager"
	"github.com/kubescape/node-agent/pkg/containerprofilemanager/v1/queue"
	"github.com/kubescape/node-agent/pkg/dnsmanager"
	"github.com/kubescape/node-agent/pkg/k8sclient"
	"github.com/kubescape/node-agent/pkg/objectcache"
	"github.com/kubescape/node-agent/pkg/rulebindingmanager"
	"github.com/kubescape/node-agent/pkg/seccompmanager"
	"github.com/kubescape/node-agent/pkg/storage"
	"github.com/kubescape/storage/pkg/apis/softwarecomposition/v1beta1"
)

// ContainerEntry holds container data with its own mutex for fine-grained locking
type ContainerEntry struct {
	data *containerData
	mu   sync.RWMutex
	// ready channel is used to signal when the container entry is fully initialized
	ready chan struct{}
}

// containerData contains all the monitored data for a single container
type containerData struct {
	// Core container information
	watchedContainerData *objectcache.WatchedContainerData

	// Apparent size
	size atomic.Int64

	// Cleanup resources
	timer *time.Timer // For max sniffing time

	// Events reported for this container that need to be saved to the profile
	capabilites   mapset.Set[string]
	syscalls      mapset.Set[string]
	endpoints     *maps.SafeMap[string, *v1beta1.HTTPEndpoint]
	execs         *maps.SafeMap[string, []string]                     // Map of execs, key is SHA256 hash
	opens         *maps.SafeMap[string, mapset.Set[string]]           // Map of opens, key is file path
	rulePolicies  *maps.SafeMap[string, *v1beta1.RulePolicy]          // Map of rule policies, key is rule ID
	callStacks    *maps.SafeMap[string, *v1beta1.IdentifiedCallStack] // Map of callstacks, key is SHA256 hash
	networks      mapset.Set[NetworkEvent]
	droppedEvents bool // Indicates if any events were dropped during monitoring

	// Last reported completion/statuses
	lastReportedCompletion string
	lastReportedStatus     string
}

// ContainerProfileManager manages container profiles and their lifecycle
type ContainerProfileManager struct {
	ctx               context.Context
	cfg               config.Config
	k8sClient         k8sclient.K8sClientInterface
	k8sObjectCache    objectcache.K8sObjectCache
	storageClient     storage.StorageClient
	dnsResolverClient dnsmanager.DNSResolver
	seccompManager    seccompmanager.SeccompManagerClient
	enricher          containerprofilemanager.Enricher
	ruleBindingCache  rulebindingmanager.RuleBindingCache
	queueData         *queue.QueueData

	// Container storage with embedded locking
	containers   map[string]*ContainerEntry
	containersMu sync.RWMutex

	// Notification channels for container end of life
	maxSniffTimeNotificationChan []chan *containercollection.Container
	notificationMu               sync.RWMutex
}

// NewContainerProfileManager creates a new container profile manager
func NewContainerProfileManager(
	ctx context.Context,
	cfg config.Config,
	k8sClient k8sclient.K8sClientInterface,
	k8sObjectCache objectcache.K8sObjectCache,
	storageClient storage.StorageClient,
	dnsResolverClient dnsmanager.DNSResolver,
	seccompManager seccompmanager.SeccompManagerClient,
	enricher containerprofilemanager.Enricher,
	ruleBindingCache rulebindingmanager.RuleBindingCache,
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

var _ containerprofilemanager.ContainerProfileManagerClient = (*ContainerProfileManager)(nil)
var _ queue.ErrorCallback = (*ContainerProfileManager)(nil)
