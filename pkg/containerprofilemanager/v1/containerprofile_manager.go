package containerprofilemanager

import (
	"context"
	"sync"
	"time"

	mapset "github.com/deckarep/golang-set/v2"
	"github.com/goradd/maps"
	containercollection "github.com/inspektor-gadget/inspektor-gadget/pkg/container-collection"
	"github.com/kubescape/node-agent/pkg/config"
	"github.com/kubescape/node-agent/pkg/containerprofilemanager"
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
}

// containerData contains all the monitored data for a single container
type containerData struct {
	// Core container information
	watchedContainerData *objectcache.WatchedContainerData

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
	syscallPeekFunc   func(nsMountId uint64) ([]string, error)
	seccompManager    seccompmanager.SeccompManagerClient
	enricher          containerprofilemanager.Enricher
	ruleBindingCache  rulebindingmanager.RuleBindingCache

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
	return &ContainerProfileManager{
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
	}, nil
}

var _ containerprofilemanager.ContainerProfileManagerClient = (*ContainerProfileManager)(nil)
