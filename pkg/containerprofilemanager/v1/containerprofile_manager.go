package containerprofilemanager

import (
	"context"

	"github.com/goradd/maps"
	containercollection "github.com/inspektor-gadget/inspektor-gadget/pkg/container-collection"
	"github.com/kubescape/node-agent/pkg/config"
	"github.com/kubescape/node-agent/pkg/containerprofilemanager"
	"github.com/kubescape/node-agent/pkg/dnsmanager"
	"github.com/kubescape/node-agent/pkg/k8sclient"
	"github.com/kubescape/node-agent/pkg/objectcache"
	"github.com/kubescape/node-agent/pkg/resourcelocks"
	"github.com/kubescape/node-agent/pkg/rulebindingmanager"
	"github.com/kubescape/node-agent/pkg/seccompmanager"
	"github.com/kubescape/node-agent/pkg/storage"
)

type ContainerProfileManager struct {
	ctx                          context.Context
	cfg                          config.Config
	k8sClient                    k8sclient.K8sClientInterface
	k8sObjectCache               objectcache.K8sObjectCache
	storageClient                storage.StorageClient
	dnsResolverClient            dnsmanager.DNSResolver
	syscallPeekFunc              func(nsMountId uint64) ([]string, error)
	seccompManager               seccompmanager.SeccompManagerClient
	enricher                     containerprofilemanager.Enricher
	ruleBindingCache             rulebindingmanager.RuleBindingCache
	containerIDToInfo            maps.SafeMap[string, *containerData]
	maxSniffTimeNotificationChan []chan *containercollection.Container
	containerLocks               *resourcelocks.ResourceLocks
}

func NewContainerProfileManager(
	ctx context.Context,
	cfg config.Config,
	k8sClient k8sclient.K8sClientInterface,
	k8sObjectCache objectcache.K8sObjectCache,
	storageClient storage.StorageClient,
	dnsResolverClient dnsmanager.DNSResolver,
	syscallPeekFunc func(nsMountId uint64) ([]string, error),
	seccompManager seccompmanager.SeccompManagerClient,
	enricher containerprofilemanager.Enricher,
	ruleBindingCache rulebindingmanager.RuleBindingCache,
) *ContainerProfileManager {
	return &ContainerProfileManager{
		ctx:                          ctx,
		cfg:                          cfg,
		k8sClient:                    k8sClient,
		k8sObjectCache:               k8sObjectCache,
		storageClient:                storageClient,
		dnsResolverClient:            dnsResolverClient,
		syscallPeekFunc:              syscallPeekFunc,
		seccompManager:               seccompManager,
		enricher:                     enricher,
		ruleBindingCache:             ruleBindingCache,
		containerLocks:               resourcelocks.New(),
		containerIDToInfo:            maps.SafeMap[string, *containerData]{},
		maxSniffTimeNotificationChan: make([]chan *containercollection.Container, 0),
	}
}

var _ containerprofilemanager.ContainerProfileManagerClient = (*ContainerProfileManager)(nil)
