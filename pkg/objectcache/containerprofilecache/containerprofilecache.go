// Package containerprofilecache provides a unified, container-keyed cache for ContainerProfile objects.
package containerprofilecache

import (
	containercollection "github.com/inspektor-gadget/inspektor-gadget/pkg/container-collection"
	"github.com/kubescape/node-agent/pkg/config"
	"github.com/kubescape/node-agent/pkg/objectcache"
	"github.com/kubescape/node-agent/pkg/objectcache/applicationprofilecache/callstackcache"
	"github.com/kubescape/node-agent/pkg/storage"
	"github.com/kubescape/storage/pkg/apis/softwarecomposition/v1beta1"
)

// ContainerProfileCacheImpl is the unified container-keyed cache for ContainerProfile objects.
// TODO: step 3 fills in the implementation fields and method bodies.
type ContainerProfileCacheImpl struct {
	cfg            config.Config
	storageClient  storage.ProfileClient
	k8sObjectCache objectcache.K8sObjectCache
}

// NewContainerProfileCache creates a new ContainerProfileCacheImpl.
// TODO: step 3 initialises internal maps, locks, and intervals.
func NewContainerProfileCache(cfg config.Config, storageClient storage.ProfileClient, k8sObjectCache objectcache.K8sObjectCache) *ContainerProfileCacheImpl {
	return &ContainerProfileCacheImpl{
		cfg:            cfg,
		storageClient:  storageClient,
		k8sObjectCache: k8sObjectCache,
	}
}

func (c *ContainerProfileCacheImpl) GetContainerProfile(_ string) *v1beta1.ContainerProfile {
	return nil
}

func (c *ContainerProfileCacheImpl) GetContainerProfileState(_ string) *objectcache.ProfileState {
	return nil
}

func (c *ContainerProfileCacheImpl) GetCallStackSearchTree(_ string) *callstackcache.CallStackSearchTree {
	return nil
}

func (c *ContainerProfileCacheImpl) ContainerCallback(_ containercollection.PubSubEvent) {
}
