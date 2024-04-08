package rulemanager

import (
	"context"
	"github.com/kubescape/node-agent/pkg/config"
	"github.com/kubescape/node-agent/pkg/exporters"
	"github.com/kubescape/node-agent/pkg/k8sclient"
	"github.com/kubescape/node-agent/pkg/objectcache"
	"github.com/kubescape/node-agent/pkg/storage"

	bindingcache "github.com/kubescape/node-agent/pkg/rulebindingmanager/cache"

	"github.com/kubescape/node-agent/pkg/metricsmanager"

	mapset "github.com/deckarep/golang-set/v2"

	storageUtils "github.com/kubescape/storage/pkg/utils"
)

func CreateRuleManagerMock(clusterName string, storageClient storage.StorageClient, ruleBindingCache *bindingcache.RBCache) *RuleManager {
	k8sClient := &k8sclient.K8sClientMock{}
	return &RuleManager{
		cfg:               config.Config{},
		ctx:               context.Background(),
		k8sClient:         k8sClient,
		containerMutexes:  storageUtils.NewMapMutex[string](),
		trackedContainers: mapset.NewSet[string](),
		ruleBindingCache:  ruleBindingCache,
		objectCache:       &objectcache.ObjectCacheMock{},
		exporter:          &exporters.ExporterMock{},
		metrics:           metricsmanager.NewMetricsMock(),
	}
}
