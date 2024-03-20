package rulemanager

import (
	"context"
	"node-agent/pkg/config"
	"node-agent/pkg/k8sclient"
	"node-agent/pkg/ruleengine"
	"node-agent/pkg/rulemanager/exporters"
	"node-agent/pkg/storage"

	bindingcache "node-agent/pkg/rulebindingmanager/cache"

	"node-agent/pkg/metricsmanager"

	mapset "github.com/deckarep/golang-set/v2"

	storageUtils "github.com/kubescape/storage/pkg/utils"
)

func CreateRuleManagerMock(clusterName string, storageClient storage.StorageClient, ruleBindingCache *bindingcache.RBCache) *RuleManager {
	k8sClient := &k8sclient.K8sClientMock{}
	return &RuleManager{
		cfg:               config.Config{},
		clusterName:       clusterName,
		ctx:               context.Background(),
		k8sClient:         k8sClient,
		containerMutexes:  storageUtils.NewMapMutex[string](),
		trackedContainers: mapset.NewSet[string](),
		ruleBindingCache:  ruleBindingCache,
		k8sObjectProvider: ruleengine.NewK8sObjectProvider(k8sClient),
		exporter:          &exporters.ExporterMock{},
		metrics:           metricsmanager.NewMetricsMock(),
		// storageClient:     kssfake.NewSimpleClientset(),
	}
}
