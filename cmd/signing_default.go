//go:build !experimental_signing

package main

import (
	"context"
	"github.com/kubescape/node-agent/pkg/config"
	"github.com/kubescape/node-agent/pkg/exporters"
	"github.com/kubescape/node-agent/pkg/healthmanager"
	"github.com/kubescape/node-agent/pkg/objectcache/containerprofilecache"
	rulebindingcachev1 "github.com/kubescape/node-agent/pkg/rulebindingmanager/cache"
	"github.com/kubescape/node-agent/pkg/rulemanager/ruleswatcher"
)

func verifiedClusterDataPath() (string, func(), error) {
	return "/etc/config/clusterData.json", func() {}, nil
}
func configureSigningHealth(h *healthmanager.HealthManager) {}
func configureSigning(ctx context.Context, cfg config.Config, cpc *containerprofilecache.ContainerProfileCacheImpl, rulesWatcher *ruleswatcher.RulesWatcherImpl, ruleBindingCache *rulebindingcachev1.RBCache, exporter exporters.Exporter) {
}
