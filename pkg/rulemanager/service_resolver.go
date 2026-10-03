package rulemanager

import (
	"time"

	"github.com/hashicorp/golang-lru/v2/expirable"
	"github.com/kubescape/node-agent/pkg/k8sclient"
	"github.com/kubescape/node-agent/pkg/utils"
)

const (
	defaultServiceCacheSize = 1024
	defaultServiceCacheTTL  = 1 * time.Minute
)

type serviceCacheEntry struct {
	selector map[string]string
}

// InitServicePeerLabelResolver registers a ServicePeerLabels hook backed by the Kubernetes client
// with a bounded LRU cache and TTL refresh policy, so that Service destination endpoints in CEL rules
// resolve to their backend selector labels without repeated synchronous Kubernetes API reads.
func InitServicePeerLabelResolver(k8sClient k8sclient.K8sClientInterface) {
	InitServicePeerLabelResolverWithCache(k8sClient, defaultServiceCacheSize, defaultServiceCacheTTL)
}

// InitServicePeerLabelResolverWithCache initializes the ServicePeerLabels hook with explicit cache size and TTL.
func InitServicePeerLabelResolverWithCache(k8sClient k8sclient.K8sClientInterface, size int, ttl time.Duration) {
	if k8sClient == nil {
		utils.SetServicePeerLabels(nil)
		return
	}
	if size <= 0 {
		size = defaultServiceCacheSize
	}
	if ttl <= 0 {
		ttl = defaultServiceCacheTTL
	}

	cache := expirable.NewLRU[string, serviceCacheEntry](size, nil, ttl)

	utils.SetServicePeerLabels(func(namespace, name string) map[string]string {
		key := namespace + "/" + name
		if entry, ok := cache.Get(key); ok {
			return copyLabels(entry.selector)
		}

		var selector map[string]string
		svc, err := k8sClient.GetWorkload(namespace, "Service", name)
		if err == nil && svc != nil {
			if svc.GetName() == "kubernetes" && svc.GetNamespace() == "default" {
				selector = svc.GetLabels()
			} else {
				selector = svc.GetServiceSelector()
			}
		}

		cache.Add(key, serviceCacheEntry{selector: copyLabels(selector)})
		return copyLabels(selector)
	})
}

func copyLabels(labels map[string]string) map[string]string {
	if labels == nil {
		return nil
	}
	cp := make(map[string]string, len(labels))
	for k, v := range labels {
		cp[k] = v
	}
	return cp
}
