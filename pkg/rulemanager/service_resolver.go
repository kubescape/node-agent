package rulemanager

import (
	"time"

	"github.com/hashicorp/golang-lru/v2/expirable"
	"github.com/kubescape/node-agent/pkg/k8sclient"
	"github.com/kubescape/node-agent/pkg/utils"
	"golang.org/x/sync/singleflight"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
)

const (
	defaultServiceCacheSize = 1024
	defaultServiceCacheTTL  = 1 * time.Minute
)

type serviceCacheEntry struct {
	selector map[string]string
}

// InitServicePeerLabelResolver registers a ServicePeerLabels hook backed by the Kubernetes client
// with a bounded LRU cache, singleflight request coalescing, and TTL refresh policy, so that Service
// destination endpoints in CEL rules resolve to their backend selector labels without repeated
// synchronous Kubernetes API reads or duplicate concurrent in-flight requests.
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
	var sf singleflight.Group

	utils.SetServicePeerLabels(func(namespace, name string) map[string]string {
		key := namespace + "/" + name
		if entry, ok := cache.Get(key); ok {
			return copyLabels(entry.selector)
		}

		res, _, _ := sf.Do(key, func() (any, error) {
			// Recheck cache inside singleflight in case another worker already populated it
			if entry, ok := cache.Get(key); ok {
				return copyLabels(entry.selector), nil
			}

			svc, err := k8sClient.GetWorkload(namespace, "Service", name)
			if err != nil {
				// Only cache negative results for confirmed NotFound responses;
				// transient errors (timeouts, network issues, RBAC) must not be cached.
				if apierrors.IsNotFound(err) {
					cache.Add(key, serviceCacheEntry{selector: nil})
				}
				return nil, nil
			}
			if svc == nil {
				cache.Add(key, serviceCacheEntry{selector: nil})
				return nil, nil
			}

			var selector map[string]string
			if svc.GetName() == "kubernetes" && svc.GetNamespace() == "default" {
				selector = svc.GetLabels()
			} else {
				selector = svc.GetServiceSelector()
			}

			copied := copyLabels(selector)
			cache.Add(key, serviceCacheEntry{selector: copied})
			return copyLabels(copied), nil
		})

		if res == nil {
			return nil
		}
		return res.(map[string]string)
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
