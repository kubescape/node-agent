package applicationprofilemanager

import (
	"sync"

	mapset "github.com/deckarep/golang-set/v2"
	"github.com/goradd/maps"
	"github.com/kubescape/go-logger"
	"github.com/kubescape/go-logger/helpers"
	helpersv1 "github.com/kubescape/k8s-interface/instanceidhandler/v1/helpers"
	"github.com/kubescape/storage/pkg/apis/softwarecomposition/v1beta1"
)

// APMetadata holds metadata about an application profile
type APMetadata struct {
	Status           string
	CompletionStatus string
	Wlid             string
}

// APMetadataCache caches application profile metadata and tracks fetched namespaces
type APMetadataCache struct {
	metadataCache     maps.SafeMap[string, APMetadata] // key is WLID
	fetchedNamespaces mapset.Set[string]               // Track which namespaces we've already fetched
	lock              sync.Mutex                       // Lock for synchronizing namespace fetching
}

// NewAPMetadataCache creates a new APMetadataCache
func NewAPMetadataCache() *APMetadataCache {
	return &APMetadataCache{
		metadataCache:     maps.SafeMap[string, APMetadata]{},
		fetchedNamespaces: mapset.NewSet[string](),
	}
}

// Get retrieves metadata for a given WLID
func (c *APMetadataCache) Get(wlid string) (APMetadata, bool) {
	return c.metadataCache.Load(wlid)
}

// Has checks if a given WLID exists in the cache
func (c *APMetadataCache) Has(wlid string) bool {
	return c.metadataCache.Has(wlid)
}

// Set stores metadata for a given WLID
func (c *APMetadataCache) Set(wlid string, metadata APMetadata) {
	c.metadataCache.Set(wlid, metadata)
}

// IsNamespaceFetched checks if application profiles for a namespace have been fetched
func (c *APMetadataCache) IsNamespaceFetched(namespace string) bool {
	return c.fetchedNamespaces.Contains(namespace)
}

// MarkNamespaceFetched marks a namespace as having had its application profiles fetched
func (c *APMetadataCache) MarkNamespaceFetched(namespace string) {
	c.fetchedNamespaces.Add(namespace)
}

// PopulateFromApplicationProfiles populates the cache from a list of application profiles
func (c *APMetadataCache) PopulateFromApplicationProfiles(aps *v1beta1.ApplicationProfileList, namespace string) {
	c.lock.Lock()
	defer c.lock.Unlock()

	// Only process if we haven't already fetched this namespace
	if !c.fetchedNamespaces.Contains(namespace) {
		for _, ap := range aps.Items {
			wlid, ok := ap.Annotations[helpersv1.WlidMetadataKey]
			if !ok {
				continue
			}

			status := ap.Annotations[helpersv1.StatusMetadataKey]
			completionStatus := ap.Annotations[helpersv1.CompletionMetadataKey]

			c.metadataCache.Set(wlid, APMetadata{
				Status:           status,
				CompletionStatus: completionStatus,
				Wlid:             wlid,
			})
		}

		// Mark this namespace as fetched
		c.fetchedNamespaces.Add(namespace)

		logger.L().Debug("APMetadataCache - populated cache for namespace",
			helpers.String("namespace", namespace),
			helpers.Int("profiles", len(aps.Items)))
	}
}
