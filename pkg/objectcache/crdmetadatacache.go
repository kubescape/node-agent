package objectcache

import (
	"sync"

	mapset "github.com/deckarep/golang-set/v2"
	"github.com/goradd/maps"
	"github.com/kubescape/go-logger"
	"github.com/kubescape/go-logger/helpers"
)

// CRDMetadataCache is a generic cache for CRD metadata that tracks fetched namespaces
type CRDMetadataCache[T any] struct {
	metadataCache     maps.SafeMap[string, T] // key is typically a unique identifier like WLID
	fetchedNamespaces mapset.Set[string]      // Track which namespaces we've already fetched
	lock              sync.Mutex              // Lock for synchronizing namespace fetching
}

// NewCRDMetadataCache creates a new CRDMetadataCache for type T
func NewCRDMetadataCache[T any]() *CRDMetadataCache[T] {
	return &CRDMetadataCache[T]{
		metadataCache:     maps.SafeMap[string, T]{},
		fetchedNamespaces: mapset.NewSet[string](),
	}
}

// Get retrieves metadata for a given key
func (c *CRDMetadataCache[T]) Get(key string) (T, bool) {
	return c.metadataCache.Load(key)
}

// Has checks if a given key exists in the cache
func (c *CRDMetadataCache[T]) Has(key string) bool {
	return c.metadataCache.Has(key)
}

// Set stores metadata for a given key
func (c *CRDMetadataCache[T]) Set(key string, metadata T) {
	c.metadataCache.Set(key, metadata)
}

// IsNamespaceFetched checks if resources for a namespace have been fetched
func (c *CRDMetadataCache[T]) IsNamespaceFetched(namespace string) bool {
	return c.fetchedNamespaces.Contains(namespace)
}

// MarkNamespaceFetched marks a namespace as having had its resources fetched
func (c *CRDMetadataCache[T]) MarkNamespaceFetched(namespace string) {
	c.fetchedNamespaces.Add(namespace)
}

// PopulateFromList populates the cache from a list of items using the provided
// extraction function to get key and metadata from each item
func (c *CRDMetadataCache[T]) PopulateFromList(items interface{}, namespace string, extractFn func(item interface{}) (string, T, bool)) {
	c.lock.Lock()
	defer c.lock.Unlock()

	// Only process if we haven't already fetched this namespace
	if !c.fetchedNamespaces.Contains(namespace) {
		itemCount := 0

		// Use reflection to iterate over items if it's a slice or similar collection
		if itemsSlice, ok := items.([]interface{}); ok {
			for _, item := range itemsSlice {
				if key, metadata, ok := extractFn(item); ok {
					c.metadataCache.Set(key, metadata)
					itemCount++
				}
			}
		}

		// Mark this namespace as fetched
		c.fetchedNamespaces.Add(namespace)

		logger.L().Debug("CRDMetadataCache - populated cache for namespace",
			helpers.String("namespace", namespace),
			helpers.Int("items", itemCount))
	}
}
