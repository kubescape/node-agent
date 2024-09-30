package utils

import (
	"sync"

	"k8s.io/utils/lru"
)

type CacheWithKeys struct {
	*lru.Cache
	keys []interface{}
	mu   sync.Mutex
}

func NewCacheWithKeys(capacity int) *CacheWithKeys {
	return &CacheWithKeys{
		Cache: lru.New(capacity),
		keys:  []interface{}{},
	}
}

func (c *CacheWithKeys) Add(key, value interface{}) {
	c.mu.Lock()
	defer c.mu.Unlock()

	c.Cache.Add(key, value)
	c.keys = append(c.keys, key)
}

func (c *CacheWithKeys) Keys() []interface{} {
	c.mu.Lock()
	defer c.mu.Unlock()

	return c.keys
}

func (c *CacheWithKeys) Remove(key interface{}) {
	c.mu.Lock()
	defer c.mu.Unlock()

	c.Cache.Remove(key)

	for i, k := range c.keys {
		if k == key {
			c.keys = append(c.keys[:i], c.keys[i+1:]...)
			break
		}
	}
}
