package adapters

import "sync"

// mapPool is a pool for map[string]interface{} to reduce allocations.
// We pre-allocate a capacity of 32, which should be a reasonable starting point
// for the number of keys in your event maps.
var mapPool = sync.Pool{
	New: func() interface{} {
		return make(map[string]interface{}, 32)
	},
}

// AcquireMap gets a map from the pool.
func AcquireMap() map[string]interface{} {
	return mapPool.Get().(map[string]interface{})
}

// ReleaseMap returns a map to the pool after clearing it for reuse.
func ReleaseMap(m map[string]interface{}) {
	// Clear all keys from the map to prevent old data from leaking.
	clear(m)
	mapPool.Put(m)
}

// ReleaseEventMap releases the main event map and all its nested maps back to the pool.
// This function specifically handles the structure created by ConvertToMap and adapter-specific nested maps.
func ReleaseEventMap(eventMap map[string]interface{}) {
	// Release nested maps first
	if runtime, ok := eventMap["runtime"].(map[string]interface{}); ok {
		ReleaseMap(runtime)
	}
	if k8s, ok := eventMap["k8s"].(map[string]interface{}); ok {
		if owner, ok := k8s["owner"].(map[string]interface{}); ok {
			ReleaseMap(owner)
		}
		ReleaseMap(k8s)
	}
	// Release adapter-specific nested maps
	if dst, ok := eventMap["dst"].(map[string]interface{}); ok {
		ReleaseMap(dst)
	}
	// Release the main map
	ReleaseMap(eventMap)
}
