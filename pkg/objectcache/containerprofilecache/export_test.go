package containerprofilecache

// export_test.go exposes internal symbols to the containerprofilecache_test
// package (the *_test.go files in this directory). Compiled only during
// `go test`; never included in the production binary.

import "context"

func (c *ContainerProfileCacheImpl) ReconcileOnce(ctx context.Context) {
	c.reconcileOnce(ctx)
}

func (c *ContainerProfileCacheImpl) SeedEntryForTest(containerID string, entry *CachedContainerProfile) {
	c.entries.Set(containerID, entry)
}

func (c *ContainerProfileCacheImpl) RefreshAllEntriesForTest(ctx context.Context) {
	c.refreshAllEntries(ctx)
}

// WarmContainerLocksForTest acquires and immediately releases each container
// lock, initialising the internal SafeMap before the concurrent phase to avoid
// the goradd/maps nil-check-before-lock initialisation race (SafeMap v1.3.0).
func (c *ContainerProfileCacheImpl) WarmContainerLocksForTest(ids []string) {
	for _, id := range ids {
		c.containerLocks.WithLock(id, func() {})
	}
}

// WarmPendingForTest initialises the pending SafeMap via a Set+Delete cycle
// for each id, preventing the goradd/maps nil-check-before-lock race in
// SafeMap.Len / SafeMap.Delete during concurrent test phases.
func (c *ContainerProfileCacheImpl) WarmPendingForTest(ids []string) {
	for _, id := range ids {
		c.pending.Set(id, nil)
		c.pending.Delete(id)
	}
}

// SeedEntryWithOverlayForTest seeds an entry with user AP and NN overlay refs.
// Pass empty strings to leave a ref nil.
func (c *ContainerProfileCacheImpl) SeedEntryWithOverlayForTest(containerID string, entry *CachedContainerProfile, apNS, apName, nnNS, nnName string) {
	if apName != "" {
		entry.UserAPRef = &namespacedName{Namespace: apNS, Name: apName}
	}
	if nnName != "" {
		entry.UserNNRef = &namespacedName{Namespace: nnNS, Name: nnName}
	}
	c.entries.Set(containerID, entry)
}
