package objectcache

// CompletionNotifier is implemented by ContainerProfileCacheImpl. The
// containerprofilemanager calls NotifyContainerCompleted when it writes a
// container profile with status="completed" to storage, allowing the CP cache
// to promote any pending entry without waiting for the next reconciler tick.
type CompletionNotifier interface {
	NotifyContainerCompleted(containerID string)
}
