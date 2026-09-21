package containerprofilemanager

import (
	"github.com/kubescape/go-logger"
	"github.com/kubescape/go-logger/helpers"
)

// withContainer executes a function with write access to container data
// This is the core method that handles all locking and error management
func (cpm *ContainerProfileManager) withContainer(containerID string, fn func(*containerData) (int, error)) error {
	if containerID == "" {
		logger.L().Error("ContainerProfileManager.withContainer - invalid empty containerID")
		return ErrInvalidContainerID
	}
	// Get container entry (read lock on map)
	cpm.containersMu.RLock()
	entry, exists := cpm.containers[containerID]
	cpm.containersMu.RUnlock()

	if !exists {
		return ErrContainerNotFound
	}

	// Lock container data for exclusive access
	entry.mu.Lock()
	defer entry.mu.Unlock()

	// Double-check that container wasn't deleted
	if entry.data == nil {
		return ErrContainerNotFound
	}

	increment, err := fn(entry.data)
	if err != nil {
		return err
	}

	if increment > 0 {
		entry.data.size.Add(int64(increment))
		if size := entry.data.size.Load(); size > cpm.cfg.MaxTsProfileSize {
			if entry.data.watchedContainerData != nil {
				logger.L().Debug("container profile too large, splitting",
					helpers.Int("size", int(size)),
					helpers.Int("maxSize", int(cpm.cfg.MaxTsProfileSize)),
					helpers.String("containerID", containerID),
					helpers.String("wlid", entry.data.watchedContainerData.Wlid))
				entry.data.watchedContainerData.SyncChannel <- ProfileRequiresSplit
				entry.data.size.Store(0) // Prevent multiple splits (race condition)
			}
		}
	}

	return nil
}

// withContainerNoSizeUpdate executes a function with access to container data but does not update the size counter
// Use this when you want to modify or read container data but do not want to increment the size
func (cpm *ContainerProfileManager) withContainerNoSizeUpdate(containerID string, fn func(*containerData) error) error {
	// Get container entry (read lock on map)
	cpm.containersMu.RLock()
	entry, exists := cpm.containers[containerID]
	cpm.containersMu.RUnlock()

	if !exists {
		return ErrContainerNotFound
	}

	// Lock container data for exclusive access
	entry.mu.Lock()
	defer entry.mu.Unlock()

	// Double-check that container wasn't deleted
	if entry.data == nil {
		return ErrContainerNotFound
	}

	return fn(entry.data)
}

// getContainerEntry retrieves a container entry by its ID
func (cpm *ContainerProfileManager) getContainerEntry(containerID string) (*ContainerEntry, bool) {
	cpm.containersMu.RLock()
	defer cpm.containersMu.RUnlock()

	entry, exists := cpm.containers[containerID]
	return entry, exists
}

// addContainerEntryIfAbsent atomically inserts entry for containerID only if
// no entry already exists, returning whether the insert happened. This is a
// get-or-insert rather than an unconditional overwrite: a replayed
// AddContainer notification for an already-tracked container (the
// container-watcher collection is known to replay events, notably for the
// host pseudo-container -- see host_sbom.go's identical comment) must not
// silently orphan the earlier entry's monitor goroutine. deleteContainer only
// ever looks up "the current" entry in the map, so an unconditional overwrite
// here would leave the first monitor with no way to ever be signalled to
// stop -- it keeps ticking and calling saveProfile against an entry the map
// no longer references, which fails once the (second) entry is removed.
func (cpm *ContainerProfileManager) addContainerEntryIfAbsent(containerID string, entry *ContainerEntry) bool {
	cpm.containersMu.Lock()
	defer cpm.containersMu.Unlock()

	if _, exists := cpm.containers[containerID]; exists {
		return false
	}
	cpm.containers[containerID] = entry
	return true
}

// removeContainerEntry safely removes a container entry from the map
func (cpm *ContainerProfileManager) removeContainerEntry(containerID string) (*ContainerEntry, bool) {
	cpm.containersMu.Lock()
	defer cpm.containersMu.Unlock()

	entry, exists := cpm.containers[containerID]
	if exists {
		delete(cpm.containers, containerID)
	}

	return entry, exists
}

// removeContainerEntryIfMatch removes containerID's entry only if it is still
// exactly expected, returning whether it did. addContainerWithTimeout's
// duplicate-registration retry (see lifecycle.go) means a failed attempt's
// cleanup can run after a replayed attempt has already installed a newer,
// successfully-registered entry for the same containerID; an unconditional
// removeContainerEntry(containerID) there would delete that newer entry out
// from under it, leaving its monitor goroutine running with no tracked entry
// to ever signal it to stop. Every cleanup path tied to a specific entry
// value (as opposed to deleteContainer's, which owns the only removal for a
// container that was never concurrently retried) must use this instead.
func (cpm *ContainerProfileManager) removeContainerEntryIfMatch(containerID string, expected *ContainerEntry) bool {
	cpm.containersMu.Lock()
	defer cpm.containersMu.Unlock()

	if cpm.containers[containerID] != expected {
		return false
	}
	delete(cpm.containers, containerID)
	return true
}
