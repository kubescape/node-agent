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

// addContainerEntry safely adds a new container entry to the map
func (cpm *ContainerProfileManager) addContainerEntry(containerID string, entry *ContainerEntry) {
	cpm.containersMu.Lock()
	defer cpm.containersMu.Unlock()

	cpm.containers[containerID] = entry
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
