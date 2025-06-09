package containerprofilemanager

// withContainer executes a function with write access to container data
// This is the core method that handles all locking and error management
func (cpm *ContainerProfileManager) withContainer(containerID string, fn func(*containerData) error) error {
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

// RegisterPeekFunc registers the syscall peek function
func (cpm *ContainerProfileManager) RegisterPeekFunc(peek func(mntns uint64) ([]string, error)) {
	cpm.syscallPeekFunc = peek
}
