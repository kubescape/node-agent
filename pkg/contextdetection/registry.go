package contextdetection

import (
	"errors"
	"fmt"

	"github.com/goradd/maps"
	"github.com/kubescape/go-logger"
	"github.com/kubescape/go-logger/helpers"
)

var (
	ErrInvalidMntns = errors.New("invalid mount namespace ID: cannot be zero")
)

// Registry defines the interface for managing mount namespace to context mappings.
type Registry interface {
	// Register adds or updates a mount namespace entry in the registry.
	// Returns an error if the mount namespace ID is invalid (zero).
	Register(mntns uint64, info ContextInfo) error

	// Lookup retrieves the context information for a mount namespace.
	// Returns the context info and true if found, false otherwise.
	Lookup(mntns uint64) (ContextInfo, bool)

	// Unregister removes a mount namespace entry from the registry.
	Unregister(mntns uint64)
}

// MntnsRegistry maps mount namespace IDs to their context information.
type MntnsRegistry struct {
	entries   maps.SafeMap[uint64, ContextInfo]
	hostMntns uint64
}

// Verify that MntnsRegistry implements the Registry interface.
var _ Registry = (*MntnsRegistry)(nil)

// NewMntnsRegistry creates a new MntnsRegistry instance.
// The hostMntns should be set separately via SetHostMntns after initialization.
func NewMntnsRegistry() *MntnsRegistry {
	return &MntnsRegistry{}
}

// Register adds or updates a mount namespace entry in the registry.
func (r *MntnsRegistry) Register(mntns uint64, info ContextInfo) error {
	if mntns == 0 {
		return ErrInvalidMntns
	}

	if r.entries.Has(mntns) {
		logger.L().Warning("MntnsRegistry - mount namespace already registered, skipping",
			helpers.String("mntns", fmt.Sprintf("%d", mntns)),
			helpers.String("context", string(info.Context())))
		return nil
	}

	r.entries.Set(mntns, info)
	logger.L().Debug("MntnsRegistry - registered mount namespace",
		helpers.String("mntns", fmt.Sprintf("%d", mntns)),
		helpers.String("context", string(info.Context())),
		helpers.String("workloadID", info.WorkloadID()))

	return nil
}

// Lookup retrieves the context information for a mount namespace.
func (r *MntnsRegistry) Lookup(mntns uint64) (ContextInfo, bool) {
	info, ok := r.entries.Load(mntns)
	return info, ok
}

// Unregister removes a mount namespace entry from the registry.
func (r *MntnsRegistry) Unregister(mntns uint64) {
	if r.entries.Has(mntns) {
		r.entries.Delete(mntns)
		logger.L().Debug("MntnsRegistry - unregistered mount namespace",
			helpers.String("mntns", fmt.Sprintf("%d", mntns)))
	}
}
