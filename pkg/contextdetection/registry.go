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

// MntnsRegistry maps mount namespace IDs to their context information.
// It uses SafeMap for thread-safe concurrent access.
type MntnsRegistry struct {
	entries   maps.SafeMap[uint64, ContextInfo]
	hostMntns uint64
}

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

// SetHostMntns sets the host's mount namespace ID.
func (r *MntnsRegistry) SetHostMntns(mntns uint64) error {
	if mntns == 0 {
		return ErrInvalidMntns
	}

	r.hostMntns = mntns
	logger.L().Info("MntnsRegistry - host mount namespace set",
		helpers.String("mntns", fmt.Sprintf("%d", mntns)))

	return nil
}

// GetHostMntns returns the host's mount namespace ID.
func (r *MntnsRegistry) GetHostMntns() uint64 {
	return r.hostMntns
}

// IsHostMntns checks if the given mount namespace ID is the host's.
func (r *MntnsRegistry) IsHostMntns(mntns uint64) bool {
	return r.hostMntns != 0 && mntns == r.hostMntns
}

// Size returns the number of entries in the registry.
func (r *MntnsRegistry) Size() int {
	return r.entries.Len()
}
