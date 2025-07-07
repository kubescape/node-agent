package strategies

import (
	"fmt"

	apitypes "github.com/armosec/armoapi-go/armotypes"
	"github.com/kubescape/go-logger"
	"github.com/kubescape/go-logger/helpers"
	containerprocesstree "github.com/kubescape/node-agent/pkg/processtree/container"
)

// DefaultStrategy handles reparenting for general cases
type DefaultStrategy struct{}

func (defs *DefaultStrategy) Name() string {
	return "default"
}

// IsApplicable checks if this strategy is applicable for the given scenario
// Default strategy is always applicable as a fallback
func (defs *DefaultStrategy) IsApplicable(exitingPID uint32, containerTree containerprocesstree.ContainerProcessTree, processMap map[uint32]*apitypes.Process) bool {
	// Default strategy is always applicable as a fallback
	return true
}

// GetNewParentPID determines the new parent PID for orphaned children
// Default behavior: reparent to init process (PID 1)
func (defs *DefaultStrategy) GetNewParentPID(exitingPID uint32, children []*apitypes.Process, containerTree containerprocesstree.ContainerProcessTree, processMap map[uint32]*apitypes.Process) uint32 {
	// Default behavior: reparent to init process (PID 1)
	logger.L().Info("DefaultStrategy: Reparenting to init",
		helpers.String("exiting_pid", fmt.Sprintf("%d", exitingPID)))
	return 1
}
