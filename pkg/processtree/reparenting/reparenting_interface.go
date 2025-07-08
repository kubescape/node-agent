package reparenting

import (
	apitypes "github.com/armosec/armoapi-go/armotypes"
	containerprocesstree "github.com/kubescape/node-agent/pkg/processtree/container"
)

// ReparentingStrategy defines the interface for different reparenting strategies
type ReparentingStrategy interface {
	// GetNewParentPID determines the new parent PID for orphaned children
	// based on the specific container runtime behavior
	GetNewParentPID(exitingPID uint32, children []*apitypes.Process, containerTree containerprocesstree.ContainerProcessTree, processMap map[uint32]*apitypes.Process) uint32

	// Name returns the name of this reparenting strategy
	Name() string

	// IsApplicable checks if this strategy is applicable for the given scenario
	IsApplicable(exitingPID uint32, containerTree containerprocesstree.ContainerProcessTree, processMap map[uint32]*apitypes.Process) bool
}

// ReparentingLogic defines the interface for the reparenting logic component
type ReparentingLogic interface {
	// HandleProcessExit handles the reparenting of orphaned children when a process exits
	HandleProcessExit(exitingPID uint32, children []*apitypes.Process, containerTree containerprocesstree.ContainerProcessTree, processMap map[uint32]*apitypes.Process) ReparentingResult

	// AddStrategy adds a new reparenting strategy
	AddStrategy(strategy ReparentingStrategy)

	// GetStrategies returns all available strategies
	GetStrategies() []ReparentingStrategy
}

// ReparentingResult contains the result of a reparenting operation
type ReparentingResult struct {
	NewParentPID uint32
	Strategy     string
	Verified     bool
	Error        error
}
