package reparenting

import (
	apitypes "github.com/armosec/armoapi-go/armotypes"
	containerprocesstree "github.com/kubescape/node-agent/pkg/processtree/container"
)

type ReparentingStrategy interface {
	GetNewParentPID(exitingPID uint32, children []*apitypes.Process, containerTree containerprocesstree.ContainerProcessTree, processMap map[uint32]*apitypes.Process) uint32

	Name() string

	IsApplicable(exitingPID uint32, containerTree containerprocesstree.ContainerProcessTree, processMap map[uint32]*apitypes.Process) bool
}

// ReparentingStrategies defines the interface for the reparenting logic component
type ReparentingStrategies interface {
	Reparent(exitingPID uint32, children []*apitypes.Process, containerTree containerprocesstree.ContainerProcessTree, processMap map[uint32]*apitypes.Process) (uint32, error)

	AddStrategy(strategy ReparentingStrategy)

	GetStrategies() []ReparentingStrategy
}
