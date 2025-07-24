package strategies

import (
	apitypes "github.com/armosec/armoapi-go/armotypes"
	containerprocesstree "github.com/kubescape/node-agent/pkg/processtree/container"
)

type FallBackStrategy struct{}

func (defs *FallBackStrategy) Name() string {
	return "fallback"
}

func (defs *FallBackStrategy) IsApplicable(exitingPID uint32, containerTree containerprocesstree.ContainerProcessTree, processMap map[uint32]*apitypes.Process) bool {
	return true
}

func (defs *FallBackStrategy) GetNewParentPID(exitingPID uint32, children []*apitypes.Process, containerTree containerprocesstree.ContainerProcessTree, processMap map[uint32]*apitypes.Process) uint32 {
	return 1
}
