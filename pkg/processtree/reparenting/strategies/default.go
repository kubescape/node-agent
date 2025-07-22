package strategies

import (
	apitypes "github.com/armosec/armoapi-go/armotypes"
	containerprocesstree "github.com/kubescape/node-agent/pkg/processtree/container"
)

type DefaultStrategy struct{}

func (defs *DefaultStrategy) Name() string {
	return "fallback"
}

func (defs *DefaultStrategy) IsApplicable(exitingPID uint32, containerTree containerprocesstree.ContainerProcessTree, processMap map[uint32]*apitypes.Process) bool {
	if exitingProcess, exists := processMap[exitingPID]; exists {
		ppid := exitingProcess.PPID
		if ppid > 0 {
			if _, parentExists := processMap[ppid]; parentExists {
				return true
			}
		}
	}

	return false
}

func (defs *DefaultStrategy) GetNewParentPID(exitingPID uint32, children []*apitypes.Process, containerTree containerprocesstree.ContainerProcessTree, processMap map[uint32]*apitypes.Process) uint32 {
	if exitingProcess, exists := processMap[exitingPID]; exists {
		ppid := exitingProcess.PPID
		if ppid > 0 {
			if _, parentExists := processMap[ppid]; parentExists {
				return ppid
			}
		}
	}

	return 0
}
