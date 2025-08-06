package strategies

import (
	apitypes "github.com/armosec/armoapi-go/armotypes"
	"github.com/goradd/maps"
	containerprocesstree "github.com/kubescape/node-agent/pkg/processtree/container"
)

type DefaultStrategy struct{}

func (defs *DefaultStrategy) Name() string {
	return "fallback"
}

func (defs *DefaultStrategy) IsApplicable(exitingPID uint32, containerTree containerprocesstree.ContainerProcessTree, processMap *maps.SafeMap[uint32, *apitypes.Process]) bool {
	if exitingProcess := processMap.Get(exitingPID); exitingProcess != nil {
		ppid := exitingProcess.PPID
		if ppid > 0 {
			if processMap.Get(ppid) != nil {
				return true
			}
		}
	}

	return false
}

func (defs *DefaultStrategy) GetNewParentPID(exitingPID uint32, children []*apitypes.Process, containerTree containerprocesstree.ContainerProcessTree, processMap *maps.SafeMap[uint32, *apitypes.Process]) uint32 {
	if exitingProcess := processMap.Get(exitingPID); exitingProcess != nil {
		ppid := exitingProcess.PPID
		if ppid > 0 {
			if processMap.Get(ppid) != nil {
				return ppid
			}
		}
	}

	return 0
}
