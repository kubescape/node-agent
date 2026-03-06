package strategies

import (
	"github.com/armosec/armoapi-go/armotypes"
	"github.com/goradd/maps"
	containerprocesstree "github.com/kubescape/node-agent/pkg/processtree/container"
)

type FallBackStrategy struct{}

func (fbs *FallBackStrategy) Name() string {
	return "fallback"
}

func (fbs *FallBackStrategy) IsApplicable(exitingPID uint32, containerTree containerprocesstree.ContainerProcessTree, processMap *maps.SafeMap[uint32, *armotypes.Process]) bool {
	return true
}

func (fbs *FallBackStrategy) GetNewParentPID(exitingPID uint32, children []*armotypes.Process, containerTree containerprocesstree.ContainerProcessTree, processMap *maps.SafeMap[uint32, *armotypes.Process]) uint32 {
	return 1
}
