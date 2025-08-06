package reparenting

import (
	"fmt"
	"sync"

	apitypes "github.com/armosec/armoapi-go/armotypes"
	"github.com/goradd/maps"
	containerprocesstree "github.com/kubescape/node-agent/pkg/processtree/container"
	"github.com/kubescape/node-agent/pkg/processtree/reparenting/strategies"
)

type reparentingLogicImpl struct {
	mutex         sync.RWMutex
	strategies    []ReparentingStrategy
	firstStrategy ReparentingStrategy
}

func NewReparentingLogic() (ReparentingStrategies, error) {
	rl := &reparentingLogicImpl{
		strategies: make([]ReparentingStrategy, 0),
	}

	rl.addDefaultStrategies()

	return rl, nil
}

func (rl *reparentingLogicImpl) addDefaultStrategies() {
	rl.firstStrategy = &strategies.DefaultStrategy{}
	rl.AddStrategy(&strategies.ContainerStrategy{})
	rl.AddStrategy(&strategies.FallBackStrategy{})
}

func (rl *reparentingLogicImpl) Reparent(exitingPID uint32, children []*apitypes.Process, containerTree containerprocesstree.ContainerProcessTree, processMap *maps.SafeMap[uint32, *apitypes.Process]) (uint32, error) {
	rl.mutex.Lock()
	defer rl.mutex.Unlock()

	if len(children) == 0 {
		return 0, nil
	}

	selectedStrategy := rl.getSelectedStrategy(exitingPID, containerTree, processMap)
	if selectedStrategy == nil {
		return 0, fmt.Errorf("no strategy found")
	}

	newParentPID := selectedStrategy.GetNewParentPID(exitingPID, children, containerTree, processMap)
	return newParentPID, nil
}

func (rl *reparentingLogicImpl) AddStrategy(strategy ReparentingStrategy) {
	rl.mutex.Lock()
	defer rl.mutex.Unlock()

	rl.strategies = append(rl.strategies, strategy)
}

func (rl *reparentingLogicImpl) GetStrategies() []ReparentingStrategy {
	rl.mutex.RLock()
	defer rl.mutex.RUnlock()

	strategies := make([]ReparentingStrategy, len(rl.strategies))
	copy(strategies, rl.strategies)
	strategies = append(strategies, rl.firstStrategy)
	return strategies
}

func (rl *reparentingLogicImpl) getSelectedStrategy(exitingPID uint32, containerTree containerprocesstree.ContainerProcessTree, processMap *maps.SafeMap[uint32, *apitypes.Process]) ReparentingStrategy {
	if rl.firstStrategy.IsApplicable(exitingPID, containerTree, processMap) {
		return rl.firstStrategy
	}

	for _, strategy := range rl.strategies {
		if strategy.IsApplicable(exitingPID, containerTree, processMap) {
			return strategy
		}
	}
	return nil
}
