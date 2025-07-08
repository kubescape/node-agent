package reparenting

import (
	"fmt"
	"sync"

	apitypes "github.com/armosec/armoapi-go/armotypes"
	"github.com/kubescape/go-logger"
	"github.com/kubescape/go-logger/helpers"
	containerprocesstree "github.com/kubescape/node-agent/pkg/processtree/container"
	"github.com/kubescape/node-agent/pkg/processtree/reparenting/strategies"
)

// reparentingLogicImpl implements the ReparentingLogic interface
type reparentingLogicImpl struct {
	mutex      sync.RWMutex
	strategies []ReparentingStrategy
}

// NewReparentingLogic creates a new reparenting logic instance
func NewReparentingLogic() (ReparentingLogic, error) {
	rl := &reparentingLogicImpl{
		strategies: make([]ReparentingStrategy, 0),
	}

	// Add default strategies
	rl.addDefaultStrategies()

	return rl, nil
}

// addDefaultStrategies adds the default reparenting strategies in priority order
func (rl *reparentingLogicImpl) addDefaultStrategies() {
	// Add strategies in priority order: containerd (highest), docker, systemd, default (lowest)
	rl.AddStrategy(&strategies.ContainerdStrategy{})
	rl.AddStrategy(&strategies.DockerStrategy{})
	rl.AddStrategy(&strategies.SystemdStrategy{})
	rl.AddStrategy(&strategies.DefaultStrategy{})
}

// HandleProcessExit handles the reparenting of orphaned children when a process exits
func (rl *reparentingLogicImpl) HandleProcessExit(exitingPID uint32, children []*apitypes.Process, containerTree containerprocesstree.ContainerProcessTree, processMap map[uint32]*apitypes.Process) ReparentingResult {
	rl.mutex.Lock()
	defer rl.mutex.Unlock()

	if len(children) == 0 {
		return ReparentingResult{
			NewParentPID: 0,
			Strategy:     "no_children",
			Verified:     true,
			Error:        nil,
		}
	}

	// Scan strategies in exact order: containerd → docker → systemd → default
	var selectedStrategy ReparentingStrategy
	for _, strategy := range rl.strategies {
		if strategy.IsApplicable(exitingPID, containerTree, processMap) {
			selectedStrategy = strategy
			break
		}
	}

	if selectedStrategy == nil {
		// Fallback to default strategy
		selectedStrategy = &strategies.DefaultStrategy{}
	}

	// Get the new parent PID from the selected strategy
	newParentPID := selectedStrategy.GetNewParentPID(exitingPID, children, containerTree, processMap)

	logger.L().Info("Reparenting: Selected strategy",
		helpers.String("strategy", selectedStrategy.Name()),
		helpers.String("exiting_pid", fmt.Sprintf("%d", exitingPID)),
		helpers.String("new_parent_pid", fmt.Sprintf("%d", newParentPID)),
		helpers.String("children_count", fmt.Sprintf("%d", len(children))))

	return ReparentingResult{
		NewParentPID: newParentPID,
		Strategy:     selectedStrategy.Name(),
		Verified:     true,
		Error:        nil,
	}
}

// AddStrategy adds a new reparenting strategy
func (rl *reparentingLogicImpl) AddStrategy(strategy ReparentingStrategy) {
	rl.mutex.Lock()
	defer rl.mutex.Unlock()

	rl.strategies = append(rl.strategies, strategy)
	logger.L().Info("Reparenting: Added strategy", helpers.String("strategy", strategy.Name()))
}

// GetStrategies returns all available strategies
func (rl *reparentingLogicImpl) GetStrategies() []ReparentingStrategy {
	rl.mutex.RLock()
	defer rl.mutex.RUnlock()

	strategies := make([]ReparentingStrategy, len(rl.strategies))
	copy(strategies, rl.strategies)
	return strategies
}
