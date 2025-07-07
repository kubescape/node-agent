package reparenting

import (
	"fmt"
	"sync"

	apitypes "github.com/armosec/armoapi-go/armotypes"
	"github.com/kubescape/go-logger"
	"github.com/kubescape/go-logger/helpers"
	containerprocesstree "github.com/kubescape/node-agent/pkg/processtree/container"
	"github.com/kubescape/node-agent/pkg/processtree/reparenting/strategies"
	"github.com/prometheus/procfs"
)

// reparentingLogicImpl implements the ReparentingLogic interface
type reparentingLogicImpl struct {
	mutex      sync.RWMutex
	strategies []ReparentingStrategy
	procfs     procfs.FS
}

// NewReparentingLogic creates a new reparenting logic instance
func NewReparentingLogic() (ReparentingLogic, error) {
	fs, err := procfs.NewFS("/proc")
	if err != nil {
		return nil, fmt.Errorf("failed to initialize procfs: %v", err)
	}

	rl := &reparentingLogicImpl{
		strategies: make([]ReparentingStrategy, 0),
		procfs:     fs,
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
	expectedNewParentPID := selectedStrategy.GetNewParentPID(exitingPID, children, containerTree, processMap)

	logger.L().Info("Reparenting: Selected strategy",
		helpers.String("strategy", selectedStrategy.Name()),
		helpers.String("exiting_pid", fmt.Sprintf("%d", exitingPID)),
		helpers.String("expected_new_parent_pid", fmt.Sprintf("%d", expectedNewParentPID)),
		helpers.String("children_count", fmt.Sprintf("%d", len(children))))

	// Verify the reparenting for each child and use procfs data if there's a mismatch
	actualNewParentPID := expectedNewParentPID
	verified := true

	for _, child := range children {
		if child != nil {
			childVerified, actualPPID, err := rl.verifyReparentingWithProcfs(child.PID, expectedNewParentPID)
			if err != nil {
				logger.L().Warning("Reparenting: Verification failed",
					helpers.String("child_pid", fmt.Sprintf("%d", child.PID)),
					helpers.String("expected_parent", fmt.Sprintf("%d", expectedNewParentPID)),
					helpers.Error(err))
				verified = false
			} else if !childVerified {
				logger.L().Warning("Reparenting: Verification mismatch, using procfs data",
					helpers.String("child_pid", fmt.Sprintf("%d", child.PID)),
					helpers.String("expected_parent", fmt.Sprintf("%d", expectedNewParentPID)),
					helpers.String("actual_parent", fmt.Sprintf("%d", actualPPID)))
				verified = false
				// Use the actual PPID from procfs
				actualNewParentPID = actualPPID
			}
		}
	}

	return ReparentingResult{
		NewParentPID: actualNewParentPID, // Use actual PPID from procfs if there was a mismatch
		Strategy:     selectedStrategy.Name(),
		Verified:     verified,
		Error:        nil,
	}
}

// VerifyReparenting verifies that the reparenting was successful by checking procfs
func (rl *reparentingLogicImpl) VerifyReparenting(childPID uint32, expectedNewParentPID uint32) (bool, error) {
	rl.mutex.RLock()
	defer rl.mutex.RUnlock()

	return rl.verifyReparentingInternal(childPID, expectedNewParentPID)
}

// verifyReparentingInternal is the internal implementation of verification
func (rl *reparentingLogicImpl) verifyReparentingInternal(childPID uint32, expectedNewParentPID uint32) (bool, error) {
	// Read the actual PPID from procfs
	proc, err := rl.procfs.Proc(int(childPID))
	if err != nil {
		return false, fmt.Errorf("failed to get process %d from procfs: %v", childPID, err)
	}

	stat, err := proc.Stat()
	if err != nil {
		return false, fmt.Errorf("failed to get stat for process %d: %v", childPID, err)
	}

	actualPPID := uint32(stat.PPID)

	logger.L().Debug("Reparenting: Verification check",
		helpers.String("child_pid", fmt.Sprintf("%d", childPID)),
		helpers.String("expected_ppid", fmt.Sprintf("%d", expectedNewParentPID)),
		helpers.String("actual_ppid", fmt.Sprintf("%d", actualPPID)))

	return actualPPID == expectedNewParentPID, nil
}

// verifyReparentingWithProcfs is a helper function to verify reparenting with procfs data
func (rl *reparentingLogicImpl) verifyReparentingWithProcfs(childPID uint32, expectedNewParentPID uint32) (bool, uint32, error) {
	// Read the actual PPID from procfs
	proc, err := rl.procfs.Proc(int(childPID))
	if err != nil {
		return false, 0, fmt.Errorf("failed to get process %d from procfs: %v", childPID, err)
	}

	stat, err := proc.Stat()
	if err != nil {
		return false, 0, fmt.Errorf("failed to get stat for process %d: %v", childPID, err)
	}

	actualPPID := uint32(stat.PPID)

	logger.L().Debug("Reparenting: Verification check",
		helpers.String("child_pid", fmt.Sprintf("%d", childPID)),
		helpers.String("expected_ppid", fmt.Sprintf("%d", expectedNewParentPID)),
		helpers.String("actual_ppid", fmt.Sprintf("%d", actualPPID)))

	return actualPPID == expectedNewParentPID, actualPPID, nil
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
