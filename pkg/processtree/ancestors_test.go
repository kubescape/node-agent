package processtree

import (
	"fmt"
	"testing"

	"github.com/armosec/armoapi-go/armotypes"
	"github.com/goradd/maps"
	"github.com/kubescape/node-agent/pkg/config"
	"github.com/kubescape/node-agent/pkg/processtree/conversion"
	"github.com/stretchr/testify/assert"
)

// stubCreator is a ProcessTreeCreator backed by a plain map, so ancestor walking
// can be tested without feeding synthetic events through the real creator.
type stubCreator struct {
	tree map[uint32]*armotypes.Process
}

func (s *stubCreator) FeedEvent(conversion.ProcessEvent) {}
func (s *stubCreator) Start()                            {}
func (s *stubCreator) Stop()                             {}

func (s *stubCreator) GetRootTree() ([]armotypes.Process, error) { return nil, nil }

func (s *stubCreator) GetProcessMap() *maps.SafeMap[uint32, *armotypes.Process] {
	m := &maps.SafeMap[uint32, *armotypes.Process]{}
	for pid, p := range s.tree {
		m.Set(pid, p)
	}
	return m
}

func (s *stubCreator) GetProcessNode(pid int) (*armotypes.Process, error) {
	p, ok := s.tree[uint32(pid)]
	if !ok {
		return nil, fmt.Errorf("process %d not found", pid)
	}
	return p, nil
}

func newTestManagerWithTree(t *testing.T, tree map[uint32]*armotypes.Process) *ProcessTreeManagerImpl {
	t.Helper()
	return &ProcessTreeManagerImpl{
		creator: &stubCreator{tree: tree},
		config:  config.Config{},
	}
}

func TestGetAncestorPIDs(t *testing.T) {
	// 900 (bash) -> 4471 (sh) -> 4530 (curl)
	tree := map[uint32]*armotypes.Process{
		900:  {PID: 900, PPID: 1},
		4471: {PID: 4471, PPID: 900},
		4530: {PID: 4530, PPID: 4471},
	}

	tests := []struct {
		name     string
		pid      uint32
		maxDepth int
		want     []uint32
	}{
		{"full chain", 4530, 8, []uint32{4471, 900, 1}},
		{"depth bound respected", 4530, 2, []uint32{4471, 900}},
		{"leaf with one ancestor", 900, 8, []uint32{1}},
		{"unknown pid yields nothing", 99999, 8, nil},
		{"zero depth yields nothing", 4530, 0, nil},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ptm := newTestManagerWithTree(t, tree)
			assert.Equal(t, tt.want, ptm.GetAncestorPIDs(tt.pid, tt.maxDepth))
		})
	}
}

// Host processes have no container shim, so GetPidBranch errors for them and
// enrichedEvent.ProcessTree is zero-valued. GetAncestorPIDs must still work --
// this is the whole reason it exists.
func TestGetAncestorPIDs_WorksForHostProcessesWithNoShim(t *testing.T) {
	tree := map[uint32]*armotypes.Process{
		2200: {PID: 2200, PPID: 1},
		2300: {PID: 2300, PPID: 2200},
	}
	ptm := newTestManagerWithTree(t, tree)
	assert.Equal(t, []uint32{2200, 1}, ptm.GetAncestorPIDs(2300, 8))
}

func TestGetAncestorPIDs_TerminatesOnCycle(t *testing.T) {
	// Defensive: reparenting races could in principle produce a loop. The depth
	// bound must contain it rather than hanging the evaluator.
	tree := map[uint32]*armotypes.Process{
		10: {PID: 10, PPID: 11},
		11: {PID: 11, PPID: 10},
	}
	ptm := newTestManagerWithTree(t, tree)
	assert.LessOrEqual(t, len(ptm.GetAncestorPIDs(10, 8)), 8)
}

// A PPID of 0 means "parent unknown", not "parent is pid 0". Recording it would
// put a meaningless 0 in the ancestor list and make state lookups probe a key
// that can never exist.
func TestGetAncestorPIDs_StopsAtUnknownParent(t *testing.T) {
	tree := map[uint32]*armotypes.Process{
		7000: {PID: 7000, PPID: 0},
	}
	ptm := newTestManagerWithTree(t, tree)
	assert.Empty(t, ptm.GetAncestorPIDs(7000, 8))
}
