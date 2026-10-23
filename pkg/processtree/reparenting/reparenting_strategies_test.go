package reparenting

import (
	"testing"

	"github.com/armosec/armoapi-go/armotypes"
	"github.com/goradd/maps"
	containerprocesstree "github.com/kubescape/node-agent/pkg/processtree/container"
	"github.com/kubescape/node-agent/pkg/processtree/reparenting/strategies"
	"github.com/stretchr/testify/require"
)

type fakeStrategy struct {
	name       string
	applicable bool
	parentPID  uint32
	checked    bool
}

func (f *fakeStrategy) Name() string { return f.name }

func (f *fakeStrategy) IsApplicable(uint32, containerprocesstree.ContainerProcessTree, *maps.SafeMap[uint32, *armotypes.Process]) bool {
	f.checked = true
	return f.applicable
}

func (f *fakeStrategy) GetNewParentPID(uint32, []*armotypes.Process, containerprocesstree.ContainerProcessTree, *maps.SafeMap[uint32, *armotypes.Process]) uint32 {
	return f.parentPID
}

func TestNewReparentingLogic(t *testing.T) {
	rl, err := NewReparentingLogic()
	require.NoError(t, err)
	got := rl.GetStrategies()
	require.Len(t, got, 3)
	require.IsType(t, &strategies.ContainerStrategy{}, got[0])
	require.IsType(t, &strategies.FallBackStrategy{}, got[1])
	require.IsType(t, &strategies.DefaultStrategy{}, got[2], "the first strategy is listed last")
}

func TestReparent_NoChildren(t *testing.T) {
	first := &fakeStrategy{name: "first", applicable: true, parentPID: 42}
	rl := &reparentingLogicImpl{firstStrategy: first}
	for _, children := range [][]*armotypes.Process{nil, {}} {
		newParent, err := rl.Reparent(100, children, nil, &maps.SafeMap[uint32, *armotypes.Process]{})
		require.NoError(t, err)
		require.Zero(t, newParent)
	}
	require.False(t, first.checked, "no strategy must be consulted without children")
}

func TestReparent_StrategySelection(t *testing.T) {
	for _, tc := range []struct {
		name       string
		first      *fakeStrategy
		strategies []*fakeStrategy
		wantParent uint32
		wantErr    bool
	}{
		{"first strategy wins", &fakeStrategy{applicable: true, parentPID: 10}, []*fakeStrategy{{applicable: true, parentPID: 20}}, 10, false},
		{"first applicable in order wins", &fakeStrategy{}, []*fakeStrategy{{}, {applicable: true, parentPID: 20}, {applicable: true, parentPID: 30}}, 20, false},
		{"no applicable strategy", &fakeStrategy{}, []*fakeStrategy{{}}, 0, true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			rl := &reparentingLogicImpl{firstStrategy: tc.first}
			for _, s := range tc.strategies {
				rl.AddStrategy(s)
			}
			newParent, err := rl.Reparent(100, []*armotypes.Process{{PID: 101, PPID: 100}}, nil, &maps.SafeMap[uint32, *armotypes.Process]{})
			require.Equal(t, tc.wantErr, err != nil)
			require.Equal(t, tc.wantParent, newParent)
			require.True(t, tc.first.checked)
			if !tc.wantErr {
				require.False(t, tc.strategies[len(tc.strategies)-1].checked, "strategies after the selected one must not be consulted")
			}
		})
	}
}

func TestReparent_DefaultStrategies(t *testing.T) {
	const parent, exiting, child = uint32(101), uint32(102), uint32(103)
	for _, tc := range []struct {
		name       string
		nodes      map[uint32]*armotypes.Process
		wantParent uint32
	}{
		{"tracked parent", map[uint32]*armotypes.Process{parent: {PID: parent, PPID: 1}, exiting: {PID: exiting, PPID: parent}}, parent},
		{"missing parent", map[uint32]*armotypes.Process{exiting: {PID: exiting, PPID: parent}}, 1},
	} {
		t.Run(tc.name, func(t *testing.T) {
			rl, err := NewReparentingLogic()
			require.NoError(t, err)
			processMap := &maps.SafeMap[uint32, *armotypes.Process]{}
			for pid, proc := range tc.nodes {
				processMap.Set(pid, proc)
			}
			// A nil container tree leaves only the default and fallback strategies.
			newParent, err := rl.Reparent(exiting, []*armotypes.Process{{PID: child, PPID: exiting}}, nil, processMap)
			require.NoError(t, err)
			require.Equal(t, tc.wantParent, newParent)
		})
	}
}

func TestAddStrategy_GetStrategies(t *testing.T) {
	first, a, b := &fakeStrategy{name: "first"}, &fakeStrategy{name: "a"}, &fakeStrategy{name: "b"}
	rl := &reparentingLogicImpl{firstStrategy: first}
	rl.AddStrategy(a)
	rl.AddStrategy(b)
	got := rl.GetStrategies()
	require.Equal(t, []ReparentingStrategy{a, b, first}, got)
	got[0] = b
	require.Equal(t, []ReparentingStrategy{a, b, first}, rl.GetStrategies(), "callers must get a copy")
}
