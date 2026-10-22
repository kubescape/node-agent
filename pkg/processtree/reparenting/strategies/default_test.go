package strategies

import (
	"testing"

	"github.com/armosec/armoapi-go/armotypes"
	"github.com/goradd/maps"
	"github.com/stretchr/testify/require"
)

func TestDefaultStrategy_Name(t *testing.T) {
	require.Equal(t, "default", (&DefaultStrategy{}).Name())
	require.NotEqual(t, (&FallBackStrategy{}).Name(), (&DefaultStrategy{}).Name())
}

func TestDefaultStrategy(t *testing.T) {
	const parent, exiting, child = uint32(101), uint32(102), uint32(103)
	for _, tc := range []struct {
		name           string
		nodes          map[uint32]*armotypes.Process
		wantApplicable bool
		wantParent     uint32
	}{
		{"missing exiting process", map[uint32]*armotypes.Process{parent: {PID: parent, PPID: 1}}, false, 0},
		{"zero ppid", map[uint32]*armotypes.Process{exiting: {PID: exiting}}, false, 0},
		{"missing parent", map[uint32]*armotypes.Process{exiting: {PID: exiting, PPID: parent}}, false, 0},
		{"tracked parent", map[uint32]*armotypes.Process{parent: {PID: parent, PPID: 1}, exiting: {PID: exiting, PPID: parent}}, true, parent},
	} {
		t.Run(tc.name, func(t *testing.T) {
			processMap := &maps.SafeMap[uint32, *armotypes.Process]{}
			for pid, proc := range tc.nodes {
				processMap.Set(pid, proc)
			}
			strategy := &DefaultStrategy{}
			require.Equal(t, tc.wantApplicable, strategy.IsApplicable(exiting, nil, processMap))
			require.Equal(t, tc.wantParent, strategy.GetNewParentPID(exiting, []*armotypes.Process{{PID: child, PPID: exiting}}, nil, processMap))
		})
	}
}
