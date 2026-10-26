package strategies

import (
	"testing"

	"github.com/armosec/armoapi-go/armotypes"
	"github.com/goradd/maps"
	containerprocesstree "github.com/kubescape/node-agent/pkg/processtree/container"
	"github.com/stretchr/testify/require"
)

func TestFallBackStrategy(t *testing.T) {
	const parent, exiting, child = uint32(101), uint32(102), uint32(103)
	for _, tc := range []struct {
		name          string
		nodes         map[uint32]*armotypes.Process
		containerTree containerprocesstree.ContainerProcessTree
	}{
		{"empty map", nil, nil},
		{"tracked parent", map[uint32]*armotypes.Process{parent: {PID: parent, PPID: 1}, exiting: {PID: exiting, PPID: parent}}, nil},
		{"under a container", map[uint32]*armotypes.Process{exiting: {PID: exiting, PPID: 100}}, &MockContainerProcessTree{shimPID: 100}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			processMap := &maps.SafeMap[uint32, *armotypes.Process]{}
			for pid, proc := range tc.nodes {
				processMap.Set(pid, proc)
			}
			strategy := &FallBackStrategy{}
			require.Equal(t, "fallback", strategy.Name())
			require.True(t, strategy.IsApplicable(exiting, tc.containerTree, processMap))
			require.Equal(t, uint32(1), strategy.GetNewParentPID(exiting, []*armotypes.Process{{PID: child, PPID: exiting}}, tc.containerTree, processMap))
		})
	}
}
