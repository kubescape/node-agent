package processtree

import (
	"testing"

	"github.com/kubescape/node-agent/pkg/config"
	"github.com/kubescape/node-agent/pkg/ebpf/events"
	containerprocesstree "github.com/kubescape/node-agent/pkg/processtree/container"
	processtreecreator "github.com/kubescape/node-agent/pkg/processtree/creator"
	"github.com/kubescape/node-agent/pkg/utils"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// TestManager_GetProcessBootTimeNs exercises the accessor that the network-stream
// attribution work calls to build a per-connection process reference: a procfs
// event reported through the manager must surface its boot-relative start time.
func TestManager_GetProcessBootTimeNs(t *testing.T) {
	creator := processtreecreator.NewProcessTreeCreator(containerprocesstree.NewContainerProcessTree(), config.Config{})
	mgr := NewProcessTreeManager(creator, containerprocesstree.NewContainerProcessTree(), config.Config{})

	require.NoError(t, mgr.ReportEvent(utils.ProcfsEventType, &events.ProcfsEvent{
		PID: 77, PPID: 1, Comm: "worker", StartTimeNs: 2_340_000_000,
	}))

	assert.Equal(t, uint64(2_340_000_000), mgr.GetProcessBootTimeNs(77))
	assert.Zero(t, mgr.GetProcessBootTimeNs(1234), "a pid the tree has never seen reads as 0")
}
