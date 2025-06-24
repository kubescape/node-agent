package processtree

import (
	"testing"
	"time"

	apitypes "github.com/armosec/armoapi-go/armotypes"
	"github.com/stretchr/testify/assert"

	feeder "github.com/kubescape/node-agent/pkg/processtree/feeder"
)

func TestProcessTreeCreator_FeedEventAndGetNodeTree(t *testing.T) {
	pt := NewProcessTreeCreator()

	// Simulate a fork event: PID 2 (parent 1)
	pt.FeedEvent(feeder.ProcessEvent{
		Type:  feeder.ForkEvent,
		PID:   2,
		PPID:  1,
		Comm:  "child",
		Pcomm: "parent",
	})
	// Simulate a fork event: PID 1 (root)
	pt.FeedEvent(feeder.ProcessEvent{
		Type: feeder.ForkEvent,
		PID:  1,
		PPID: 0,
		Comm: "parent",
	})

	tree, err := pt.GetNodeTree()
	assert.NoError(t, err)
	assert.Len(t, tree, 1)
	assert.Equal(t, uint32(1), tree[0].PID)
	assert.Contains(t, tree[0].ChildrenMap, apitypes.CommPID{Comm: "child", PID: 2})
}

func TestProcessTreeCreator_ExecEvent(t *testing.T) {
	pt := NewProcessTreeCreator()
	pt.FeedEvent(feeder.ProcessEvent{
		Type: feeder.ForkEvent,
		PID:  1,
		PPID: 0,
		Comm: "init",
	})
	pt.FeedEvent(feeder.ProcessEvent{
		Type:    feeder.ExecEvent,
		PID:     1,
		PPID:    0,
		Comm:    "newinit",
		Cmdline: "/sbin/init",
	})
	proc, err := pt.GetProcessNode(1)
	assert.NoError(t, err)
	assert.Equal(t, "newinit", proc.Comm)
	assert.Equal(t, "/sbin/init", proc.Cmdline)
}

func TestProcessTreeCreator_ExitEvent(t *testing.T) {
	pt := NewProcessTreeCreator()
	pt.FeedEvent(feeder.ProcessEvent{
		Type: feeder.ForkEvent,
		PID:  1,
		PPID: 0,
		Comm: "init",
	})
	pt.FeedEvent(feeder.ProcessEvent{
		Type: feeder.ExitEvent,
		PID:  1,
	})
	proc, err := pt.GetProcessNode(1)
	assert.NoError(t, err)
	assert.Nil(t, proc)
}

func TestProcessTreeCreator_ProcfsEvent(t *testing.T) {
	pt := NewProcessTreeCreator()
	pt.FeedEvent(feeder.ProcessEvent{
		Type: feeder.ProcfsEvent,
		PID:  10,
		PPID: 0,
		Comm: "procfs",
	})
	proc, err := pt.GetProcessNode(10)
	assert.NoError(t, err)
	assert.NotNil(t, proc)
	assert.Equal(t, "procfs", proc.Comm)
}

func TestProcessTreeCreator_EnrichProcfsEvent(t *testing.T) {
	pt := NewProcessTreeCreator()
	pt.FeedEvent(feeder.ProcessEvent{
		Type: feeder.ForkEvent,
		PID:  1,
		PPID: 0,
		Comm: "init",
	})
	pt.FeedEvent(feeder.ProcessEvent{
		Type:    feeder.ProcfsEvent,
		PID:     1,
		PPID:    0,
		Comm:    "init",
		Cmdline: "/sbin/init",
		Cwd:     "/root",
	})
	proc, err := pt.GetProcessNode(1)
	assert.NoError(t, err)
	assert.Equal(t, "/sbin/init", proc.Cmdline)
	assert.Equal(t, "/root", proc.Cwd)
}

func TestProcessTreeCreator_ProcfsDoesNotOverwriteNonEmpty(t *testing.T) {
	pt := NewProcessTreeCreator()
	pt.FeedEvent(feeder.ProcessEvent{
		Type:    feeder.ForkEvent,
		PID:     1,
		PPID:    0,
		Comm:    "init",
		Cmdline: "/init",
	})
	pt.FeedEvent(feeder.ProcessEvent{
		Type:    feeder.ProcfsEvent,
		PID:     1,
		PPID:    0,
		Comm:    "init",
		Cmdline: "",
		Cwd:     "/root",
	})
	proc, err := pt.GetProcessNode(1)
	assert.NoError(t, err)
	assert.Equal(t, "/init", proc.Cmdline) // not overwritten
	assert.Equal(t, "/root", proc.Cwd)
}

func TestProcessTreeCreator_PIDReuse(t *testing.T) {
	pt := NewProcessTreeCreator()
	// First process with PID 2
	pt.FeedEvent(feeder.ProcessEvent{Type: feeder.ForkEvent, PID: 2, PPID: 1, Comm: "child1"})
	proc, err := pt.GetProcessNode(2)
	assert.NoError(t, err)
	assert.Equal(t, "child1", proc.Comm)
	// Simulate exit of the first process
	pt.FeedEvent(feeder.ProcessEvent{Type: feeder.ExitEvent, PID: 2})
	proc, err = pt.GetProcessNode(2)
	assert.NoError(t, err)
	assert.Nil(t, proc) // Should be removed after exit
	// Reuse PID 2 for a new process
	pt.FeedEvent(feeder.ProcessEvent{Type: feeder.ForkEvent, PID: 2, PPID: 1, Comm: "child2"})
	proc, err = pt.GetProcessNode(2)
	assert.NoError(t, err)
	assert.NotNil(t, proc)
	assert.Equal(t, "child2", proc.Comm)
}

func TestProcessTreeCreator_OrphanedProcess(t *testing.T) {
	pt := NewProcessTreeCreator()
	pt.FeedEvent(feeder.ProcessEvent{Type: feeder.ForkEvent, PID: 10, PPID: 99, Comm: "orphan"})
	roots, err := pt.GetNodeTree()
	assert.NoError(t, err)
	found := false
	for _, r := range roots {
		if r.PID == 10 {
			found = true
		}
	}
	assert.True(t, found)
}

func TestProcessTreeCreator_EventOrderings(t *testing.T) {
	pt := NewProcessTreeCreator()
	// Exec before Fork
	pt.FeedEvent(feeder.ProcessEvent{Type: feeder.ExecEvent, PID: 5, PPID: 1, Comm: "execfirst", Cmdline: "/bin/execfirst"})
	pt.FeedEvent(feeder.ProcessEvent{Type: feeder.ForkEvent, PID: 5, PPID: 1, Comm: "execfirst"})
	proc, err := pt.GetProcessNode(5)
	assert.NoError(t, err)
	assert.Equal(t, "/bin/execfirst", proc.Cmdline)
	// Fork before Exec
	pt.FeedEvent(feeder.ProcessEvent{Type: feeder.ForkEvent, PID: 6, PPID: 1, Comm: "forkfirst"})
	pt.FeedEvent(feeder.ProcessEvent{Type: feeder.ExecEvent, PID: 6, PPID: 1, Comm: "forkfirst", Cmdline: "/bin/forkfirst"})
	proc, err = pt.GetProcessNode(6)
	assert.NoError(t, err)
	assert.Equal(t, "/bin/forkfirst", proc.Cmdline)
}

func TestProcessTreeCreator_Efficiency(t *testing.T) {
	pt := NewProcessTreeCreator()
	n := 10000
	start := time.Now()
	for i := 1; i <= n; i++ {
		pt.FeedEvent(feeder.ProcessEvent{Type: feeder.ForkEvent, PID: uint32(i), PPID: uint32(i - 1), Comm: "proc"})
	}
	dur := time.Since(start)
	assert.Less(t, dur.Seconds(), 2.0, "Should handle 10k events in under 2 seconds")
	roots, err := pt.GetNodeTree()
	assert.NoError(t, err)
	assert.NotEmpty(t, roots)
}
