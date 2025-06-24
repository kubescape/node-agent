package processtree

import (
	"fmt"
	"sync"
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

// Test field filling logic for Fork events
func TestProcessTreeCreator_ForkFieldFilling(t *testing.T) {
	pt := NewProcessTreeCreator()

	// Test that fork only fills empty fields
	pt.FeedEvent(feeder.ProcessEvent{
		Type:    feeder.ForkEvent,
		PID:     1,
		PPID:    0,
		Comm:    "init",
		Cmdline: "/sbin/init",
		Uid:     &[]uint32{0}[0],
		Gid:     &[]uint32{0}[0],
	})

	// Try to update with different values - should not overwrite
	pt.FeedEvent(feeder.ProcessEvent{
		Type:    feeder.ForkEvent,
		PID:     1,
		PPID:    0,
		Comm:    "different-init",   // Should not overwrite
		Cmdline: "/different/init",  // Should not overwrite
		Uid:     &[]uint32{1000}[0], // Should not overwrite
		Gid:     &[]uint32{1000}[0], // Should not overwrite
	})

	proc, err := pt.GetProcessNode(1)
	assert.NoError(t, err)
	assert.Equal(t, "init", proc.Comm)          // Should keep original
	assert.Equal(t, "/sbin/init", proc.Cmdline) // Should keep original
	assert.Equal(t, uint32(0), *proc.Uid)       // Should keep original
	assert.Equal(t, uint32(0), *proc.Gid)       // Should keep original
}

// Test field filling logic for Exec events
func TestProcessTreeCreator_ExecFieldOverriding(t *testing.T) {
	pt := NewProcessTreeCreator()

	// Create process with fork
	pt.FeedEvent(feeder.ProcessEvent{
		Type:    feeder.ForkEvent,
		PID:     1,
		PPID:    0,
		Comm:    "init",
		Cmdline: "/sbin/init",
		Uid:     &[]uint32{0}[0],
		Gid:     &[]uint32{0}[0],
	})

	// Exec should always override when values are provided
	pt.FeedEvent(feeder.ProcessEvent{
		Type:    feeder.ExecEvent,
		PID:     1,
		PPID:    0,
		Comm:    "new-init",
		Cmdline: "/bin/new-init",
		Uid:     &[]uint32{1000}[0],
		Gid:     &[]uint32{1000}[0],
	})

	proc, err := pt.GetProcessNode(1)
	assert.NoError(t, err)
	assert.Equal(t, "new-init", proc.Comm)         // Should be overridden
	assert.Equal(t, "/bin/new-init", proc.Cmdline) // Should be overridden
	assert.Equal(t, uint32(1000), *proc.Uid)       // Should be overridden
	assert.Equal(t, uint32(1000), *proc.Gid)       // Should be overridden
}

// Test field filling logic for Procfs events
func TestProcessTreeCreator_ProcfsFieldEnrichment(t *testing.T) {
	pt := NewProcessTreeCreator()

	// Create process with some fields
	pt.FeedEvent(feeder.ProcessEvent{
		Type:    feeder.ForkEvent,
		PID:     1,
		PPID:    0,
		Comm:    "init",
		Cmdline: "/sbin/init",
	})

	// Procfs should only fill empty fields
	pt.FeedEvent(feeder.ProcessEvent{
		Type:    feeder.ProcfsEvent,
		PID:     1,
		PPID:    0,
		Comm:    "different-init", // Should not overwrite existing
		Cmdline: "",               // Empty, should not overwrite
		Cwd:     "/root",          // New field, should be added
		Path:    "/sbin/init",     // New field, should be added
	})

	proc, err := pt.GetProcessNode(1)
	assert.NoError(t, err)
	assert.Equal(t, "init", proc.Comm)          // Should keep original
	assert.Equal(t, "/sbin/init", proc.Cmdline) // Should keep original
	assert.Equal(t, "/root", proc.Cwd)          // Should be added
	assert.Equal(t, "/sbin/init", proc.Path)    // Should be added
}

// Test complex process tree scenarios
func TestProcessTreeCreator_ComplexTreeScenarios(t *testing.T) {
	pt := NewProcessTreeCreator()

	// Create a complex tree: init -> systemd -> sshd -> bash -> vim
	pt.FeedEvent(feeder.ProcessEvent{Type: feeder.ForkEvent, PID: 1, PPID: 0, Comm: "init"})
	pt.FeedEvent(feeder.ProcessEvent{Type: feeder.ForkEvent, PID: 2, PPID: 1, Comm: "systemd"})
	pt.FeedEvent(feeder.ProcessEvent{Type: feeder.ForkEvent, PID: 3, PPID: 2, Comm: "sshd"})
	pt.FeedEvent(feeder.ProcessEvent{Type: feeder.ForkEvent, PID: 4, PPID: 3, Comm: "bash"})
	pt.FeedEvent(feeder.ProcessEvent{Type: feeder.ForkEvent, PID: 5, PPID: 4, Comm: "vim"})

	// Verify tree structure
	roots, err := pt.GetNodeTree()
	assert.NoError(t, err)
	assert.Len(t, roots, 1)
	assert.Equal(t, uint32(1), roots[0].PID)

	// Check that bash has vim as child
	bash, err := pt.GetProcessNode(4)
	assert.NoError(t, err)
	assert.NotNil(t, bash)
	assert.Contains(t, bash.ChildrenMap, apitypes.CommPID{Comm: "vim", PID: 5})

	// Check that sshd has bash as child
	sshd, err := pt.GetProcessNode(3)
	assert.NoError(t, err)
	assert.NotNil(t, sshd)
	assert.Contains(t, sshd.ChildrenMap, apitypes.CommPID{Comm: "bash", PID: 4})
}

// Test process replacement scenarios
func TestProcessTreeCreator_ProcessReplacement(t *testing.T) {
	pt := NewProcessTreeCreator()

	// Create initial process
	pt.FeedEvent(feeder.ProcessEvent{
		Type:    feeder.ForkEvent,
		PID:     1,
		PPID:    0,
		Comm:    "init",
		Cmdline: "/sbin/init",
	})

	// Process exits
	pt.FeedEvent(feeder.ProcessEvent{Type: feeder.ExitEvent, PID: 1})

	// New process with same PID (PID reuse)
	pt.FeedEvent(feeder.ProcessEvent{
		Type:    feeder.ForkEvent,
		PID:     1,
		PPID:    0,
		Comm:    "new-process",
		Cmdline: "/bin/new-process",
	})

	proc, err := pt.GetProcessNode(1)
	assert.NoError(t, err)
	assert.NotNil(t, proc)
	assert.Equal(t, "new-process", proc.Comm)
	assert.Equal(t, "/bin/new-process", proc.Cmdline)
}

// Test event ordering edge cases
func TestProcessTreeCreator_EventOrderingEdgeCases(t *testing.T) {
	pt := NewProcessTreeCreator()

	// Test: Exit before any other events
	pt.FeedEvent(feeder.ProcessEvent{Type: feeder.ExitEvent, PID: 1})
	proc, err := pt.GetProcessNode(1)
	assert.NoError(t, err)
	assert.Nil(t, proc) // Should not exist

	// Test: Exec before fork (process creation)
	pt.FeedEvent(feeder.ProcessEvent{
		Type:    feeder.ExecEvent,
		PID:     2,
		PPID:    1,
		Comm:    "exec-first",
		Cmdline: "/bin/exec-first",
	})
	pt.FeedEvent(feeder.ProcessEvent{
		Type: feeder.ForkEvent,
		PID:  2,
		PPID: 1,
		Comm: "exec-first",
	})

	proc, err = pt.GetProcessNode(2)
	assert.NoError(t, err)
	assert.NotNil(t, proc)
	assert.Equal(t, "exec-first", proc.Comm)
	assert.Equal(t, "/bin/exec-first", proc.Cmdline)
}

// Test concurrent access
func TestProcessTreeCreator_ConcurrentAccess(t *testing.T) {
	pt := NewProcessTreeCreator()

	var wg sync.WaitGroup
	numGoroutines := 10
	eventsPerGoroutine := 100

	// Start multiple goroutines adding events
	for i := 0; i < numGoroutines; i++ {
		wg.Add(1)
		go func(basePID int) {
			defer wg.Done()
			firstPID := basePID*1000 + 1
			pt.FeedEvent(feeder.ProcessEvent{
				Type: feeder.ForkEvent,
				PID:  uint32(firstPID),
				PPID: 0,
				Comm: fmt.Sprintf("proc-%d", firstPID),
			})
			for j := 1; j < eventsPerGoroutine; j++ {
				pid := basePID*1000 + j + 1
				pt.FeedEvent(feeder.ProcessEvent{
					Type: feeder.ForkEvent,
					PID:  uint32(pid),
					PPID: uint32(pid - 1),
					Comm: fmt.Sprintf("proc-%d", pid),
				})
			}
		}(i)
	}

	wg.Wait()

	// Verify all processes were added
	roots, err := pt.GetNodeTree()
	assert.NoError(t, err)
	assert.NotEmpty(t, roots)

	// Count total processes
	totalProcesses := 0
	for _, root := range roots {
		totalProcesses += countProcesses(&root)
	}

	expectedTotal := numGoroutines * eventsPerGoroutine
	assert.Equal(t, expectedTotal, totalProcesses,
		"Expected %d processes, got %d", expectedTotal, totalProcesses)
}

// Test memory efficiency with large trees
func TestProcessTreeCreator_MemoryEfficiency(t *testing.T) {
	pt := NewProcessTreeCreator()

	// Create a large tree
	numProcesses := 1000
	for i := 1; i <= numProcesses; i++ {
		pt.FeedEvent(feeder.ProcessEvent{
			Type: feeder.ForkEvent,
			PID:  uint32(i),
			PPID: uint32(i - 1),
			Comm: fmt.Sprintf("proc-%d", i),
		})
	}

	// Verify tree integrity
	roots, err := pt.GetNodeTree()
	assert.NoError(t, err)
	assert.Len(t, roots, 1)

	// Test that we can still access processes efficiently
	start := time.Now()
	for i := 1; i <= numProcesses; i++ {
		proc, err := pt.GetProcessNode(i)
		assert.NoError(t, err)
		assert.NotNil(t, proc)
		assert.Equal(t, uint32(i), proc.PID)
	}
	duration := time.Since(start)

	// Should be able to access 1000 processes in reasonable time
	assert.Less(t, duration.Milliseconds(), int64(500), "Process access should be efficient")
}

// Test field validation and edge cases
func TestProcessTreeCreator_FieldValidation(t *testing.T) {
	pt := NewProcessTreeCreator()

	// Test with nil UID/GID
	pt.FeedEvent(feeder.ProcessEvent{
		Type: feeder.ForkEvent,
		PID:  1,
		PPID: 0,
		Comm: "test",
		Uid:  nil,
		Gid:  nil,
	})

	proc, err := pt.GetProcessNode(1)
	assert.NoError(t, err)
	assert.NotNil(t, proc)
	assert.Nil(t, proc.Uid)
	assert.Nil(t, proc.Gid)

	// Test with empty strings
	pt.FeedEvent(feeder.ProcessEvent{
		Type:    feeder.ForkEvent,
		PID:     2,
		PPID:    0,
		Comm:    "",
		Cmdline: "",
		Cwd:     "",
		Path:    "",
	})

	proc, err = pt.GetProcessNode(2)
	assert.NoError(t, err)
	assert.NotNil(t, proc)
	assert.Equal(t, "", proc.Comm)
	assert.Equal(t, "", proc.Cmdline)
	assert.Equal(t, "", proc.Cwd)
	assert.Equal(t, "", proc.Path)
}

// Test process tree cleanup
func TestProcessTreeCreator_TreeCleanup(t *testing.T) {
	pt := NewProcessTreeCreator()

	// Create a tree: init -> parent -> child
	pt.FeedEvent(feeder.ProcessEvent{Type: feeder.ForkEvent, PID: 1, PPID: 0, Comm: "init"})
	pt.FeedEvent(feeder.ProcessEvent{Type: feeder.ForkEvent, PID: 2, PPID: 1, Comm: "parent"})
	pt.FeedEvent(feeder.ProcessEvent{Type: feeder.ForkEvent, PID: 3, PPID: 2, Comm: "child"})

	// Remove parent - child should become orphan
	pt.FeedEvent(feeder.ProcessEvent{Type: feeder.ExitEvent, PID: 2})

	// Verify parent is gone
	parent, err := pt.GetProcessNode(2)
	assert.NoError(t, err)
	assert.Nil(t, parent)

	// Verify child still exists but is now orphaned
	child, err := pt.GetProcessNode(3)
	assert.NoError(t, err)
	assert.NotNil(t, child)
	assert.Equal(t, uint32(1), child.PPID)

	// Verify init no longer has parent as child
	init, err := pt.GetProcessNode(1)
	assert.NoError(t, err)
	assert.NotNil(t, init)
	assert.NotContains(t, init.ChildrenMap, apitypes.CommPID{Comm: "parent", PID: 2})
}

// Test deep copy functionality
func TestProcessTreeCreator_DeepCopy(t *testing.T) {
	pt := NewProcessTreeCreator()

	// Create a process with children
	pt.FeedEvent(feeder.ProcessEvent{Type: feeder.ForkEvent, PID: 1, PPID: 0, Comm: "parent"})
	pt.FeedEvent(feeder.ProcessEvent{Type: feeder.ForkEvent, PID: 2, PPID: 1, Comm: "child1"})
	pt.FeedEvent(feeder.ProcessEvent{Type: feeder.ForkEvent, PID: 3, PPID: 1, Comm: "child2"})

	// Get deep copy
	roots, err := pt.GetNodeTree()
	assert.NoError(t, err)
	assert.Len(t, roots, 1)

	// Modify the copy - should not affect original
	roots[0].Comm = "modified"
	roots[0].ChildrenMap[apitypes.CommPID{Comm: "child1", PID: 2}].Comm = "modified-child"

	// Verify original is unchanged
	original, err := pt.GetProcessNode(1)
	assert.NoError(t, err)
	assert.Equal(t, "parent", original.Comm)

	child1, err := pt.GetProcessNode(2)
	assert.NoError(t, err)
	assert.Equal(t, "child1", child1.Comm)
}

// Helper function to count processes in a tree
func countProcesses(proc *apitypes.Process) int {
	count := 1
	for _, child := range proc.ChildrenMap {
		count += countProcesses(child)
	}
	return count
}

// Test complex expected tree structure
func TestProcessTreeCreator_ExpectedTreeStructure(t *testing.T) {
	pt := NewProcessTreeCreator()

	// Define the expected tree structure
	// This represents a realistic system with multiple containers and processes
	expectedTree := map[uint32]*ExpectedProcess{
		1:  {PID: 1, PPID: 0, Comm: "init", Children: []uint32{2, 100, 200}},
		2:  {PID: 2, PPID: 1, Comm: "systemd", Children: []uint32{3, 4, 5}},
		3:  {PID: 3, PPID: 2, Comm: "sshd", Children: []uint32{6, 7}},
		4:  {PID: 4, PPID: 2, Comm: "cron", Children: []uint32{8}},
		5:  {PID: 5, PPID: 2, Comm: "rsyslogd", Children: []uint32{}},
		6:  {PID: 6, PPID: 3, Comm: "sshd", Children: []uint32{9}},
		7:  {PID: 7, PPID: 3, Comm: "sshd", Children: []uint32{10}},
		8:  {PID: 8, PPID: 4, Comm: "cron", Children: []uint32{11}},
		9:  {PID: 9, PPID: 6, Comm: "bash", Children: []uint32{12, 13}},
		10: {PID: 10, PPID: 7, Comm: "bash", Children: []uint32{14}},
		11: {PID: 11, PPID: 8, Comm: "backup-script", Children: []uint32{15}},
		12: {PID: 12, PPID: 9, Comm: "vim", Children: []uint32{}},
		13: {PID: 13, PPID: 9, Comm: "git", Children: []uint32{16}},
		14: {PID: 14, PPID: 10, Comm: "docker", Children: []uint32{17}},
		15: {PID: 15, PPID: 11, Comm: "tar", Children: []uint32{}},
		16: {PID: 16, PPID: 13, Comm: "git-remote-http", Children: []uint32{}},
		17: {PID: 17, PPID: 14, Comm: "docker-proxy", Children: []uint32{}},
		// Container 1 processes
		100: {PID: 100, PPID: 1, Comm: "containerd-shim", Children: []uint32{101, 102}},
		101: {PID: 101, PPID: 100, Comm: "nginx", Children: []uint32{103, 104}},
		102: {PID: 102, PPID: 100, Comm: "nginx", Children: []uint32{105}},
		103: {PID: 103, PPID: 101, Comm: "nginx-worker", Children: []uint32{}},
		104: {PID: 104, PPID: 101, Comm: "nginx-worker", Children: []uint32{}},
		105: {PID: 105, PPID: 102, Comm: "nginx-worker", Children: []uint32{}},
		// Container 2 processes
		200: {PID: 200, PPID: 1, Comm: "containerd-shim", Children: []uint32{201, 202}},
		201: {PID: 201, PPID: 200, Comm: "postgres", Children: []uint32{203, 204}},
		202: {PID: 202, PPID: 200, Comm: "postgres", Children: []uint32{205}},
		203: {PID: 203, PPID: 201, Comm: "postgres-writer", Children: []uint32{}},
		204: {PID: 204, PPID: 201, Comm: "postgres-checkpointer", Children: []uint32{}},
		205: {PID: 205, PPID: 202, Comm: "postgres-logger", Children: []uint32{}},
	}

	// Feed events to create the tree
	// We'll feed them in a specific order to test the field filling logic
	events := []feeder.ProcessEvent{
		// Create init process
		{Type: feeder.ForkEvent, PID: 1, PPID: 0, Comm: "init"},
		{Type: feeder.ExecEvent, PID: 1, PPID: 0, Comm: "init", Cmdline: "/sbin/init"},

		// Create systemd and its children
		{Type: feeder.ForkEvent, PID: 2, PPID: 1, Comm: "systemd"},
		{Type: feeder.ExecEvent, PID: 2, PPID: 1, Comm: "systemd", Cmdline: "/usr/lib/systemd/systemd"},

		{Type: feeder.ForkEvent, PID: 3, PPID: 2, Comm: "sshd"},
		{Type: feeder.ExecEvent, PID: 3, PPID: 2, Comm: "sshd", Cmdline: "/usr/sbin/sshd -D"},

		{Type: feeder.ForkEvent, PID: 4, PPID: 2, Comm: "cron"},
		{Type: feeder.ExecEvent, PID: 4, PPID: 2, Comm: "cron", Cmdline: "/usr/sbin/cron"},

		{Type: feeder.ForkEvent, PID: 5, PPID: 2, Comm: "rsyslogd"},
		{Type: feeder.ExecEvent, PID: 5, PPID: 2, Comm: "rsyslogd", Cmdline: "/usr/sbin/rsyslogd"},

		// Create sshd children
		{Type: feeder.ForkEvent, PID: 6, PPID: 3, Comm: "sshd"},
		{Type: feeder.ForkEvent, PID: 7, PPID: 3, Comm: "sshd"},

		{Type: feeder.ForkEvent, PID: 9, PPID: 6, Comm: "bash"},
		{Type: feeder.ExecEvent, PID: 9, PPID: 6, Comm: "bash", Cmdline: "/bin/bash"},

		{Type: feeder.ForkEvent, PID: 10, PPID: 7, Comm: "bash"},
		{Type: feeder.ExecEvent, PID: 10, PPID: 7, Comm: "bash", Cmdline: "/bin/bash"},

		// Create cron child
		{Type: feeder.ForkEvent, PID: 8, PPID: 4, Comm: "cron"},
		{Type: feeder.ForkEvent, PID: 11, PPID: 8, Comm: "backup-script"},
		{Type: feeder.ExecEvent, PID: 11, PPID: 8, Comm: "backup-script", Cmdline: "/usr/local/bin/backup.sh"},

		// Create bash children
		{Type: feeder.ForkEvent, PID: 12, PPID: 9, Comm: "vim"},
		{Type: feeder.ExecEvent, PID: 12, PPID: 9, Comm: "vim", Cmdline: "vim /etc/hosts"},

		{Type: feeder.ForkEvent, PID: 13, PPID: 9, Comm: "git"},
		{Type: feeder.ExecEvent, PID: 13, PPID: 9, Comm: "git", Cmdline: "git pull"},

		{Type: feeder.ForkEvent, PID: 14, PPID: 10, Comm: "docker"},
		{Type: feeder.ExecEvent, PID: 14, PPID: 10, Comm: "docker", Cmdline: "docker run nginx"},

		// Create git child
		{Type: feeder.ForkEvent, PID: 16, PPID: 13, Comm: "git-remote-http"},
		{Type: feeder.ExecEvent, PID: 16, PPID: 13, Comm: "git-remote-http", Cmdline: "git-remote-http origin"},

		// Create docker child
		{Type: feeder.ForkEvent, PID: 17, PPID: 14, Comm: "docker-proxy"},
		{Type: feeder.ExecEvent, PID: 17, PPID: 14, Comm: "docker-proxy", Cmdline: "docker-proxy -proto tcp"},

		// Create backup script child
		{Type: feeder.ForkEvent, PID: 15, PPID: 11, Comm: "tar"},
		{Type: feeder.ExecEvent, PID: 15, PPID: 11, Comm: "tar", Cmdline: "tar -czf backup.tar.gz /data"},

		// Create container 1 processes
		{Type: feeder.ForkEvent, PID: 100, PPID: 1, Comm: "containerd-shim"},
		{Type: feeder.ExecEvent, PID: 100, PPID: 1, Comm: "containerd-shim", Cmdline: "containerd-shim -namespace moby"},

		{Type: feeder.ForkEvent, PID: 101, PPID: 100, Comm: "nginx"},
		{Type: feeder.ExecEvent, PID: 101, PPID: 100, Comm: "nginx", Cmdline: "nginx -g 'daemon off;'"},

		{Type: feeder.ForkEvent, PID: 102, PPID: 100, Comm: "nginx"},
		{Type: feeder.ExecEvent, PID: 102, PPID: 100, Comm: "nginx", Cmdline: "nginx -g 'daemon off;'"},

		{Type: feeder.ForkEvent, PID: 103, PPID: 101, Comm: "nginx-worker"},
		{Type: feeder.ExecEvent, PID: 103, PPID: 101, Comm: "nginx-worker", Cmdline: "nginx: worker process"},

		{Type: feeder.ForkEvent, PID: 104, PPID: 101, Comm: "nginx-worker"},
		{Type: feeder.ExecEvent, PID: 104, PPID: 101, Comm: "nginx-worker", Cmdline: "nginx: worker process"},

		{Type: feeder.ForkEvent, PID: 105, PPID: 102, Comm: "nginx-worker"},
		{Type: feeder.ExecEvent, PID: 105, PPID: 102, Comm: "nginx-worker", Cmdline: "nginx: worker process"},

		// Create container 2 processes
		{Type: feeder.ForkEvent, PID: 200, PPID: 1, Comm: "containerd-shim"},
		{Type: feeder.ExecEvent, PID: 200, PPID: 1, Comm: "containerd-shim", Cmdline: "containerd-shim -namespace moby"},

		{Type: feeder.ForkEvent, PID: 201, PPID: 200, Comm: "postgres"},
		{Type: feeder.ExecEvent, PID: 201, PPID: 200, Comm: "postgres", Cmdline: "postgres -D /var/lib/postgresql/data"},

		{Type: feeder.ForkEvent, PID: 202, PPID: 200, Comm: "postgres"},
		{Type: feeder.ExecEvent, PID: 202, PPID: 200, Comm: "postgres", Cmdline: "postgres -D /var/lib/postgresql/data"},

		{Type: feeder.ForkEvent, PID: 203, PPID: 201, Comm: "postgres-writer"},
		{Type: feeder.ExecEvent, PID: 203, PPID: 201, Comm: "postgres-writer", Cmdline: "postgres: writer process"},

		{Type: feeder.ForkEvent, PID: 204, PPID: 201, Comm: "postgres-checkpointer"},
		{Type: feeder.ExecEvent, PID: 204, PPID: 201, Comm: "postgres-checkpointer", Cmdline: "postgres: checkpointer process"},

		{Type: feeder.ForkEvent, PID: 205, PPID: 202, Comm: "postgres-logger"},
		{Type: feeder.ExecEvent, PID: 205, PPID: 202, Comm: "postgres-logger", Cmdline: "postgres: logger process"},

		// Add some procfs enrichment events
		{Type: feeder.ProcfsEvent, PID: 1, PPID: 0, Comm: "init", Cwd: "/", Path: "/sbin/init"},
		{Type: feeder.ProcfsEvent, PID: 9, PPID: 6, Comm: "bash", Cwd: "/home/user", Path: "/bin/bash"},
		{Type: feeder.ProcfsEvent, PID: 101, PPID: 100, Comm: "nginx", Cwd: "/var/lib/nginx", Path: "/usr/sbin/nginx"},
	}

	// Feed all events
	for _, event := range events {
		pt.FeedEvent(event)
	}

	// Get the actual tree
	actualRoots, err := pt.GetNodeTree()
	assert.NoError(t, err)
	assert.Len(t, actualRoots, 1, "Should have exactly one root process")

	// Build actual tree map for comparison
	actualTree := buildProcessTreeMap(&actualRoots[0])

	// Compare expected vs actual
	compareProcessTrees(t, expectedTree, actualTree)

	// Test some specific scenarios
	t.Run("test_field_filling_persistence", func(t *testing.T) {
		// Test that procfs enrichment didn't overwrite existing fields
		init, err := pt.GetProcessNode(1)
		assert.NoError(t, err)
		assert.Equal(t, "init", init.Comm)          // Should keep original, not be overwritten by procfs
		assert.Equal(t, "/sbin/init", init.Cmdline) // Should keep original
		assert.Equal(t, "/", init.Cwd)              // Should be added by procfs
		assert.Equal(t, "/sbin/init", init.Path)    // Should be added by procfs
	})

	t.Run("test_complex_tree_traversal", func(t *testing.T) {
		// Test that we can traverse the complex tree
		init, err := pt.GetProcessNode(1)
		assert.NoError(t, err)
		assert.NotNil(t, init)
		assert.Len(t, init.ChildrenMap, 3) // systemd, containerd-shim, containerd-shim

		// Check that nginx has workers
		nginx, err := pt.GetProcessNode(101)
		assert.NoError(t, err)
		assert.NotNil(t, nginx)
		assert.Len(t, nginx.ChildrenMap, 2) // Two worker processes

		// Check that postgres has subprocesses
		postgres, err := pt.GetProcessNode(201)
		assert.NoError(t, err)
		assert.NotNil(t, postgres)
		assert.Len(t, postgres.ChildrenMap, 2) // writer and checkpointer
	})

	t.Run("test_process_removal", func(t *testing.T) {
		// Remove a process and verify tree integrity
		pt.FeedEvent(feeder.ProcessEvent{Type: feeder.ExitEvent, PID: 101})

		// Verify nginx is gone
		nginx, err := pt.GetProcessNode(101)
		assert.NoError(t, err)
		assert.Nil(t, nginx)

		// Verify containerd-shim no longer has nginx as child
		shim, err := pt.GetProcessNode(100)
		assert.NoError(t, err)
		assert.NotNil(t, shim)
		assert.NotContains(t, shim.ChildrenMap, apitypes.CommPID{Comm: "nginx", PID: 101})
		assert.Contains(t, shim.ChildrenMap, apitypes.CommPID{Comm: "nginx", PID: 102}) // Other nginx should still exist
	})
}

// ExpectedProcess represents the expected structure of a process
type ExpectedProcess struct {
	PID      uint32
	PPID     uint32
	Comm     string
	Children []uint32
}

// buildProcessTreeMap converts the actual tree to a map for comparison
func buildProcessTreeMap(proc *apitypes.Process) map[uint32]*ExpectedProcess {
	result := make(map[uint32]*ExpectedProcess)
	buildProcessTreeMapRecursive(proc, result)
	return result
}

func buildProcessTreeMapRecursive(proc *apitypes.Process, result map[uint32]*ExpectedProcess) {
	if proc == nil {
		return
	}

	children := make([]uint32, 0, len(proc.ChildrenMap))
	for childPID := range proc.ChildrenMap {
		children = append(children, childPID.PID)
	}

	result[proc.PID] = &ExpectedProcess{
		PID:      proc.PID,
		PPID:     proc.PPID,
		Comm:     proc.Comm,
		Children: children,
	}

	// Recursively process children
	for _, child := range proc.ChildrenMap {
		buildProcessTreeMapRecursive(child, result)
	}
}

// compareProcessTrees compares expected and actual process trees
func compareProcessTrees(t *testing.T, expected, actual map[uint32]*ExpectedProcess) {
	// Check that all expected processes exist
	for pid, expectedProc := range expected {
		actualProc, exists := actual[pid]
		assert.True(t, exists, "Expected process %d (%s) not found in actual tree", pid, expectedProc.Comm)
		if !exists {
			continue
		}

		assert.Equal(t, expectedProc.PPID, actualProc.PPID,
			"Process %d (%s) has wrong PPID", pid, expectedProc.Comm)
		assert.Equal(t, expectedProc.Comm, actualProc.Comm,
			"Process %d has wrong command name", pid)

		// Check children
		assert.ElementsMatch(t, expectedProc.Children, actualProc.Children,
			"Process %d (%s) has wrong children", pid, expectedProc.Comm)
	}

	// Check that no unexpected processes exist
	for pid, actualProc := range actual {
		_, exists := expected[pid]
		assert.True(t, exists, "Unexpected process %d (%s) found in actual tree", pid, actualProc.Comm)
	}

	// Log tree statistics
	t.Logf("Process tree comparison completed successfully:")
	t.Logf("  Total processes: %d", len(expected))
	t.Logf("  Root processes: %d", countRootProcesses(expected))
	t.Logf("  Max tree depth: %d", calculateMaxDepth(expected))
}

// countRootProcesses counts processes with PPID 0
func countRootProcesses(tree map[uint32]*ExpectedProcess) int {
	count := 0
	for _, proc := range tree {
		if proc.PPID == 0 {
			count++
		}
	}
	return count
}

// calculateMaxDepth calculates the maximum depth of the tree
func calculateMaxDepth(tree map[uint32]*ExpectedProcess) int {
	maxDepth := 0
	for pid := range tree {
		depth := calculateProcessDepth(pid, tree)
		if depth > maxDepth {
			maxDepth = depth
		}
	}
	return maxDepth
}

// calculateProcessDepth calculates the depth of a specific process
func calculateProcessDepth(pid uint32, tree map[uint32]*ExpectedProcess) int {
	proc, exists := tree[pid]
	if !exists {
		return 0
	}
	if proc.PPID == 0 {
		return 1
	}
	return 1 + calculateProcessDepth(proc.PPID, tree)
}
