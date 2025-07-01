package processtreecreator

import (
	"fmt"
	"sync"
	"testing"
	"time"

	apitypes "github.com/armosec/armoapi-go/armotypes"
	containerprocesstree "github.com/kubescape/node-agent/pkg/processtree/container"
	"github.com/kubescape/node-agent/pkg/processtree/feeder"
	"github.com/stretchr/testify/assert"
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

	tree, err := pt.GetRootTree()
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
	pt.FeedEvent(feeder.ProcessEvent{
		Type:        feeder.ForkEvent,
		PID:         2,
		PPID:        1,
		Comm:        "child1",
		StartTimeNs: 1000,
	})
	proc, err := pt.GetProcessNode(2)
	assert.NoError(t, err)
	assert.Equal(t, "child1", proc.Comm)
	// Simulate exit of the first process
	pt.FeedEvent(feeder.ProcessEvent{
		Type:        feeder.ExitEvent,
		PID:         2,
		StartTimeNs: 1000,
	})
	proc, err = pt.GetProcessNode(2)
	assert.NoError(t, err)
	assert.Nil(t, proc) // Should be removed after exit
	// Reuse PID 2 for a new process with different start time
	pt.FeedEvent(feeder.ProcessEvent{
		Type:        feeder.ForkEvent,
		PID:         2,
		PPID:        1,
		Comm:        "child2",
		StartTimeNs: 2000, // Different start time for PID reuse
	})
	proc, err = pt.GetProcessNode(2)
	assert.NoError(t, err)
	assert.NotNil(t, proc)
	assert.Equal(t, "child2", proc.Comm)
}

func TestProcessTreeCreator_EventOrderings(t *testing.T) {
	pt := NewProcessTreeCreator()
	// Exec before Fork - same process instance
	pt.FeedEvent(feeder.ProcessEvent{
		Type:        feeder.ExecEvent,
		PID:         5,
		PPID:        1,
		Comm:        "execfirst",
		Cmdline:     "/bin/execfirst",
		StartTimeNs: 1000,
	})
	pt.FeedEvent(feeder.ProcessEvent{
		Type:        feeder.ForkEvent,
		PID:         5,
		PPID:        1,
		Comm:        "execfirst",
		StartTimeNs: 1000, // Same start time as exec event
	})
	proc, err := pt.GetProcessNode(5)
	assert.NoError(t, err)
	assert.Equal(t, "/bin/execfirst", proc.Cmdline)
	// Fork before Exec - same process instance
	pt.FeedEvent(feeder.ProcessEvent{
		Type:        feeder.ForkEvent,
		PID:         6,
		PPID:        1,
		Comm:        "forkfirst",
		StartTimeNs: 2000,
	})
	pt.FeedEvent(feeder.ProcessEvent{
		Type:        feeder.ExecEvent,
		PID:         6,
		PPID:        1,
		Comm:        "forkfirst",
		Cmdline:     "/bin/forkfirst",
		StartTimeNs: 2000, // Same start time as fork event
	})
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
	roots, err := pt.GetRootTree()
	assert.NoError(t, err)
	assert.NotEmpty(t, roots)
}

// Test field filling logic for Fork events
func TestProcessTreeCreator_ForkFieldFilling(t *testing.T) {
	pt := NewProcessTreeCreator()

	// Test that fork only fills empty fields
	pt.FeedEvent(feeder.ProcessEvent{
		Type:        feeder.ForkEvent,
		PID:         1,
		PPID:        0,
		Comm:        "init",
		Cmdline:     "/sbin/init",
		Uid:         &[]uint32{0}[0],
		Gid:         &[]uint32{0}[0],
		StartTimeNs: 1000,
	})

	// Try to update with different values - should not overwrite (same process instance)
	pt.FeedEvent(feeder.ProcessEvent{
		Type:        feeder.ForkEvent,
		PID:         1,
		PPID:        0,
		Comm:        "different-init",   // Should not overwrite
		Cmdline:     "/different/init",  // Should not overwrite
		Uid:         &[]uint32{1000}[0], // Should not overwrite
		Gid:         &[]uint32{1000}[0], // Should not overwrite
		StartTimeNs: 1000,               // Same start time as first event
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
		Type:        feeder.ForkEvent,
		PID:         1,
		PPID:        0,
		Comm:        "init",
		Cmdline:     "/sbin/init",
		Uid:         &[]uint32{0}[0],
		Gid:         &[]uint32{0}[0],
		StartTimeNs: 1000,
	})

	// Exec should always override when values are provided (same process instance)
	pt.FeedEvent(feeder.ProcessEvent{
		Type:        feeder.ExecEvent,
		PID:         1,
		PPID:        0,
		Comm:        "new-init",
		Cmdline:     "/bin/new-init",
		Uid:         &[]uint32{1000}[0],
		Gid:         &[]uint32{1000}[0],
		StartTimeNs: 1000, // Same start time as fork event
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
		Type:        feeder.ForkEvent,
		PID:         1,
		PPID:        0,
		Comm:        "init",
		Cmdline:     "/sbin/init",
		StartTimeNs: 1000,
	})

	// Procfs should only fill empty fields (same process instance)
	pt.FeedEvent(feeder.ProcessEvent{
		Type:        feeder.ProcfsEvent,
		PID:         1,
		PPID:        0,
		Comm:        "different-init", // Should not overwrite existing
		Cmdline:     "",               // Empty, should not overwrite
		Cwd:         "/root",          // New field, should be added
		Path:        "/sbin/init",     // New field, should be added
		StartTimeNs: 1000,             // Same start time as fork event
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
	roots, err := pt.GetRootTree()
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
		Type:        feeder.ForkEvent,
		PID:         1,
		PPID:        0,
		Comm:        "init",
		Cmdline:     "/sbin/init",
		StartTimeNs: 1000,
	})

	// Process exits
	pt.FeedEvent(feeder.ProcessEvent{
		Type:        feeder.ExitEvent,
		PID:         1,
		StartTimeNs: 1000,
	})

	// New process with same PID (PID reuse) but different start time
	pt.FeedEvent(feeder.ProcessEvent{
		Type:        feeder.ForkEvent,
		PID:         1,
		PPID:        0,
		Comm:        "new-process",
		Cmdline:     "/bin/new-process",
		StartTimeNs: 2000, // Different start time for PID reuse
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
	roots, err := pt.GetRootTree()
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
	roots, err := pt.GetRootTree()
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
	assert.Less(t, duration.Milliseconds(), int64(100), "Process access should be efficient")
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
	roots, err := pt.GetRootTree()
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
	actualRoots, err := pt.GetRootTree()
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

// TestProcfsAfterExit tests the race condition scenario where procfs tries to add
// a process that has already exited
func TestProcfsAfterExit(t *testing.T) {
	pt := NewProcessTreeCreator()

	// Create a process
	pt.FeedEvent(feeder.ProcessEvent{
		Type:        feeder.ForkEvent,
		PID:         1,
		PPID:        0,
		Comm:        "test-process",
		Cmdline:     "/bin/test",
		StartTimeNs: 1000,
	})

	// Verify process exists
	proc, err := pt.GetProcessNode(1)
	assert.NoError(t, err)
	assert.NotNil(t, proc)
	assert.Equal(t, "test-process", proc.Comm)

	// Process exits
	pt.FeedEvent(feeder.ProcessEvent{
		Type:        feeder.ExitEvent,
		PID:         1,
		StartTimeNs: 1000, // Same start time as the original process
	})

	// Verify process is removed
	proc, err = pt.GetProcessNode(1)
	assert.NoError(t, err)
	assert.Nil(t, proc)

	// Simulate procfs trying to add the exited process
	// This should not create a phantom process
	pt.FeedEvent(feeder.ProcessEvent{
		Type:        feeder.ProcfsEvent,
		PID:         1,
		PPID:        0,
		Comm:        "phantom-process",
		Cmdline:     "/bin/phantom",
		StartTimeNs: 1000, // Same start time as the exited process
	})

	// Verify process still doesn't exist (no phantom process created)
	proc, err = pt.GetProcessNode(1)
	assert.NoError(t, err)
	assert.Nil(t, proc, "Procfs event after exit should not create phantom process")
}

// TestPIDReuseWithDifferentStartTime tests that PID reuse works correctly
// when the start time is different (different process instance)
func TestPIDReuseWithDifferentStartTime(t *testing.T) {
	pt := NewProcessTreeCreator()

	// Create first process with PID 1 and start time 1000
	pt.FeedEvent(feeder.ProcessEvent{
		Type:        feeder.ForkEvent,
		PID:         1,
		PPID:        0,
		Comm:        "first-process",
		StartTimeNs: 1000,
	})

	// Verify first process exists
	proc, err := pt.GetProcessNode(1)
	assert.NoError(t, err)
	assert.NotNil(t, proc)
	assert.Equal(t, "first-process", proc.Comm)

	// First process exits
	pt.FeedEvent(feeder.ProcessEvent{
		Type:        feeder.ExitEvent,
		PID:         1,
		StartTimeNs: 1000,
	})

	// Verify first process is removed
	proc, err = pt.GetProcessNode(1)
	assert.NoError(t, err)
	assert.Nil(t, proc)

	// Create second process with same PID 1 but different start time 2000
	pt.FeedEvent(feeder.ProcessEvent{
		Type:        feeder.ForkEvent,
		PID:         1,
		PPID:        0,
		Comm:        "second-process",
		StartTimeNs: 2000, // Different start time
	})

	// Verify second process exists (PID reuse should work)
	proc, err = pt.GetProcessNode(1)
	assert.NoError(t, err)
	assert.NotNil(t, proc)
	assert.Equal(t, "second-process", proc.Comm)

	// Try to add the first process again via procfs (should be blocked)
	pt.FeedEvent(feeder.ProcessEvent{
		Type:        feeder.ProcfsEvent,
		PID:         1,
		PPID:        0,
		Comm:        "phantom-first-process",
		StartTimeNs: 1000, // Same start time as the first (exited) process
	})

	// Verify the second process is still there and not replaced
	proc, err = pt.GetProcessNode(1)
	assert.NoError(t, err)
	assert.NotNil(t, proc)
	assert.Equal(t, "second-process", proc.Comm, "Second process should not be replaced by phantom process")
}

// TestEnrichmentStillWorks tests that enrichment still works for existing processes
// even when there are exited processes with the same PID but different start times
func TestEnrichmentStillWorks(t *testing.T) {
	pt := NewProcessTreeCreator()

	// Create a process with PID 1 and start time 1000
	pt.FeedEvent(feeder.ProcessEvent{
		Type:        feeder.ForkEvent,
		PID:         1,
		PPID:        0,
		Comm:        "test-process",
		StartTimeNs: 1000,
	})

	// Verify process exists
	proc, err := pt.GetProcessNode(1)
	assert.NoError(t, err)
	assert.NotNil(t, proc)
	assert.Equal(t, "test-process", proc.Comm)
	assert.Equal(t, "", proc.Cmdline) // Initially empty

	// Exit a different process instance with same PID but different start time
	pt.FeedEvent(feeder.ProcessEvent{
		Type:        feeder.ExitEvent,
		PID:         1,
		StartTimeNs: 2000, // Different start time
	})

	// Enrich the existing process with additional information
	pt.FeedEvent(feeder.ProcessEvent{
		Type:        feeder.ProcfsEvent,
		PID:         1,
		PPID:        0,
		Comm:        "test-process",
		Cmdline:     "/bin/test --enriched",
		StartTimeNs: 1000, // Same start time as the existing process
	})

	// Verify the existing process was enriched
	proc, err = pt.GetProcessNode(1)
	assert.NoError(t, err)
	assert.NotNil(t, proc)
	assert.Equal(t, "test-process", proc.Comm)
	assert.Equal(t, "/bin/test --enriched", proc.Cmdline, "Process should be enriched with cmdline")
}

func TestProcessTreeCreator_ParentChildRelationshipBuilding(t *testing.T) {
	pt := NewProcessTreeCreator()

	// Create a simple parent-child relationship
	pt.FeedEvent(feeder.ProcessEvent{
		Type: feeder.ForkEvent,
		PID:  1,
		PPID: 0,
		Comm: "parent",
	})
	pt.FeedEvent(feeder.ProcessEvent{
		Type: feeder.ForkEvent,
		PID:  2,
		PPID: 1,
		Comm: "child",
	})

	// Verify the relationship
	parent, err := pt.GetProcessNode(1)
	assert.NoError(t, err)
	assert.NotNil(t, parent)
	assert.Contains(t, parent.ChildrenMap, apitypes.CommPID{Comm: "child", PID: 2})

	child, err := pt.GetProcessNode(2)
	assert.NoError(t, err)
	assert.NotNil(t, child)
	assert.Equal(t, uint32(1), child.PPID)
}

// TestProcessTreeCreator_OutOfOrderParentDiscovery tests the edge case where:
// 1. Initial state: We have a process with PID 1000, but we only know its PPID (999) from an event
// 2. Later event: We get information about PPID 999, including its PPID (998)
// 3. Problem: When we create PPID 999, we don't check if its parent (PPID 998) exists, so we might not properly link the hierarchy
func TestProcessTreeCreator_OutOfOrderParentDiscovery(t *testing.T) {
	pt := NewProcessTreeCreator()

	// Step 1: Create process 1000 with PPID 999 (but we don't know about 999 yet)
	pt.FeedEvent(feeder.ProcessEvent{
		Type: feeder.ForkEvent,
		PID:  1000,
		PPID: 999,
		Comm: "process1000",
	})

	// Verify process 1000 exists but its parent 999 is just a stub
	proc1000, err := pt.GetProcessNode(1000)
	assert.NoError(t, err)
	assert.NotNil(t, proc1000)
	assert.Equal(t, uint32(999), proc1000.PPID)
	assert.Equal(t, "process1000", proc1000.Comm)

	// Check that process 999 exists as a stub (created by getOrCreateProcess)
	proc999, err := pt.GetProcessNode(999)
	assert.NoError(t, err)
	assert.NotNil(t, proc999)
	assert.Equal(t, uint32(999), proc999.PID)
	// Process 999 should have 1000 as a child
	assert.Contains(t, proc999.ChildrenMap, apitypes.CommPID{Comm: "process1000", PID: 1000})

	// Step 2: Later, we get information about process 999, including its PPID (998)
	pt.FeedEvent(feeder.ProcessEvent{
		Type:  feeder.ForkEvent,
		PID:   999,
		PPID:  998,
		Comm:  "process999",
		Pcomm: "process998",
	})

	// Verify process 999 now has proper details
	proc999, err = pt.GetProcessNode(999)
	assert.NoError(t, err)
	assert.NotNil(t, proc999)
	assert.Equal(t, uint32(998), proc999.PPID)
	assert.Equal(t, "process999", proc999.Comm)
	assert.Equal(t, "process998", proc999.Pcomm)
	// Process 999 should still have 1000 as a child
	assert.Contains(t, proc999.ChildrenMap, apitypes.CommPID{Comm: "process1000", PID: 1000})

	// Check that process 998 exists and has 999 as a child
	proc998, err := pt.GetProcessNode(998)
	assert.NoError(t, err)
	assert.NotNil(t, proc998)
	assert.Equal(t, uint32(998), proc998.PID)
	assert.Contains(t, proc998.ChildrenMap, apitypes.CommPID{Comm: "process999", PID: 999})

	// Step 3: Get the root tree to verify the complete hierarchy
	rootTree, err := pt.GetRootTree()
	assert.NoError(t, err)

	// Should have one root process (998)
	assert.Len(t, rootTree, 1)
	assert.Equal(t, uint32(998), rootTree[0].PID)

	// Verify the complete tree structure
	root := rootTree[0]
	assert.Contains(t, root.ChildrenMap, apitypes.CommPID{Comm: "process999", PID: 999})

	// Get the child process 999 from the root tree
	child999 := root.ChildrenMap[apitypes.CommPID{Comm: "process999", PID: 999}]
	assert.NotNil(t, child999)
	assert.Equal(t, uint32(998), child999.PPID)
	assert.Contains(t, child999.ChildrenMap, apitypes.CommPID{Comm: "process1000", PID: 1000})

	// Get the grandchild process 1000 from the tree
	child1000 := child999.ChildrenMap[apitypes.CommPID{Comm: "process1000", PID: 1000}]
	assert.NotNil(t, child1000)
	assert.Equal(t, uint32(999), child1000.PPID)
}

// TestProcessTreeCreator_ComplexOutOfOrderScenario tests a more complex scenario with multiple levels
func TestProcessTreeCreator_ComplexOutOfOrderScenario(t *testing.T) {
	pt := NewProcessTreeCreator()

	// Create processes in a random order that doesn't follow the hierarchy
	// This simulates real-world scenarios where events arrive out of order

	// Event 1: Process 3000 with PPID 2000 (but we don't know about 2000 yet)
	pt.FeedEvent(feeder.ProcessEvent{
		Type: feeder.ForkEvent,
		PID:  3000,
		PPID: 2000,
		Comm: "process3000",
	})

	// Event 2: Process 2000 with PPID 1000 (but we don't know about 1000 yet)
	pt.FeedEvent(feeder.ProcessEvent{
		Type: feeder.ForkEvent,
		PID:  2000,
		PPID: 1000,
		Comm: "process2000",
	})

	// Event 3: Process 1000 (root process)
	pt.FeedEvent(feeder.ProcessEvent{
		Type: feeder.ForkEvent,
		PID:  1000,
		PPID: 0,
		Comm: "process1000",
	})

	// Event 4: Process 4000 with PPID 3000 (grandchild of 2000)
	pt.FeedEvent(feeder.ProcessEvent{
		Type: feeder.ForkEvent,
		PID:  4000,
		PPID: 3000,
		Comm: "process4000",
	})

	// Verify the complete tree structure
	rootTree, err := pt.GetRootTree()
	assert.NoError(t, err)
	assert.Len(t, rootTree, 1)

	root := rootTree[0]
	assert.Equal(t, uint32(1000), root.PID)
	assert.Equal(t, "process1000", root.Comm)

	// Verify the complete hierarchy: 1000 -> 2000 -> 3000 -> 4000
	assert.Contains(t, root.ChildrenMap, apitypes.CommPID{Comm: "process2000", PID: 2000})

	child2000 := root.ChildrenMap[apitypes.CommPID{Comm: "process2000", PID: 2000}]
	assert.Equal(t, uint32(1000), child2000.PPID)
	assert.Contains(t, child2000.ChildrenMap, apitypes.CommPID{Comm: "process3000", PID: 3000})

	child3000 := child2000.ChildrenMap[apitypes.CommPID{Comm: "process3000", PID: 3000}]
	assert.Equal(t, uint32(2000), child3000.PPID)
	assert.Contains(t, child3000.ChildrenMap, apitypes.CommPID{Comm: "process4000", PID: 4000})

	child4000 := child3000.ChildrenMap[apitypes.CommPID{Comm: "process4000", PID: 4000}]
	assert.Equal(t, uint32(3000), child4000.PPID)
	assert.Equal(t, "process4000", child4000.Comm)
}

func TestProcessTreeCreator_ForkExecNoDuplication(t *testing.T) {
	pt := NewProcessTreeCreator()

	// Simulate a fork event creating a new process
	forkEvent := feeder.ProcessEvent{
		Type:        feeder.ForkEvent,
		PID:         1830946, // Same PID as in the user's example
		PPID:        1792028,
		Comm:        "bash", // Initial comm from fork
		StartTimeNs: 1000,
	}
	pt.FeedEvent(forkEvent)

	// Verify the fork created a process node
	proc, err := pt.GetProcessNode(1830946)
	assert.NoError(t, err)
	assert.NotNil(t, proc)
	assert.Equal(t, uint32(1830946), proc.PID)
	assert.Equal(t, uint32(1792028), proc.PPID)
	assert.Equal(t, "bash", proc.Comm)
	assert.Equal(t, "", proc.Cmdline) // No cmdline from fork
	assert.Equal(t, "", proc.Path)    // No path from fork

	// Simulate an exec event for the same PID
	execEvent := feeder.ProcessEvent{
		Type:        feeder.ExecEvent,
		PID:         1830946, // Same PID as fork
		PPID:        1792028,
		Comm:        "ls", // New comm from exec
		Cmdline:     "/bin/ls",
		Path:        "/bin/ls",
		StartTimeNs: 1000, // Same start time
	}
	pt.FeedEvent(execEvent)

	// Verify the exec enriched the existing process, didn't create a duplicate
	proc, err = pt.GetProcessNode(1830946)
	assert.NoError(t, err)
	assert.NotNil(t, proc)
	assert.Equal(t, uint32(1830946), proc.PID)
	assert.Equal(t, uint32(1792028), proc.PPID)
	assert.Equal(t, "ls", proc.Comm)         // Updated by exec
	assert.Equal(t, "/bin/ls", proc.Cmdline) // Added by exec
	assert.Equal(t, "/bin/ls", proc.Path)    // Added by exec

	// Verify there's only one process in the map for this PID
	processMap := pt.GetProcessMap()
	count := 0
	for pid := range processMap {
		if pid == 1830946 {
			count++
		}
	}
	assert.Equal(t, 1, count, "Should have exactly one process node for PID 1830946")

	// Verify the process is properly linked to its parent
	parent, err := pt.GetProcessNode(1792028)
	if err == nil && parent != nil {
		childKey := apitypes.CommPID{Comm: "ls", PID: 1830946}
		assert.Contains(t, parent.ChildrenMap, childKey, "Child should be in parent's children map")
	}
}

func TestProcessTreeCreator_ExecBeforeFork(t *testing.T) {
	pt := NewProcessTreeCreator()

	// Simulate exec event arriving before fork (rare but possible)
	execEvent := feeder.ProcessEvent{
		Type:        feeder.ExecEvent,
		PID:         9999,
		PPID:        1,
		Comm:        "early_exec",
		Cmdline:     "/bin/early_exec",
		Path:        "/bin/early_exec",
		StartTimeNs: 1000,
	}
	pt.FeedEvent(execEvent)

	// Verify exec created a process node
	proc, err := pt.GetProcessNode(9999)
	assert.NoError(t, err)
	assert.NotNil(t, proc)
	assert.Equal(t, uint32(9999), proc.PID)
	assert.Equal(t, "early_exec", proc.Comm)
	assert.Equal(t, "/bin/early_exec", proc.Cmdline)

	// Now simulate fork event for the same PID
	forkEvent := feeder.ProcessEvent{
		Type:        feeder.ForkEvent,
		PID:         9999,
		PPID:        1,
		Comm:        "early_exec", // Same comm
		StartTimeNs: 1000,         // Same start time
	}
	pt.FeedEvent(forkEvent)

	// Verify the fork enriched the existing process, didn't create a duplicate
	proc, err = pt.GetProcessNode(9999)
	assert.NoError(t, err)
	assert.NotNil(t, proc)
	assert.Equal(t, uint32(9999), proc.PID)
	assert.Equal(t, "early_exec", proc.Comm)
	assert.Equal(t, "/bin/early_exec", proc.Cmdline) // Preserved from exec

	// Verify there's only one process in the map for this PID
	processMap := pt.GetProcessMap()
	count := 0
	for pid := range processMap {
		if pid == 9999 {
			count++
		}
	}
	assert.Equal(t, 1, count, "Should have exactly one process node for PID 9999")
}

func TestProcessTreeCreator_ConcurrentForkExec(t *testing.T) {
	pt := NewProcessTreeCreator()
	var wg sync.WaitGroup

	// Simulate concurrent fork and exec events for the same PID
	for i := 0; i < 10; i++ {
		wg.Add(2)

		// Fork event
		go func(pid uint32) {
			defer wg.Done()
			forkEvent := feeder.ProcessEvent{
				Type:        feeder.ForkEvent,
				PID:         pid,
				PPID:        1,
				Comm:        fmt.Sprintf("process_%d", pid),
				StartTimeNs: uint64(pid),
			}
			pt.FeedEvent(forkEvent)
		}(uint32(1000 + i))

		// Exec event for the same PID
		go func(pid uint32) {
			defer wg.Done()
			execEvent := feeder.ProcessEvent{
				Type:        feeder.ExecEvent,
				PID:         pid,
				PPID:        1,
				Comm:        fmt.Sprintf("exec_%d", pid),
				Cmdline:     fmt.Sprintf("/bin/exec_%d", pid),
				Path:        fmt.Sprintf("/bin/exec_%d", pid),
				StartTimeNs: uint64(pid),
			}
			pt.FeedEvent(execEvent)
		}(uint32(1000 + i))
	}

	wg.Wait()

	// Verify each PID has exactly one process (no duplicates)
	processMap := pt.GetProcessMap()

	// Count unique PIDs
	uniquePIDs := make(map[uint32]bool)
	for pid := range processMap {
		uniquePIDs[pid] = true
	}

	// Should have exactly 11 unique PIDs: 10 children (1000-1009) + 1 parent (PID=1)
	assert.Equal(t, 11, len(uniquePIDs), "Should have exactly 11 unique PIDs: 10 children + 1 parent, no duplicates")

	// Verify each expected child PID has exactly one process
	for i := 0; i < 10; i++ {
		pid := uint32(1000 + i)
		proc, err := pt.GetProcessNode(int(pid))
		assert.NoError(t, err)
		assert.NotNil(t, proc)
		assert.Equal(t, pid, proc.PID)

		// Verify the process has either fork data, exec data, or both
		assert.True(t, proc.Comm != "", "Process should have a comm name")
	}

	// Verify parent process (PID=1) exists
	parent, err := pt.GetProcessNode(1)
	assert.NoError(t, err)
	assert.NotNil(t, parent)
	assert.Equal(t, uint32(1), parent.PID)
}

// Test container-aware PPID management
func TestProcessTreeCreator_ContainerAwarePPIDManagement(t *testing.T) {
	pt := NewProcessTreeCreator()
	containerTree := containerprocesstree.NewContainerProcessTree()
	pt.SetContainerTree(containerTree)

	// Set up a container with shim PID 100
	containerID := "test-container-123"
	containerTree.SetShimPIDForTesting(containerID, 100)

	// Create the shim process first
	pt.FeedEvent(feeder.ProcessEvent{
		Type:        feeder.ForkEvent,
		PID:         100,
		PPID:        1,
		Comm:        "containerd-shim",
		Pcomm:       "systemd",
		StartTimeNs: 1000,
	})

	// Test 1: Fork event for a process that will be under container subtree
	pt.FeedEvent(feeder.ProcessEvent{
		Type:        feeder.ForkEvent,
		PID:         101,
		PPID:        100, // Direct child of shim
		Comm:        "nginx",
		Pcomm:       "containerd-shim",
		StartTimeNs: 2000,
	})

	// Verify the process was created with correct PPID
	proc, err := pt.GetProcessNode(101)
	assert.NoError(t, err)
	assert.NotNil(t, proc)
	assert.Equal(t, uint32(100), proc.PPID) // Should be under shim

	// Test 2: Exec event that tries to change PPID when process is already under container
	pt.FeedEvent(feeder.ProcessEvent{
		Type:        feeder.ExecEvent,
		PID:         101,
		PPID:        999, // Try to change to different PPID
		Comm:        "nginx",
		Pcomm:       "containerd-shim",
		StartTimeNs: 3000,
	})

	// Verify PPID was preserved (not changed)
	proc, err = pt.GetProcessNode(101)
	assert.NoError(t, err)
	assert.NotNil(t, proc)
	assert.Equal(t, uint32(100), proc.PPID) // Should still be under shim, not changed to 999

	// Test 3: ProcFS event that tries to change PPID when process is already under container
	pt.FeedEvent(feeder.ProcessEvent{
		Type:        feeder.ProcfsEvent,
		PID:         101,
		PPID:        888, // Try to change to different PPID
		Comm:        "nginx",
		Pcomm:       "containerd-shim",
		StartTimeNs: 4000,
	})

	// Verify PPID was preserved (not changed)
	proc, err = pt.GetProcessNode(101)
	assert.NoError(t, err)
	assert.NotNil(t, proc)
	assert.Equal(t, uint32(100), proc.PPID) // Should still be under shim, not changed to 888
}

func TestProcessTreeCreator_ContainerAwarePPIDManagement_ProcFS(t *testing.T) {
	pt := NewProcessTreeCreator()
	containerTree := containerprocesstree.NewContainerProcessTree()
	pt.SetContainerTree(containerTree)

	// Set up a container with shim PID 100
	containerID := "test-container-123"
	containerTree.SetShimPIDForTesting(containerID, 100)

	// Create the shim process first
	pt.FeedEvent(feeder.ProcessEvent{
		Type:        feeder.ForkEvent,
		PID:         100,
		PPID:        1,
		Comm:        "containerd-shim",
		Pcomm:       "systemd",
		StartTimeNs: 1000,
	})

	// Test: ProcFS event for a process not under container, but new PPID is under container
	pt.FeedEvent(feeder.ProcessEvent{
		Type:        feeder.ProcfsEvent,
		PID:         201,
		PPID:        100, // PPID is under container subtree
		Comm:        "new-app",
		Pcomm:       "containerd-shim",
		StartTimeNs: 7000,
	})

	// Verify the process was created and PPID was set to container subtree
	proc, err := pt.GetProcessNode(201)
	assert.NoError(t, err)
	assert.NotNil(t, proc)
	assert.Equal(t, uint32(100), proc.PPID) // Should be under shim
}

func TestProcessTreeCreator_ContainerAwarePPIDManagement_MultipleContainers(t *testing.T) {
	pt := NewProcessTreeCreator()
	containerTree := containerprocesstree.NewContainerProcessTree()
	pt.SetContainerTree(containerTree)

	// Set up two containers with different shim PIDs
	container1ID := "container-1"
	container2ID := "container-2"

	containerTree.SetShimPIDForTesting(container1ID, 100)
	containerTree.SetShimPIDForTesting(container2ID, 200)

	// Create both shim processes
	pt.FeedEvent(feeder.ProcessEvent{
		Type:        feeder.ForkEvent,
		PID:         100,
		PPID:        1,
		Comm:        "containerd-shim",
		Pcomm:       "systemd",
		StartTimeNs: 1000,
	})

	pt.FeedEvent(feeder.ProcessEvent{
		Type:        feeder.ForkEvent,
		PID:         200,
		PPID:        1,
		Comm:        "containerd-shim",
		Pcomm:       "systemd",
		StartTimeNs: 2000,
	})

	// Create processes under each container
	pt.FeedEvent(feeder.ProcessEvent{
		Type:        feeder.ForkEvent,
		PID:         101,
		PPID:        100, // Under container 1
		Comm:        "nginx",
		Pcomm:       "containerd-shim",
		StartTimeNs: 3000,
	})

	pt.FeedEvent(feeder.ProcessEvent{
		Type:        feeder.ForkEvent,
		PID:         201,
		PPID:        200, // Under container 2
		Comm:        "postgres",
		Pcomm:       "containerd-shim",
		StartTimeNs: 4000,
	})

	// Verify both processes are under their respective containers
	proc1, err := pt.GetProcessNode(101)
	assert.NoError(t, err)
	assert.NotNil(t, proc1)
	assert.Equal(t, uint32(100), proc1.PPID) // Under container 1

	proc2, err := pt.GetProcessNode(201)
	assert.NoError(t, err)
	assert.NotNil(t, proc2)
	assert.Equal(t, uint32(200), proc2.PPID) // Under container 2

	// Try to change PPIDs - they should be preserved
	pt.FeedEvent(feeder.ProcessEvent{
		Type:        feeder.ExecEvent,
		PID:         101,
		PPID:        999, // Try to change container 1 process
		Comm:        "nginx",
		Pcomm:       "containerd-shim",
		StartTimeNs: 5000,
	})

	pt.FeedEvent(feeder.ProcessEvent{
		Type:        feeder.ExecEvent,
		PID:         201,
		PPID:        888, // Try to change container 2 process
		Comm:        "postgres",
		Pcomm:       "containerd-shim",
		StartTimeNs: 6000,
	})

	// Verify PPIDs were preserved
	proc1, err = pt.GetProcessNode(101)
	assert.NoError(t, err)
	assert.Equal(t, uint32(100), proc1.PPID) // Still under container 1

	proc2, err = pt.GetProcessNode(201)
	assert.NoError(t, err)
	assert.Equal(t, uint32(200), proc2.PPID) // Still under container 2
}
