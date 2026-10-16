package containerprofilemanager

import (
	"testing"

	"github.com/kubescape/node-agent/pkg/utils"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// Whether the agent records a container's entrypoint depended on whether
// it attached before the container ran it, so the same workload learned twice
// produced two different exec sets and whichever side the race fell on was
// then enforced, or put in front of a signer.
//
// An exec that already happened cannot be replayed. The process it started is
// usually still running, and procfs carries the same two facts the exec event
// would have: the resolved binary and the argv. So learning is retried against
// the live process. Nothing is taken from the pod spec, which would state what
// was asked for rather than what ran: an image entrypoint can exec something
// else entirely and only the process shows it.

func execPaths(t *testing.T, cpm *ContainerProfileManager, containerID string) []string {
	t.Helper()
	var out []string
	err := cpm.withContainer(containerID, func(d *containerData) (int, error) {
		for _, e := range d.getExecs() {
			out = append(out, e.Path)
		}
		return 0, nil
	})
	require.NoError(t, err)
	return out
}

func withEmptyContainer(t *testing.T, id string) *ContainerProfileManager {
	t.Helper()
	cpm := &ContainerProfileManager{containers: map[string]*ContainerEntry{}}
	entry := &ContainerEntry{data: &containerData{}, ready: make(chan struct{})}
	close(entry.ready)
	cpm.containers[id] = entry
	return cpm
}

func TestProcfsExec_RecordsAProcessTheAgentNeverSawStart(t *testing.T) {
	cpm := withEmptyContainer(t, "cid")

	cpm.ReportProcfsExec("cid", "/bin/sh", []string{"/bin/sh", "-c", "while true; do cat /etc/hostname; sleep 5; done"})

	assert.Equal(t, []string{"/bin/sh"}, execPaths(t, cpm, "cid"),
		"the running process is recorded as an exec, because that is what it is")
}

func TestProcfsExec_AgreesWithAnObservedExecRatherThanDuplicatingIt(t *testing.T) {
	cpm := withEmptyContainer(t, "cid")
	args := []string{"/bin/sh", "-c", "sleep 3600"}

	// The same process, seen both ways: the tracer caught the exec, and the
	// scan then found it still running. One entry, not two.
	cpm.ReportFileExec("cid", &utils.StructEvent{
		ExePath: "/bin/sh",
		Args:    args,
	})
	cpm.ReportProcfsExec("cid", "/bin/sh", args)

	assert.Equal(t, []string{"/bin/sh"}, execPaths(t, cpm, "cid"))

	// Reverse order: procfs found it first, then an observed exec arrives later.
	// Must still result in one entry and must not double-count profile size.
	cpm2 := withEmptyContainer(t, "cid2")
	cpm2.ReportProcfsExec("cid2", "/bin/sh", args)
	var sizeAfterProcfs int64
	_ = cpm2.withContainer("cid2", func(d *containerData) (int, error) {
		sizeAfterProcfs = d.size.Load()
		return 0, nil
	})

	cpm2.ReportFileExec("cid2", &utils.StructEvent{
		ExePath: "/bin/sh",
		Args:    args,
	})
	var sizeAfterFileExec int64
	_ = cpm2.withContainer("cid2", func(d *containerData) (int, error) {
		sizeAfterFileExec = d.size.Load()
		return 0, nil
	})

	assert.Equal(t, []string{"/bin/sh"}, execPaths(t, cpm2, "cid2"))
	assert.Equal(t, sizeAfterProcfs, sizeAfterFileExec, "file exec after procfs exec must not double-count profile size")
}

func TestProcfsExec_DifferentArgvIsADifferentEntry(t *testing.T) {
	cpm := withEmptyContainer(t, "cid")
	cpm.ReportProcfsExec("cid", "/usr/bin/curl", []string{"/usr/bin/curl", "https://a"})
	cpm.ReportProcfsExec("cid", "/usr/bin/curl", []string{"/usr/bin/curl", "https://b"})

	assert.Len(t, execPaths(t, cpm, "cid"), 2,
		"argv is part of the identity, the same way an observed exec records it")
}

func TestProcfsExec_NoPathRecordsNothing(t *testing.T) {
	cpm := withEmptyContainer(t, "cid")
	// A kernel thread, or a process whose exe link could not be read. Recording
	// a nameless entry would put behaviour in a profile that nobody can review.
	cpm.ReportProcfsExec("cid", "", []string{"[kworker/0:1]"})
	assert.Empty(t, execPaths(t, cpm, "cid"))
}

func TestProcfsExec_EmptyCmdlineStillRecordsThePath(t *testing.T) {
	cpm := withEmptyContainer(t, "cid")
	cpm.ReportProcfsExec("cid", "/usr/sbin/nginx", nil)
	assert.Equal(t, []string{"/usr/sbin/nginx"}, execPaths(t, cpm, "cid"),
		"a readable binary with an unreadable cmdline is still a process that ran")
}

func TestProcfsExec_UnknownContainerIsIgnored(t *testing.T) {
	cpm := &ContainerProfileManager{containers: map[string]*ContainerEntry{}}
	cpm.ReportProcfsExec("not-watched", "/bin/sh", []string{"/bin/sh"})
	assert.Empty(t, cpm.containers)
}

func TestProcfsExec_ArgvKeepsElementBoundaries(t *testing.T) {
	cpm := withEmptyContainer(t, "cid")
	cpm.ReportProcfsExec("cid", "/bin/sh", []string{"/bin/sh", "-c", "while true; do cat /etc/hostname; sleep 5; done"})
	var recorded [][]string
	require.NoError(t, cpm.withContainer("cid", func(d *containerData) (int, error) {
		d.execs.Range(func(_ string, v []string) bool { recorded = append(recorded, v); return true })
		return 0, nil
	}))
	require.Len(t, recorded, 1)
	assert.Equal(t, []string{"/bin/sh", "/bin/sh", "-c", "while true; do cat /etc/hostname; sleep 5; done"}, recorded[0],
		"the shell script is one argument; whitespace inside an argument is not an element boundary")
}

func TestProcfsExec_ArgvBoundaryCollisionsAreNotDiscarded(t *testing.T) {
	cpm := withEmptyContainer(t, "cid")
	cpm.ReportProcfsExec("cid", "/bin/sh", []string{"/bin/sh", "a b"})
	cpm.ReportProcfsExec("cid", "/bin/sh", []string{"/bin/sh", "a", "b"})

	assert.Len(t, execPaths(t, cpm, "cid"), 2,
		"distinct argv boundaries must produce different exec entries and not collide")
}
