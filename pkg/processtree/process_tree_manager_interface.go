package processtree

import (
	"github.com/armosec/armoapi-go/armotypes"
	"github.com/kubescape/node-agent/pkg/utils"
)

type ProcessTreeManager interface {
	Start()
	Stop()
	GetContainerProcessTree(containerID string, pid uint32, useCache bool) (armotypes.Process, error)
	ReportEvent(eventType utils.EventType, event utils.K8sEvent) error
	GetPidList() []uint32
	// GetProcessBootTimeNs returns the process's creation time as nanoseconds
	// since boot (CLOCK_BOOTTIME), sourced exclusively from /proc/<pid>/stat
	// field 22 — either the periodic scan or the on-demand read performed when a
	// fork/exec creates the node. Returns 0 when unknown: the process died
	// before its creation event was processed, or it has already exited.
	//
	// This is the sole process-identity time source. The wall-clock
	// armotypes.Process.StartTime carried on tree nodes is display-only and
	// inherits btime's whole-second skew, so it must never be compared for
	// identity.
	GetProcessBootTimeNs(pid uint32) uint64
}
