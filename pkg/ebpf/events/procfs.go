package events

import (
	"github.com/inspektor-gadget/inspektor-gadget/pkg/types"
	"github.com/kubescape/node-agent/pkg/utils"
)

// ProcfsEvent represents a procfs event that can be processed by the ordered event queue
type ProcfsEvent struct {
	Type           types.EventType `json:"type"`
	Timestamp      types.Time      `json:"timestamp"`
	PID            uint32          `json:"pid"`
	PPID           uint32          `json:"ppid"`
	Comm           string          `json:"comm"`
	Pcomm          string          `json:"pcomm"`
	Cmdline        string          `json:"cmdline"`
	Uid            *uint32         `json:"uid"`
	Gid            *uint32         `json:"gid"`
	Cwd            string          `json:"cwd"`
	Path           string          `json:"path"`
	StartTimeNs    uint64          `json:"start_time_ns"`
	ContainerID    string          `json:"container_id"`
	ContainerMntNs uint64          `json:"container_mnt_ns"`
	ContainerNetNs uint64          `json:"container_net_ns"`
	HostPID        int             `json:"host_pid"`
	HostPPID       int             `json:"host_ppid"`
}

var _ utils.K8sEvent = (*ProcfsEvent)(nil)

func (pe *ProcfsEvent) GetContainerID() string {
	return pe.ContainerID
}

func (pe *ProcfsEvent) GetEventType() utils.EventType {
	return utils.ProcfsEventType
}

// GetEventType returns the event type
func (pe *ProcfsEvent) GetType() types.EventType {
	return pe.Type
}

// GetTimestamp returns the event timestamp
func (pe *ProcfsEvent) GetTimestamp() types.Time {
	return pe.Timestamp
}

// GetNamespace returns the namespace (empty for procfs events)
func (pe *ProcfsEvent) GetNamespace() string {
	return ""
}

// GetPod returns the pod name (empty for procfs events)
func (pe *ProcfsEvent) GetPod() string {
	return ""
}

func (pe *ProcfsEvent) HasDroppedEvents() bool {
	return false
}

func (pe *ProcfsEvent) Release() {}
