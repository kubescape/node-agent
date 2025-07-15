package utils

import (
	"time"

	(
	"fmt"
	"path/filepath"

	tracerexectype "github.com/inspektor-gadget/inspektor-gadget/pkg/gadgets/trace/exec/types"
	traceropentype "github.com/inspektor-gadget/inspektor-gadget/pkg/gadgets/trace/open/types"
	"github.com/inspektor-gadget/inspektor-gadget/pkg/types"
)
)

type K8sEvent interface {
	GetPod() string
	GetNamespace() string
}

type EnrichEvent interface {
	GetBaseEvent() *types.Event
	GetPID() uint64
	SetExtra(extra interface{})
	GetExtra() interface{}
}

type EventType string

const (
	ExecveEventType       EventType = "exec"
	OpenEventType         EventType = "open"
	CapabilitiesEventType EventType = "capabilities"
	DnsEventType          EventType = "dns"
	NetworkEventType      EventType = "network"
	SyscallEventType      EventType = "syscall"
	RandomXEventType      EventType = "randomx"
	SymlinkEventType      EventType = "symlink"
	HardlinkEventType     EventType = "hardlink"
	SSHEventType          EventType = "ssh"
	HTTPEventType         EventType = "http"
	PtraceEventType       EventType = "ptrace"
	IoUringEventType      EventType = "iouring"
	ForkEventType         EventType = "fork"
	ExitEventType         EventType = "exit"
	ProcfsEventType       EventType = "procfs"
	AllEventType          EventType = "all"
)

// ProcfsEvent represents a procfs event that can be processed by the ordered event queue
type ProcfsEvent struct {
	Type        types.EventType `json:"type"`
	Timestamp   time.Time       `json:"timestamp"`
	PID         uint32          `json:"pid"`
	PPID        uint32          `json:"ppid"`
	Comm        string          `json:"comm"`
	Pcomm       string          `json:"pcomm"`
	Cmdline     string          `json:"cmdline"`
	Uid         *uint32         `json:"uid"`
	Gid         *uint32         `json:"gid"`
	Cwd         string          `json:"cwd"`
	Path        string          `json:"path"`
	StartTimeNs uint64          `json:"start_time_ns"`
	ContainerID string          `json:"container_id"`
	HostPID     int             `json:"host_pid"`
	HostPPID    int             `json:"host_ppid"`
}

// GetType returns the event type
func (pe *ProcfsEvent) GetType() types.EventType {
	return pe.Type
}

// GetTimestamp returns the event timestamp
func (pe *ProcfsEvent) GetTimestamp() time.Time {
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

// Get the path of the file on the node.
func GetHostFilePathFromEvent(event K8sEvent, containerPid uint32) (string, error) {
	if execEvent, ok := event.(*tracerexectype.Event); ok {
		realPath := filepath.Join("/proc", fmt.Sprintf("/%d/root/%s", containerPid, GetExecPathFromEvent(execEvent)))
		return realPath, nil
	}

	if openEvent, ok := event.(*traceropentype.Event); ok {
		realPath := filepath.Join("/proc", fmt.Sprintf("/%d/root/%s", containerPid, openEvent.FullPath))
		return realPath, nil
	}

	return "", fmt.Errorf("event is not of type tracerexectype.Event or traceropentype.Event")
}

// Get the path of the executable from the given event.
func GetExecPathFromEvent(event *tracerexectype.Event) string {
	if len(event.Args) > 0 {
		if event.Args[0] != "" {
			return event.Args[0]
		}
	}
	return event.Comm
}

// Get exec args from the given event.
func GetExecArgsFromEvent(event *tracerexectype.Event) []string {
	if len(event.Args) > 1 {
		return event.Args[1:]
	}
	return []string{}
}
