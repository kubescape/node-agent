package conversion

import (
	"fmt"
	"strings"
	"time"

	"github.com/kubescape/node-agent/pkg/ebpf/events"
	"github.com/kubescape/node-agent/pkg/utils"
)

func ConvertEvent(eventType utils.EventType, event utils.K8sEvent) (ProcessEvent, error) {
	switch eventType {
	case utils.ExecveEventType:
		return convertExecEvent(event.(utils.ExecEvent)), nil
	case utils.ForkEventType:
		return convertForkEvent(event.(utils.ForkEvent)), nil
	case utils.ExitEventType:
		return convertExitEvent(event.(utils.ExitEvent)), nil
	case utils.ProcfsEventType:
		return convertProcfsEvent(event.(*events.ProcfsEvent)), nil
	default:
		return ProcessEvent{}, fmt.Errorf("unsupported event type: %s", eventType)
	}
}

// convertExecEvent converts an ExecEvent to ProcessEvent
func convertExecEvent(execEvent utils.ExecEvent) ProcessEvent {
	event := ProcessEvent{
		Type:        ExecEvent,
		Timestamp:   time.Now(),
		PID:         execEvent.GetPID(),
		PPID:        execEvent.GetPpid(),
		Comm:        execEvent.GetComm(),
		Path:        execEvent.GetExePath(),
		Pcomm:       execEvent.GetPcomm(),
		StartTimeNs: uint64(execEvent.GetTimestamp()), // Use event timestamp for consistency
	}

	// Convert command line arguments to string
	if args := execEvent.GetArgs(); len(args) > 0 {
		cmdline := strings.Join(args, " ")
		event.Cmdline = cmdline
	}

	// Set UID and GID if available
	if uid := execEvent.GetUid(); uid != nil {
		event.Uid = uid
	}
	if gid := execEvent.GetGid(); gid != nil {
		event.Gid = gid
	}

	// Set container context if available
	if containerId := execEvent.GetContainerID(); containerId != "" {
		event.ContainerID = containerId
	}

	return event
}

// convertForkEvent converts a ForkEvent to ProcessEvent
func convertForkEvent(forkEvent utils.ForkEvent) ProcessEvent {
	event := ProcessEvent{
		Type:        ForkEvent,
		Timestamp:   time.Now(),
		PID:         forkEvent.GetPID(),
		PPID:        forkEvent.GetPpid(),
		Comm:        forkEvent.GetComm(),
		Pcomm:       forkEvent.GetPcomm(),
		Path:        forkEvent.GetExePath(),
		StartTimeNs: uint64(forkEvent.GetTimestamp()), // Use event timestamp for consistency
	}

	// Set UID and GID if available
	if uid := forkEvent.GetUid(); uid != nil {
		event.Uid = uid
	}
	if gid := forkEvent.GetGid(); gid != nil {
		event.Gid = gid
	}

	// Set container context if available
	if containerId := forkEvent.GetContainerID(); containerId != "" {
		event.ContainerID = containerId
	}

	return event
}

// convertExitEvent converts an ExitEvent to ProcessEvent
func convertExitEvent(exitEvent utils.ExitEvent) ProcessEvent {
	event := ProcessEvent{
		Type:        ExitEvent,
		Timestamp:   time.Now(),
		PID:         exitEvent.GetPID(),
		PPID:        exitEvent.GetPpid(),
		Comm:        exitEvent.GetComm(),
		StartTimeNs: uint64(exitEvent.GetTimestamp()), // Use event timestamp for consistency
	}

	// Set UID and GID if available
	if uid := exitEvent.GetUid(); uid != nil {
		event.Uid = uid
	}
	if gid := exitEvent.GetGid(); gid != nil {
		event.Gid = gid
	}

	// Set container context if available
	if containerId := exitEvent.GetContainerID(); containerId != "" {
		event.ContainerID = containerId
	}

	return event
}

// convertProcfsEvent converts a ProcfsEvent to ProcessEvent
func convertProcfsEvent(procfsEvent *events.ProcfsEvent) ProcessEvent {
	event := ProcessEvent{
		Type:        ProcfsEvent,
		Timestamp:   time.Unix(0, int64(procfsEvent.Timestamp)),
		PID:         procfsEvent.PID,
		PPID:        procfsEvent.PPID,
		Comm:        procfsEvent.Comm,
		Pcomm:       procfsEvent.Pcomm,
		Cmdline:     procfsEvent.Cmdline,
		Uid:         procfsEvent.Uid,
		Gid:         procfsEvent.Gid,
		Cwd:         procfsEvent.Cwd,
		Path:        procfsEvent.Path,
		StartTimeNs: procfsEvent.StartTimeNs,
		ContainerID: procfsEvent.ContainerID,
		HostPID:     procfsEvent.HostPID,
		HostPPID:    procfsEvent.HostPPID,
	}

	return event
}
