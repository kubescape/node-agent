package conversion

import (
	"fmt"
	"time"

	events "github.com/kubescape/node-agent/pkg/ebpf/events"
	tracerexittype "github.com/kubescape/node-agent/pkg/ebpf/gadgets/exit/types"
	tracerforktype "github.com/kubescape/node-agent/pkg/ebpf/gadgets/fork/types"
	"github.com/kubescape/node-agent/pkg/utils"
)

func ConvertEvent(eventType utils.EventType, event utils.K8sEvent) (ProcessEvent, error) {
	switch eventType {
	case utils.ExecveEventType:
		return convertExecEvent(event.(*events.ExecEvent)), nil
	case utils.ForkEventType:
		return convertForkEvent(event.(*tracerforktype.Event)), nil
	case utils.ExitEventType:
		return convertExitEvent(event.(*tracerexittype.Event)), nil
	case utils.ProcfsEventType:
		return convertProcfsEvent(event.(*events.ProcfsEvent)), nil
	default:
		return ProcessEvent{}, fmt.Errorf("unsupported event type: %s", eventType)
	}
}

// convertExecEvent converts an ExecEvent to ProcessEvent
func convertExecEvent(execEvent *events.ExecEvent) ProcessEvent {
	event := ProcessEvent{
		Type:        ExecEvent,
		Timestamp:   time.Now(),
		PID:         execEvent.Pid,
		PPID:        execEvent.Ppid,
		Comm:        execEvent.Comm,
		Path:        execEvent.ExePath,
		Pcomm:       execEvent.Pcomm,
		StartTimeNs: uint64(execEvent.Timestamp), // Use event timestamp for consistency
	}

	// Convert command line arguments to string
	if len(execEvent.Args) > 0 {
		// Join all arguments with spaces
		cmdline := ""
		for i, arg := range execEvent.Args {
			if i > 0 {
				cmdline += " "
			}
			cmdline += arg
		}
		event.Cmdline = cmdline
	}

	// Set UID and GID if available
	if execEvent.Uid != 0 {
		uid := execEvent.Uid
		event.Uid = &uid
	}
	if execEvent.Gid != 0 {
		gid := execEvent.Gid
		event.Gid = &gid
	}

	// Set container context if available
	if execEvent.Runtime.ContainerID != "" {
		event.ContainerID = execEvent.Runtime.ContainerID
	}

	return event
}

// convertForkEvent converts a ForkEvent to ProcessEvent
func convertForkEvent(forkEvent *tracerforktype.Event) ProcessEvent {
	event := ProcessEvent{
		Type:        ForkEvent,
		Timestamp:   time.Now(),
		PID:         forkEvent.Pid,
		PPID:        forkEvent.PPid,
		Comm:        forkEvent.Comm,
		Path:        forkEvent.ExePath,
		StartTimeNs: uint64(forkEvent.Timestamp), // Use event timestamp for consistency
	}

	// Set UID and GID if available
	if forkEvent.Uid != 0 {
		uid := forkEvent.Uid
		event.Uid = &uid
	}
	if forkEvent.Gid != 0 {
		gid := forkEvent.Gid
		event.Gid = &gid
	}

	// Set container context if available
	if forkEvent.Runtime.ContainerID != "" {
		event.ContainerID = forkEvent.Runtime.ContainerID
	}

	return event
}

// convertExitEvent converts an ExitEvent to ProcessEvent
func convertExitEvent(exitEvent *tracerexittype.Event) ProcessEvent {
	event := ProcessEvent{
		Type:        ExitEvent,
		Timestamp:   time.Now(),
		PID:         exitEvent.Pid,
		PPID:        exitEvent.PPid,
		Comm:        exitEvent.Comm,
		StartTimeNs: uint64(exitEvent.Timestamp), // Use event timestamp for consistency
	}

	// Set UID and GID if available
	if exitEvent.Uid != 0 {
		uid := exitEvent.Uid
		event.Uid = &uid
	}
	if exitEvent.Gid != 0 {
		gid := exitEvent.Gid
		event.Gid = &gid
	}

	// Set container context if available
	if exitEvent.Runtime.ContainerID != "" {
		event.ContainerID = exitEvent.Runtime.ContainerID
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
