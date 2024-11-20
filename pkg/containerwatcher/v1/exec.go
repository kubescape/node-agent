package containerwatcher

import (
	"fmt"

	tracerexec "github.com/inspektor-gadget/inspektor-gadget/pkg/gadgets/trace/exec/tracer"
	tracerexectype "github.com/inspektor-gadget/inspektor-gadget/pkg/gadgets/trace/exec/types"
	"github.com/inspektor-gadget/inspektor-gadget/pkg/types"
	events "github.com/kubescape/node-agent/pkg/ebpf/events"
	"golang.org/x/sys/unix"
)

func (ch *IGContainerWatcher) execEventCallback(event *tracerexectype.Event) {
	if event.Type == types.DEBUG {
		return
	}

	execEvent := &events.ExecEvent{Event: *event}
	ch.enrichEvent(execEvent, []uint64{unix.SYS_EXECVE, unix.SYS_EXECVEAT})

	if event.Retval > -1 && event.Comm != "" {
		ch.execWorkerChan <- execEvent
	}
}

func (ch *IGContainerWatcher) startExecTracing() error {
	if err := ch.tracerCollection.AddTracer(execTraceName, ch.containerSelector); err != nil {
		return fmt.Errorf("adding tracer: %w", err)
	}

	// Get mount namespace map to filter by containers
	execMountnsmap, err := ch.tracerCollection.TracerMountNsMap(execTraceName)
	if err != nil {
		return fmt.Errorf("getting execMountnsmap: %w", err)
	}

	tracerExec, err := tracerexec.NewTracer(&tracerexec.Config{MountnsMap: execMountnsmap, GetPaths: true}, ch.containerCollection, ch.execEventCallback)
	if err != nil {
		return fmt.Errorf("creating tracer: %w", err)
	}
	go func() {
		for event := range ch.execWorkerChan {
			_ = ch.execWorkerPool.Invoke(*event)
		}
	}()

	ch.execTracer = tracerExec

	return nil
}

func (ch *IGContainerWatcher) stopExecTracing() error {
	// Stop exec tracer
	if err := ch.tracerCollection.RemoveTracer(execTraceName); err != nil {
		return fmt.Errorf("removing tracer: %w", err)
	}
	ch.execTracer.Stop()
	return nil
}
