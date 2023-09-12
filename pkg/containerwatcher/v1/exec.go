package containerwatcher

import (
	"fmt"

	tracerexec "github.com/inspektor-gadget/inspektor-gadget/pkg/gadgets/trace/exec/tracer"
	tracerexectype "github.com/inspektor-gadget/inspektor-gadget/pkg/gadgets/trace/exec/types"
	"github.com/inspektor-gadget/inspektor-gadget/pkg/types"
	"github.com/kubescape/go-logger"
	"github.com/kubescape/go-logger/helpers"
)

func (ch *IGContainerWatcher) execEventCallback(event *tracerexectype.Event) {
	if event.Type != types.NORMAL {
		// dropped event
		logger.L().Ctx(ch.ctx).Warning("exec tracer got drop events - we may miss some realtime data", helpers.Interface("event", event), helpers.String("error", event.Message))
		return
	}
	if event.Retval > -1 {
		p := event.Comm
		if len(event.Args) > 0 {
			p = event.Args[0]
		}
		if p != "" {
			_ = ch.execWorkerPool.Invoke([4]string{event.K8s.Namespace, event.K8s.PodName, event.K8s.ContainerName, p})
		}
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

	tracerExec, err := tracerexec.NewTracer(&tracerexec.Config{MountnsMap: execMountnsmap}, ch.containerCollection, ch.execEventCallback)
	if err != nil {
		return fmt.Errorf("creating tracer: %w", err)
	}
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
