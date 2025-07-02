package containerwatcher

import (
	"fmt"

	tracerexit "github.com/kubescape/node-agent/pkg/ebpf/gadgets/exit/tracer"
	tracerexittype "github.com/kubescape/node-agent/pkg/ebpf/gadgets/exit/types"
	"github.com/kubescape/node-agent/pkg/utils"

	"github.com/inspektor-gadget/inspektor-gadget/pkg/types"
	"github.com/kubescape/go-logger"
	"github.com/kubescape/go-logger/helpers"
)

func (ch *IGContainerWatcher) exitEventCallback(event *tracerexittype.Event) {
	if event.Type == types.DEBUG {
		return
	}

	if isDroppedEvent(event.Type, event.Message) {
		logger.L().Ctx(ch.ctx).Warning("exit tracer got drop events - we may miss some realtime data", helpers.Interface("event", event), helpers.String("error", event.Message))
		return
	}

	ch.handleEvent(event, []uint64{}, ch.exitEnricherCallback)
}

func (ch *IGContainerWatcher) startExitTracing() error {
	if err := ch.tracerCollection.AddTracer(exitTraceName, ch.containerSelector); err != nil {
		return fmt.Errorf("adding tracer: %w", err)
	}

	// Get mount namespace map to filter by containers
	exitMountnsmap, err := ch.tracerCollection.TracerMountNsMap(exitTraceName)
	if err != nil {
		return fmt.Errorf("getting exitMountnsmap: %w", err)
	}

	tracerExit, err := tracerexit.NewTracer(&tracerexit.Config{MountnsMap: exitMountnsmap}, ch.containerCollection, ch.exitEventCallback)
	if err != nil {
		return fmt.Errorf("creating tracer: %w", err)
	}
	go func() {
		for event := range ch.exitWorkerChan {
			_ = ch.exitWorkerPool.Invoke(*event)
		}
	}()

	ch.exitTracer = tracerExit

	return nil
}

func (ch *IGContainerWatcher) stopExitTracing() error {
	// Stop exit tracer
	if err := ch.tracerCollection.RemoveTracer(exitTraceName); err != nil {
		return fmt.Errorf("removing tracer: %w", err)
	}
	ch.exitTracer.Stop()
	return nil
}

func (ch *IGContainerWatcher) exitEnricherCallback(event utils.EnrichEvent) {
	ch.exitWorkerChan <- event.(*tracerexittype.Event)
}
