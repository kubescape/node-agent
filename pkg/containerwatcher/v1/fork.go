package containerwatcher

import (
	"fmt"

	tracerfork "github.com/kubescape/node-agent/pkg/ebpf/gadgets/fork/tracer"
	tracerforktype "github.com/kubescape/node-agent/pkg/ebpf/gadgets/fork/types"
	"github.com/kubescape/node-agent/pkg/utils"

	"github.com/inspektor-gadget/inspektor-gadget/pkg/types"
	"github.com/kubescape/go-logger"
	"github.com/kubescape/go-logger/helpers"
)

func (ch *IGContainerWatcher) forkEventCallback(event *tracerforktype.Event) {
	if event.Type == types.DEBUG {
		return
	}

	if isDroppedEvent(event.Type, event.Message) {
		logger.L().Ctx(ch.ctx).Warning("fork tracer got drop events - we may miss some realtime data", helpers.Interface("event", event), helpers.String("error", event.Message))
		return
	}

	ch.handleEvent(event, []uint64{}, ch.forkEnricherCallback)
}

func (ch *IGContainerWatcher) startForkTracing() error {
	if err := ch.tracerCollection.AddTracer(forkTraceName, ch.containerSelector); err != nil {
		return fmt.Errorf("adding tracer: %w", err)
	}

	// Get mount namespace map to filter by containers
	forkMountnsmap, err := ch.tracerCollection.TracerMountNsMap(forkTraceName)
	if err != nil {
		return fmt.Errorf("getting forkMountnsmap: %w", err)
	}

	tracerFork, err := tracerfork.NewTracer(&tracerfork.Config{MountnsMap: forkMountnsmap}, ch.containerCollection, ch.forkEventCallback)
	if err != nil {
		return fmt.Errorf("creating tracer: %w", err)
	}
	go func() {
		for event := range ch.forkWorkerChan {
			_ = ch.forkWorkerPool.Invoke(*event)
		}
	}()

	ch.forkTracer = tracerFork

	return nil
}

func (ch *IGContainerWatcher) stopForkTracing() error {
	// Stop fork tracer
	if err := ch.tracerCollection.RemoveTracer(forkTraceName); err != nil {
		return fmt.Errorf("removing tracer: %w", err)
	}
	ch.forkTracer.Stop()
	return nil
}

func (ch *IGContainerWatcher) forkEnricherCallback(event utils.EnrichEvent) {
	ch.forkWorkerChan <- event.(*tracerforktype.Event)
}
