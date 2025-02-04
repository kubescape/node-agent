package containerwatcher

import (
	"fmt"

	traceriouring "github.com/kubescape/node-agent/pkg/ebpf/gadgets/iouring/tracer"
	traceriouringtype "github.com/kubescape/node-agent/pkg/ebpf/gadgets/iouring/tracer/types"

	"github.com/inspektor-gadget/inspektor-gadget/pkg/types"
	"github.com/kubescape/go-logger"
	"github.com/kubescape/go-logger/helpers"
)

func (ch *IGContainerWatcher) iouringEventCallback(event *traceriouringtype.Event) {
	if event.Type == types.DEBUG {
		return
	}

	if isDroppedEvent(event.Type, event.Message) {
		logger.L().Ctx(ch.ctx).Warning("io_uring tracer got drop events - we may miss some realtime data",
			helpers.Interface("event", event),
			helpers.String("error", event.Message))
		return
	}

	ch.iouringWorkerChan <- event
}

func (ch *IGContainerWatcher) startIouringTracing() error {
	if err := ch.tracerCollection.AddTracer(iouringTraceName, ch.containerSelector); err != nil {
		return fmt.Errorf("adding tracer: %w", err)
	}

	// Get mount namespace map to filter by containers
	iouringMountnsmap, err := ch.tracerCollection.TracerMountNsMap(iouringTraceName)
	if err != nil {
		return fmt.Errorf("getting iouringMountnsmap: %w", err)
	}

	tracerIouring, err := traceriouring.NewTracer(
		&traceriouring.Config{MountnsMap: iouringMountnsmap},
		ch.containerCollection,
		ch.iouringEventCallback)
	if err != nil {
		return fmt.Errorf("creating tracer: %w", err)
	}

	go func() {
		for event := range ch.iouringWorkerChan {
			_ = ch.iouringWorkerPool.Invoke(*event)
		}
	}()

	ch.iouringTracer = tracerIouring

	return nil
}

func (ch *IGContainerWatcher) stopIouringTracing() error {
	// Stop io_uring tracer
	if err := ch.tracerCollection.RemoveTracer(iouringTraceName); err != nil {
		return fmt.Errorf("removing tracer: %w", err)
	}
	ch.iouringTracer.Stop()
	return nil
}
