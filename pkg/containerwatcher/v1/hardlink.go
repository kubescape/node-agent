package containerwatcher

import (
	"fmt"

	tracerhardlink "github.com/kubescape/node-agent/pkg/ebpf/gadgets/hardlink/tracer"
	tracerhardlinktype "github.com/kubescape/node-agent/pkg/ebpf/gadgets/hardlink/types"

	"github.com/inspektor-gadget/inspektor-gadget/pkg/types"
	"github.com/kubescape/go-logger"
	"github.com/kubescape/go-logger/helpers"
)

func (ch *IGContainerWatcher) hardlinkEventCallback(event *tracerhardlinktype.Event) {
	if event.Type == types.DEBUG {
		return
	}

	if isDroppedEvent(event.Type, event.Message) {
		logger.L().Ctx(ch.ctx).Warning("hardlink tracer got drop events - we may miss some realtime data", helpers.Interface("event", event), helpers.String("error", event.Message))
		return
	}

	ch.hardlinkWorkerChan <- event
}

func (ch *IGContainerWatcher) startHardlinkTracing() error {
	if err := ch.tracerCollection.AddTracer(hardlinkTraceName, ch.containerSelector); err != nil {
		return fmt.Errorf("adding tracer: %w", err)
	}

	// Get mount namespace map to filter by containers
	hardlinkMountnsmap, err := ch.tracerCollection.TracerMountNsMap(hardlinkTraceName)
	if err != nil {
		return fmt.Errorf("getting hardlinkMountnsmap: %w", err)
	}

	tracerHardlink, err := tracerhardlink.NewTracer(&tracerhardlink.Config{MountnsMap: hardlinkMountnsmap}, ch.containerCollection, ch.hardlinkEventCallback)
	if err != nil {
		return fmt.Errorf("creating tracer: %w", err)
	}
	go func() {
		for event := range ch.hardlinkWorkerChan {
			_ = ch.hardlinkWorkerPool.Invoke(*event)
		}
	}()

	ch.hardlinkTracer = tracerHardlink

	return nil
}

func (ch *IGContainerWatcher) stopHardlinkTracing() error {
	// Stop hardlink tracer
	if err := ch.tracerCollection.RemoveTracer(hardlinkTraceName); err != nil {
		return fmt.Errorf("removing tracer: %w", err)
	}
	ch.hardlinkTracer.Stop()
	return nil
}
