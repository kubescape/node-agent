package containerwatcher

import (
	"fmt"

	tracersymlink "github.com/kubescape/node-agent/pkg/ebpf/gadgets/symlink/tracer"
	tracersymlinktype "github.com/kubescape/node-agent/pkg/ebpf/gadgets/symlink/types"
	"github.com/kubescape/node-agent/pkg/utils"

	"github.com/inspektor-gadget/inspektor-gadget/pkg/types"
	"github.com/kubescape/go-logger"
	"github.com/kubescape/go-logger/helpers"
)

func (ch *IGContainerWatcher) symlinkEventCallback(event *tracersymlinktype.Event) {
	if event.Type == types.DEBUG {
		return
	}

	if isDroppedEvent(event.Type, event.Message) {
		logger.L().Ctx(ch.ctx).Warning("symlink tracer got drop events - we may miss some realtime data", helpers.Interface("event", event), helpers.String("error", event.Message))
		return
	}

	ch.handleEvent(event, []uint64{SYS_SYMLINK, SYS_SYMLINKAT}, ch.symlinkEnricherCallback)
}

func (ch *IGContainerWatcher) startSymlinkTracing() error {
	if err := ch.tracerCollection.AddTracer(symlinkTraceName, ch.containerSelector); err != nil {
		return fmt.Errorf("adding tracer: %w", err)
	}

	// Get mount namespace map to filter by containers
	symlinkMountnsmap, err := ch.tracerCollection.TracerMountNsMap(symlinkTraceName)
	if err != nil {
		return fmt.Errorf("getting symlinkMountnsmap: %w", err)
	}

	tracerSymlink, err := tracersymlink.NewTracer(&tracersymlink.Config{MountnsMap: symlinkMountnsmap}, ch.containerCollection, ch.symlinkEventCallback)
	if err != nil {
		return fmt.Errorf("creating tracer: %w", err)
	}
	go func() {
		for event := range ch.symlinkWorkerChan {
			_ = ch.symlinkWorkerPool.Invoke(*event)
		}
	}()

	ch.symlinkTracer = tracerSymlink

	return nil
}

func (ch *IGContainerWatcher) stopSymlinkTracing() error {
	// Stop symlink tracer
	if err := ch.tracerCollection.RemoveTracer(symlinkTraceName); err != nil {
		return fmt.Errorf("removing tracer: %w", err)
	}
	ch.symlinkTracer.Stop()
	return nil
}

func (ch *IGContainerWatcher) symlinkEnricherCallback(event utils.EnrichEvent) {
	ch.symlinkWorkerChan <- event.(*tracersymlinktype.Event)
}
