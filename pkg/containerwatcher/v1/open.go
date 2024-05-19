package containerwatcher

import (
	"fmt"

	traceropen "github.com/inspektor-gadget/inspektor-gadget/pkg/gadgets/trace/open/tracer"
	traceropentype "github.com/inspektor-gadget/inspektor-gadget/pkg/gadgets/trace/open/types"
	"github.com/inspektor-gadget/inspektor-gadget/pkg/types"
	"github.com/kubescape/go-logger"
	"github.com/kubescape/go-logger/helpers"
)

func (ch *IGContainerWatcher) openEventCallback(event *traceropentype.Event) {
	if event.Type != types.NORMAL {
		// dropped event
		logger.L().Ctx(ch.ctx).Warning("open tracer got drop events - we may miss some realtime data", helpers.Interface("event", event), helpers.String("error", event.Message))
	}
	if event.Err > -1 && event.FullPath != "" {
		ch.openWorkerChan <- event
	}
}

func (ch *IGContainerWatcher) startOpenTracing() error {
	if err := ch.tracerCollection.AddTracer(openTraceName, ch.containerSelector); err != nil {
		return fmt.Errorf("adding tracer: %w", err)
	}

	go func() {
		for c := range ch.openWorkerChan {
			_ = ch.openWorkerPool.Invoke(*c)
		}
	}()

	// Get mount namespace map to filter by containers
	openMountnsmap, err := ch.tracerCollection.TracerMountNsMap(openTraceName)
	if err != nil {
		return fmt.Errorf("getting openMountnsmap: %w", err)
	}

	tracerOpen, err := traceropen.NewTracer(&traceropen.Config{MountnsMap: openMountnsmap, FullPath: true}, ch.containerCollection, ch.openEventCallback)
	if err != nil {
		return fmt.Errorf("creating tracer: %w", err)
	}
	ch.openTracer = tracerOpen

	return nil
}

func (ch *IGContainerWatcher) stopOpenTracing() error {
	// Stop open tracer
	if err := ch.tracerCollection.RemoveTracer(openTraceName); err != nil {
		return fmt.Errorf("removing tracer: %w", err)
	}
	ch.openTracer.Stop()
	return nil
}
