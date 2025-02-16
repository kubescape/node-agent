package hostwatcher

import (
	"fmt"

	tracerandomx "github.com/kubescape/node-agent/pkg/ebpf/gadgets/randomx/tracer"
	tracerrandomxtype "github.com/kubescape/node-agent/pkg/ebpf/gadgets/randomx/types"

	"github.com/inspektor-gadget/inspektor-gadget/pkg/types"
	"github.com/kubescape/go-logger"
	"github.com/kubescape/go-logger/helpers"
)

func (ch *IGHostWatcher) randomxEventCallback(event *tracerrandomxtype.Event) {
	if event.Type == types.DEBUG || event.Pid == ch.ownPid {
		return
	}

	if isDroppedEvent(event.Type, event.Message) {
		logger.L().Ctx(ch.ctx).Warning("randomx tracer got drop events - we may miss some realtime data", helpers.Interface("event", event), helpers.String("error", event.Message))
		return
	}

	ch.randomxWorkerChan <- event
}

func (ch *IGHostWatcher) startRandomxTracing() error {
	if err := ch.tracerCollection.AddTracer(randomxTraceName, ch.containerSelector); err != nil {
		return fmt.Errorf("adding tracer: %w", err)
	}

	// Get mount namespace map to filter by containers
	randomxMountnsmap, err := ch.tracerCollection.TracerMountNsMap(randomxTraceName)
	if err != nil {
		return fmt.Errorf("getting randomxMountnsmap: %w", err)
	}

	tracerrandomx, err := tracerandomx.NewTracer(&tracerandomx.Config{MountnsMap: randomxMountnsmap}, ch.containerCollection, ch.randomxEventCallback)
	if err != nil {
		return fmt.Errorf("creating tracer: %w", err)
	}
	go func() {
		for event := range ch.randomxWorkerChan {
			_ = ch.randomxWorkerPool.Invoke(*event)
		}
	}()

	ch.randomxTracer = tracerrandomx

	return nil
}

func (ch *IGHostWatcher) stopRandomxTracing() error {
	// Stop randomx tracer
	if err := ch.tracerCollection.RemoveTracer(randomxTraceName); err != nil {
		return fmt.Errorf("removing tracer: %w", err)
	}
	ch.randomxTracer.Stop()
	return nil
}
