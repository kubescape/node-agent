package containerwatcher

import (
	"fmt"

	tracerandomx "node-agent/pkg/ebpf/gadgets/randomx/tracer"
	tracerrandomxtype "node-agent/pkg/ebpf/gadgets/randomx/types"

	"github.com/inspektor-gadget/inspektor-gadget/pkg/types"
	"github.com/kubescape/go-logger"
	"github.com/kubescape/go-logger/helpers"
)

func (ch *IGContainerWatcher) randomxEventCallback(event *tracerrandomxtype.Event) {
	if event.Type != types.NORMAL {
		// dropped event
		logger.L().Ctx(ch.ctx).Warning("randomx tracer got drop events - we may miss some realtime data", helpers.Interface("event", event), helpers.String("error", event.Message))
		return
	}

	_ = ch.randomxWorkerPool.Invoke(*event)
}

func (ch *IGContainerWatcher) startRandomxTracing() error {
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
	ch.randomxTracer = tracerrandomx

	return nil
}

func (ch *IGContainerWatcher) stopRandomxTracing() error {
	// Stop randomx tracer
	if err := ch.tracerCollection.RemoveTracer(randomxTraceName); err != nil {
		return fmt.Errorf("removing tracer: %w", err)
	}
	ch.randomxTracer.Stop()
	return nil
}
