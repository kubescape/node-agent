package containerwatcher

import (
	"fmt"

	tracercapabilities "github.com/inspektor-gadget/inspektor-gadget/pkg/gadgets/trace/capabilities/tracer"
	tracercapabilitiestype "github.com/inspektor-gadget/inspektor-gadget/pkg/gadgets/trace/capabilities/types"
	"github.com/inspektor-gadget/inspektor-gadget/pkg/types"
	"github.com/kubescape/go-logger"
	"github.com/kubescape/go-logger/helpers"
)

func (ch *IGContainerWatcher) capabilitiesEventCallback(event *tracercapabilitiestype.Event) {
	if event.Type != types.NORMAL {
		// dropped event
		logger.L().Ctx(ch.ctx).Warning("capabilities tracer got drop events - we may miss some realtime data", helpers.Interface("event", event), helpers.String("error", event.Message))
		return
	}
	_ = ch.capabilitiesWorkerPool.Invoke(*event)
}

func (ch *IGContainerWatcher) startCapabilitiesTracing() error {
	if err := ch.tracerCollection.AddTracer(capabilitiesTraceName, ch.containerSelector); err != nil {
		return fmt.Errorf("adding tracer: %w", err)
	}

	// Get mount namespace map to filter by containers
	capabilitiesMountnsmap, err := ch.tracerCollection.TracerMountNsMap(capabilitiesTraceName)
	if err != nil {
		return fmt.Errorf("getting capabilitiesMountnsmap: %w", err)
	}

	tracerCapabilities, err := tracercapabilities.NewTracer(&tracercapabilities.Config{MountnsMap: capabilitiesMountnsmap}, ch.containerCollection, ch.capabilitiesEventCallback)
	if err != nil {
		return fmt.Errorf("creating tracer: %w", err)
	}
	ch.capabilitiesTracer = tracerCapabilities

	return nil
}

func (ch *IGContainerWatcher) stopCapabilitiesTracing() error {
	// Stop capabilities tracer
	if err := ch.tracerCollection.RemoveTracer(capabilitiesTraceName); err != nil {
		return fmt.Errorf("removing tracer: %w", err)
	}
	ch.capabilitiesTracer.Stop()
	return nil
}
