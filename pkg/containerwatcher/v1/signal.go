package containerwatcher

import (
	"fmt"

	tracersignal "github.com/inspektor-gadget/inspektor-gadget/pkg/gadgets/trace/signal/tracer"
	tracersignaltype "github.com/inspektor-gadget/inspektor-gadget/pkg/gadgets/trace/signal/types"
	"github.com/inspektor-gadget/inspektor-gadget/pkg/types"
	"github.com/kubescape/go-logger"
	"github.com/kubescape/go-logger/helpers"
)

func (ch *IGContainerWatcher) signalEventCallback(event *tracersignaltype.Event) {
	if event.Type != types.NORMAL {
		// dropped event
		logger.L().Ctx(ch.ctx).Warning("signal tracer got drop events - we may miss some realtime data", helpers.Interface("event", event), helpers.String("error", event.Message))
	}
	if event.Retval > -1 && event.Comm != "" {
		ch.signalWorkerChan <- event
	}
}

func (ch *IGContainerWatcher) startSignalTracing() error {
	if err := ch.tracerCollection.AddTracer(signalTraceName, ch.containerSelector); err != nil {
		return fmt.Errorf("adding tracer: %w", err)
	}

	// Get mount namespace map to filter by containers
	signalMountnsmap, err := ch.tracerCollection.TracerMountNsMap(signalTraceName)
	if err != nil {
		return fmt.Errorf("getting signalMountnsmap: %w", err)
	}

	go func() {
		for event := range ch.signalWorkerChan {
			ch.signalWorkerPool.Invoke(*event)
		}
	}()

	tracerSignal, err := tracersignal.NewTracer(&tracersignal.Config{MountnsMap: signalMountnsmap, KillOnly: true}, ch.containerCollection, ch.signalEventCallback)
	if err != nil {
		return fmt.Errorf("creating tracer: %w", err)
	}
	ch.signalTracer = tracerSignal

	return nil
}

func (ch *IGContainerWatcher) stopSignalTracing() error {
	// Stop signal tracer
	if err := ch.tracerCollection.RemoveTracer(signalTraceName); err != nil {
		return fmt.Errorf("removing tracer: %w", err)
	}
	ch.signalTracer.Stop()
	return nil
}
