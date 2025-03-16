package containerwatcher

import (
	"fmt"

	"github.com/inspektor-gadget/inspektor-gadget/pkg/gadgets/top"
	toptracer "github.com/inspektor-gadget/inspektor-gadget/pkg/gadgets/top/ebpf/tracer"
	toptypes "github.com/inspektor-gadget/inspektor-gadget/pkg/gadgets/top/ebpf/types"
)

func (ch *IGContainerWatcher) topEventCallback(event *top.Event[toptypes.Stats]) {
	ch.topWorkerChan <- event
}

func (ch *IGContainerWatcher) startTopTracing() error {
	if err := ch.tracerCollection.AddTracer(topTraceName, ch.containerSelector); err != nil {
		return fmt.Errorf("adding top tracer: %w", err)
	}

	topTracer, err := toptracer.NewTracer(&toptracer.Config{}, ch.containerCollection, ch.topEventCallback)
	if err != nil {
		return fmt.Errorf("creating top tracer: %w", err)
	}

	go func() {
		for event := range ch.topWorkerChan {
			_ = ch.topWorkerPool.Invoke(*event)
		}
	}()

	ch.topTracer = topTracer
	return nil
}

func (ch *IGContainerWatcher) stopTopTracing() error {
	if err := ch.tracerCollection.RemoveTracer(topTraceName); err != nil {
		return fmt.Errorf("removing top tracer: %w", err)
	}
	ch.topTracer.Stop()
	return nil
}
