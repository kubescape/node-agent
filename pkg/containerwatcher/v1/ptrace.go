package containerwatcher

import (
	"fmt"

	"github.com/inspektor-gadget/inspektor-gadget/pkg/types"
	tracerptrace "github.com/kubescape/node-agent/pkg/ebpf/gadgets/ptrace/tracer"
	tracerptracetype "github.com/kubescape/node-agent/pkg/ebpf/gadgets/ptrace/tracer/types"
)

func (ch *IGContainerWatcher) ptraceEventCallback(event *tracerptracetype.Event) {
	if event.Type != types.NORMAL {
		return
	}

	ch.ptraceWorkerChan <- event

}

func (ch *IGContainerWatcher) startPtraceTracing() error {
	if err := ch.tracerCollection.AddTracer(ptraceTraceName, ch.containerSelector); err != nil {
		return fmt.Errorf("adding tracer: %w", err)
	}

	// Get mount namespace map to filter by containers
	ptraceMountnsmap, err := ch.tracerCollection.TracerMountNsMap(ptraceTraceName)
	if err != nil {
		return fmt.Errorf("getting ptraceMountnsmap: %w", err)
	}

	tracerPtrace, err := tracerptrace.NewTracer(&tracerptrace.Config{MountnsMap: ptraceMountnsmap}, ch.containerCollection, ch.ptraceEventCallback)
	if err != nil {
		return fmt.Errorf("creating tracer: %w", err)
	}
	go func() {
		for event := range ch.ptraceWorkerChan {
			_ = ch.ptraceWorkerPool.Invoke(*event)
		}
	}()

	ch.ptraceTracer = tracerPtrace

	return nil
}

func (ch *IGContainerWatcher) stopPtraceTracing() error {
	if err := ch.tracerCollection.RemoveTracer(ptraceTraceName); err != nil {
		return fmt.Errorf("removing tracer: %w", err)
	}
	ch.ptraceTracer.Close()
	return nil
}
