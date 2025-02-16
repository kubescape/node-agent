package hostwatcher

import (
	"fmt"

	traceropen "github.com/inspektor-gadget/inspektor-gadget/pkg/gadgets/trace/open/tracer"
	traceropentype "github.com/inspektor-gadget/inspektor-gadget/pkg/gadgets/trace/open/types"
	"github.com/inspektor-gadget/inspektor-gadget/pkg/types"
	events "github.com/kubescape/node-agent/pkg/ebpf/events"
)

func (ch *IGHostWatcher) openEventCallback(event *traceropentype.Event) {
	if event.Type == types.DEBUG || event.Pid == ch.ownPid {
		return
	}

	openEvent := &events.OpenEvent{Event: *event}

	if event.Err > -1 && event.FullPath != "" {
		ch.openWorkerChan <- openEvent
	}
}

func (ch *IGHostWatcher) startOpenTracing() error {
	if err := ch.tracerCollection.AddTracer(openTraceName, ch.containerSelector); err != nil {
		return fmt.Errorf("adding tracer: %w", err)
	}

	// Get mount namespace map to filter by containers
	openMountnsmap, err := ch.tracerCollection.TracerMountNsMap(openTraceName)
	if err != nil {
		return fmt.Errorf("getting openMountnsmap: %w", err)
	}

	tracerOpen, err := traceropen.NewTracer(&traceropen.Config{MountnsMap: openMountnsmap, FullPath: true}, nil, ch.openEventCallback)
	if err != nil {
		return fmt.Errorf("creating tracer: %w", err)
	}
	go func() {
		for event := range ch.openWorkerChan {
			_ = ch.openWorkerPool.Invoke(*event)
		}
	}()

	ch.openTracer = tracerOpen

	return nil
}

func (ch *IGHostWatcher) stopOpenTracing() error {
	// Stop open tracer
	if err := ch.tracerCollection.RemoveTracer(openTraceName); err != nil {
		return fmt.Errorf("removing tracer: %w", err)
	}
	ch.openTracer.Stop()
	return nil
}
