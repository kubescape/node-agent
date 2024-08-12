package containerwatcher

import (
	"fmt"

	tracersshlink "github.com/kubescape/node-agent/pkg/ebpf/gadgets/ssh/tracer"
	tracersshtype "github.com/kubescape/node-agent/pkg/ebpf/gadgets/ssh/types"

	"github.com/inspektor-gadget/inspektor-gadget/pkg/types"
	"github.com/kubescape/go-logger"
	"github.com/kubescape/go-logger/helpers"
)

func (ch *IGContainerWatcher) sshEventCallback(event *tracersshtype.Event) {
	if event.Type == types.DEBUG {
		return
	}

	if isDroppedEvent(event.Type, event.Message) {
		logger.L().Ctx(ch.ctx).Warning("ssh tracer got drop events - we may miss some realtime data", helpers.Interface("event", event), helpers.String("error", event.Message))
		return
	}

	ch.sshWorkerChan <- event
}

func (ch *IGContainerWatcher) startSshTracing() error {
	if err := ch.tracerCollection.AddTracer(sshTraceName, ch.containerSelector); err != nil {
		return fmt.Errorf("adding tracer: %w", err)
	}

	// Get mount namespace map to filter by containers
	sshMountnsmap, err := ch.tracerCollection.TracerMountNsMap(sshTraceName)
	if err != nil {
		return fmt.Errorf("getting sshMountnsmap: %w", err)
	}

	tracerSsh, err := tracersshlink.NewTracer(&tracersshlink.Config{MountnsMap: sshMountnsmap}, ch.containerCollection, ch.sshEventCallback)
	if err != nil {
		return fmt.Errorf("creating tracer: %w", err)
	}
	go func() {
		for event := range ch.sshWorkerChan {
			_ = ch.sshdWorkerPool.Invoke(*event)
		}
	}()

	ch.sshTracer = tracerSsh

	return nil
}

func (ch *IGContainerWatcher) stopSshTracing() error {
	// Stop ssh tracer
	if err := ch.tracerCollection.RemoveTracer(sshTraceName); err != nil {
		return fmt.Errorf("removing tracer: %w", err)
	}
	ch.sshTracer.Stop()
	return nil
}
