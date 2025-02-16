package hostwatcher

import (
	"fmt"

	tracerssh "github.com/kubescape/node-agent/pkg/ebpf/gadgets/ssh/tracer"
	tracersshtype "github.com/kubescape/node-agent/pkg/ebpf/gadgets/ssh/types"

	"github.com/inspektor-gadget/inspektor-gadget/pkg/container-collection/networktracer"
	"github.com/inspektor-gadget/inspektor-gadget/pkg/types"
	"github.com/kubescape/go-logger"
	"github.com/kubescape/go-logger/helpers"
)

func (ch *IGHostWatcher) sshEventCallback(event *tracersshtype.Event) {
	if event.Type == types.DEBUG || event.Pid == ch.ownPid {
		return
	}

	if isDroppedEvent(event.Type, event.Message) {
		logger.L().Ctx(ch.ctx).Warning("ssh tracer got drop events - we may miss some realtime data", helpers.Interface("event", event), helpers.String("error", event.Message))
		return
	}

	ch.containerCollection.EnrichByMntNs(&event.CommonData, event.MountNsID)
	ch.containerCollection.EnrichByNetNs(&event.CommonData, event.NetNsID)

	ch.sshWorkerChan <- event
}

func (ch *IGHostWatcher) startSshTracing() error {
	if err := ch.tracerCollection.AddTracer(sshTraceName, ch.containerSelector); err != nil {
		return fmt.Errorf("adding tracer: %w", err)
	}

	tracerSsh, err := tracerssh.NewTracer()
	if err != nil {
		return fmt.Errorf("creating tracer: %w", err)
	}
	go func() {
		for event := range ch.sshWorkerChan {
			_ = ch.sshdWorkerPool.Invoke(*event)
		}
	}()

	tracerSsh.SetSocketEnricherMap(ch.socketEnricher.SocketsMap())
	tracerSsh.SetEventHandler(ch.sshEventCallback)

	err = tracerSsh.RunWorkaround()
	if err != nil {
		return fmt.Errorf("running workaround: %w", err)
	}

	ch.sshTracer = tracerSsh

	config := &networktracer.ConnectToContainerCollectionConfig[tracersshtype.Event]{
		Tracer:   ch.sshTracer,
		Resolver: ch.containerCollection,
		Selector: ch.containerSelector,
		Base:     tracersshtype.Base,
	}

	_, err = networktracer.ConnectToContainerCollection(config)
	if err != nil {
		return fmt.Errorf("creating tracer: %w", err)
	}

	return nil
}

func (ch *IGHostWatcher) stopSshTracing() error {
	// Stop ssh tracer
	if err := ch.tracerCollection.RemoveTracer(sshTraceName); err != nil {
		return fmt.Errorf("removing tracer: %w", err)
	}
	ch.sshTracer.Close()
	return nil
}
