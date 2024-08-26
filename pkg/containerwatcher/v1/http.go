package containerwatcher

import (
	"fmt"

	tracerhttp "github.com/kubescape/node-agent/pkg/ebpf/gadgets/http/tracer"
	tracerhttptype "github.com/kubescape/node-agent/pkg/ebpf/gadgets/http/types"

	"github.com/inspektor-gadget/inspektor-gadget/pkg/container-collection/networktracer"
	"github.com/inspektor-gadget/inspektor-gadget/pkg/types"
	"github.com/kubescape/go-logger"
	"github.com/kubescape/go-logger/helpers"
)

func (ch *IGContainerWatcher) httpEventCallback(event *tracerhttptype.Event) {
	if event.Type == types.DEBUG {
		return
	}

	if isDroppedEvent(event.Type, event.Message) {
		logger.L().Ctx(ch.ctx).Warning("ssh tracer got drop events - we may miss some realtime data", helpers.Interface("event", event), helpers.String("error", event.Message))
		return
	}

	ch.containerCollection.EnrichByMntNs(&event.CommonData, event.MountNsID)
	ch.containerCollection.EnrichByNetNs(&event.CommonData, event.NetNsID)

	ch.httpWorkerChan <- event
}

func (ch *IGContainerWatcher) startHttpTracing() error {
	if err := ch.tracerCollection.AddTracer(httpTraceName, ch.containerSelector); err != nil {
		return fmt.Errorf("adding tracer: %w", err)
	}

	tracerHttp, err := tracerhttp.NewTracer()
	if err != nil {
		return fmt.Errorf("creating tracer: %w", err)
	}
	go func() {
		for event := range ch.sshWorkerChan {
			_ = ch.sshdWorkerPool.Invoke(*event)
		}
	}()

	tracerHttp.SetSocketEnricherMap(ch.socketEnricher.SocketsMap())
	tracerHttp.SetEventHandler(ch.httpEventCallback)

	err = tracerHttp.RunWorkaround()
	if err != nil {
		return fmt.Errorf("running workaround: %w", err)
	}

	ch.httpTracer = tracerHttp

	config := &networktracer.ConnectToContainerCollectionConfig[tracerhttptype.Event]{
		Tracer:   ch.httpTracer,
		Resolver: ch.containerCollection,
		Selector: ch.containerSelector,
		Base:     tracerhttptype.Base,
	}

	_, err = networktracer.ConnectToContainerCollection(config)
	if err != nil {
		return fmt.Errorf("creating tracer: %w", err)
	}

	return nil
}

func (ch *IGContainerWatcher) stopHttpTracing() error {
	// Stop ssh tracer
	if err := ch.tracerCollection.RemoveTracer(httpTraceName); err != nil {
		return fmt.Errorf("removing tracer: %w", err)
	}
	ch.sshTracer.Close()
	return nil
}
