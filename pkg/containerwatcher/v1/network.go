package containerwatcher

import (
	"fmt"

	"github.com/inspektor-gadget/inspektor-gadget/pkg/container-collection/networktracer"
	tracernetwork "github.com/inspektor-gadget/inspektor-gadget/pkg/gadgets/trace/network/tracer"
	tracernetworktypes "github.com/inspektor-gadget/inspektor-gadget/pkg/gadgets/trace/network/types"
	"github.com/inspektor-gadget/inspektor-gadget/pkg/types"
	"github.com/inspektor-gadget/inspektor-gadget/pkg/utils/host"
	"github.com/kubescape/go-logger"
	"github.com/kubescape/go-logger/helpers"
)

func (ch *IGContainerWatcher) networkEventCallback(event *tracernetworktypes.Event) {
	if event.Type == types.DEBUG {
		return
	}

	if event.Type != types.NORMAL {
		// dropped event
		logger.L().Ctx(ch.ctx).Warning("network tracer got drop events - we may miss some realtime data", helpers.Interface("event", event), helpers.String("error", event.Message))
		return
	}

	_ = ch.networkWorkerPool.Invoke(*event)
}

func (ch *IGContainerWatcher) startNetworkTracing() error {
	host.Init(host.Config{AutoMountFilesystems: true})

	if err := ch.tracerCollection.AddTracer(networkTraceName, ch.containerSelector); err != nil {
		return fmt.Errorf("adding tracer: %w", err)
	}

	tracerNetwork, err := tracernetwork.NewTracer()
	if err != nil {
		return fmt.Errorf("creating tracer: %w", err)
	}
	tracerNetwork.SetEventHandler(ch.networkEventCallback)

	ch.networkTracer = tracerNetwork

	config := &networktracer.ConnectToContainerCollectionConfig[tracernetworktypes.Event]{
		Tracer:   ch.networkTracer,
		Resolver: ch.containerCollection,
		Selector: ch.containerSelector,
		Base:     tracernetworktypes.Base,
	}

	_, err = networktracer.ConnectToContainerCollection(config)
	if err != nil {
		return fmt.Errorf("creating tracer: %w", err)
	}

	return nil
}

func (ch *IGContainerWatcher) stopNetworkTracing() error {
	// Stop network tracer
	if err := ch.tracerCollection.RemoveTracer(networkTraceName); err != nil {
		return fmt.Errorf("removing tracer: %w", err)
	}

	ch.networkTracer.Close()

	return nil
}
