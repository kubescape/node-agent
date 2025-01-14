package containerwatcher

import (
	"fmt"

	"github.com/inspektor-gadget/inspektor-gadget/pkg/container-collection/networktracer"
	tracernetwork "github.com/inspektor-gadget/inspektor-gadget/pkg/gadgets/trace/network/tracer"
	tracernetworktypes "github.com/inspektor-gadget/inspektor-gadget/pkg/gadgets/trace/network/types"
	"github.com/inspektor-gadget/inspektor-gadget/pkg/operators"
	"github.com/inspektor-gadget/inspektor-gadget/pkg/operators/kubeipresolver"
	"github.com/inspektor-gadget/inspektor-gadget/pkg/operators/kubenameresolver"
	"github.com/inspektor-gadget/inspektor-gadget/pkg/types"
	"github.com/kubescape/go-logger"
)

func (ch *IGContainerWatcher) networkEventCallback(event *tracernetworktypes.Event) {
	if event.Type == types.DEBUG {
		return
	}

	// do not skip dropped events as their processing is done in the worker

	ch.containerCollection.EnrichByMntNs(&event.CommonData, event.MountNsID)
	ch.containerCollection.EnrichByNetNs(&event.CommonData, event.NetNsID)

	if ch.kubeIPInstance != nil {
		_ = ch.kubeIPInstance.EnrichEvent(event)
	}
	if ch.kubeNameInstance != nil {
		_ = ch.kubeNameInstance.EnrichEvent(event)
	}

	ch.networkWorkerChan <- event
}

func (ch *IGContainerWatcher) startNetworkTracing() error {
	if err := ch.tracerCollection.AddTracer(networkTraceName, ch.containerSelector); err != nil {
		return fmt.Errorf("adding tracer: %w", err)
	}

	tracerNetwork, err := tracernetwork.NewTracer()
	if err != nil {
		return fmt.Errorf("creating tracer: %w", err)
	}
	go func() {
		for event := range ch.networkWorkerChan {
			_ = ch.networkWorkerPool.Invoke(*event)
		}
	}()

	if ch.socketEnricher != nil {
		tracerNetwork.SetSocketEnricherMap(ch.socketEnricher.SocketsMap())
	} else {
		logger.L().Error("IGContainerWatcher - socket enricher is nil")
	}

	tracerNetwork.SetEventHandler(ch.networkEventCallback)

	err = tracerNetwork.RunWorkaround()
	if err != nil {
		return fmt.Errorf("running workaround: %w", err)
	}

	ch.networkTracer = tracerNetwork

	config := &networktracer.ConnectToContainerCollectionConfig[tracernetworktypes.Event]{
		Tracer:   ch.networkTracer,
		Resolver: ch.containerCollection,
		Selector: ch.containerSelector,
		Base:     tracernetworktypes.Base,
	}

	_, err = networktracer.ConnectToContainerCollection(config)
	if err != nil {
		return fmt.Errorf("connecting tracer to container collection: %w", err)
	}

	return nil
}

// startKubernetesResolution starts the kubeIP and kube name resolution, which are used to enrich network communication data
func (ch *IGContainerWatcher) startKubernetesResolution() error {
	kubeIPOp := operators.GetRaw(kubeipresolver.OperatorName).(*kubeipresolver.KubeIPResolver)
	_ = kubeIPOp.Init(nil)

	kubeIPInstance, err := kubeIPOp.Instantiate(nil, nil, nil)
	if err != nil {
		return fmt.Errorf("creating kube ip resolver: %w", err)
	}

	ch.kubeIPInstance = kubeIPInstance
	_ = ch.kubeIPInstance.PreGadgetRun()

	kubeNameOp := operators.GetRaw(kubenameresolver.OperatorName).(*kubenameresolver.KubeNameResolver)
	_ = kubeNameOp.Init(nil)
	kubeNameInstance, err := kubeNameOp.Instantiate(nil, nil, nil)
	if err != nil {
		return fmt.Errorf("creating kube name resolver: %w", err)
	}

	ch.kubeNameInstance = kubeNameInstance
	_ = ch.kubeNameInstance.PreGadgetRun()

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
