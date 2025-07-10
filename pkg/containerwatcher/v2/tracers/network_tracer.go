package tracers

import (
	"context"
	"fmt"

	containercollection "github.com/inspektor-gadget/inspektor-gadget/pkg/container-collection"
	"github.com/inspektor-gadget/inspektor-gadget/pkg/container-collection/networktracer"
	tracernetwork "github.com/inspektor-gadget/inspektor-gadget/pkg/gadgets/trace/network/tracer"
	tracernetworktypes "github.com/inspektor-gadget/inspektor-gadget/pkg/gadgets/trace/network/types"
	"github.com/inspektor-gadget/inspektor-gadget/pkg/operators"
	"github.com/inspektor-gadget/inspektor-gadget/pkg/operators/kubeipresolver"
	"github.com/inspektor-gadget/inspektor-gadget/pkg/operators/kubenameresolver"
	"github.com/inspektor-gadget/inspektor-gadget/pkg/socketenricher"
	tracercollection "github.com/inspektor-gadget/inspektor-gadget/pkg/tracer-collection"
	"github.com/inspektor-gadget/inspektor-gadget/pkg/types"
	"github.com/kubescape/go-logger"
	"github.com/kubescape/node-agent/pkg/config"
	"github.com/kubescape/node-agent/pkg/utils"
)

const networkTraceName = "trace_network"

// NetworkTracer implements TracerInterface for network events
type NetworkTracer struct {
	containerCollection *containercollection.ContainerCollection
	tracerCollection    *tracercollection.TracerCollection
	containerSelector   containercollection.ContainerSelector
	eventCallback       func(utils.K8sEvent)
	tracer              *tracernetwork.Tracer
	socketEnricher      *socketenricher.SocketEnricher
	kubeIPInstance      operators.OperatorInstance
	kubeNameInstance    operators.OperatorInstance
}

// NewNetworkTracer creates a new network tracer
func NewNetworkTracer(
	containerCollection *containercollection.ContainerCollection,
	tracerCollection *tracercollection.TracerCollection,
	containerSelector containercollection.ContainerSelector,
	eventCallback func(utils.K8sEvent),
	socketEnricher *socketenricher.SocketEnricher,
) *NetworkTracer {
	return &NetworkTracer{
		containerCollection: containerCollection,
		tracerCollection:    tracerCollection,
		containerSelector:   containerSelector,
		eventCallback:       eventCallback,
		socketEnricher:      socketEnricher,
	}
}

// Start initializes and starts the network tracer
func (nt *NetworkTracer) Start(ctx context.Context) error {
	// Start Kubernetes resolution first
	if err := nt.startKubernetesResolution(); err != nil {
		return fmt.Errorf("starting kubernetes resolution: %w", err)
	}

	if err := nt.tracerCollection.AddTracer(networkTraceName, nt.containerSelector); err != nil {
		return fmt.Errorf("adding network tracer: %w", err)
	}

	tracerNetwork, err := tracernetwork.NewTracer()
	if err != nil {
		return fmt.Errorf("creating network tracer: %w", err)
	}

	if nt.socketEnricher != nil {
		tracerNetwork.SetSocketEnricherMap(nt.socketEnricher.SocketsMap())
	} else {
		logger.L().Error("NetworkTracer - socket enricher is nil")
	}

	tracerNetwork.SetEventHandler(nt.networkEventCallback)

	err = tracerNetwork.RunWorkaround()
	if err != nil {
		return fmt.Errorf("running workaround: %w", err)
	}

	nt.tracer = tracerNetwork

	config := &networktracer.ConnectToContainerCollectionConfig[tracernetworktypes.Event]{
		Tracer:   nt.tracer,
		Resolver: nt.containerCollection,
		Selector: nt.containerSelector,
		Base:     tracernetworktypes.Base,
	}

	_, err = networktracer.ConnectToContainerCollection(config)
	if err != nil {
		return fmt.Errorf("connecting tracer to container collection: %w", err)
	}

	return nil
}

// Stop gracefully stops the network tracer
func (nt *NetworkTracer) Stop() error {
	if nt.tracer != nil {
		nt.tracer.Close()
	}

	if err := nt.tracerCollection.RemoveTracer(networkTraceName); err != nil {
		return fmt.Errorf("removing network tracer: %w", err)
	}

	return nil
}

// GetName returns the unique name of the tracer
func (nt *NetworkTracer) GetName() string {
	return "network_tracer"
}

// GetEventType returns the event type this tracer produces
func (nt *NetworkTracer) GetEventType() utils.EventType {
	return utils.NetworkEventType
}

// IsEnabled checks if this tracer should be enabled based on configuration
func (nt *NetworkTracer) IsEnabled(cfg interface{}) bool {
	if config, ok := cfg.(config.Config); ok {
		return config.EnableNetworkTracing || config.EnableRuntimeDetection
	}
	return false
}

// networkEventCallback handles network events from the tracer
func (nt *NetworkTracer) networkEventCallback(event *tracernetworktypes.Event) {
	if event.Type == types.DEBUG {
		return
	}

	// do not skip dropped events as their processing is done in the worker

	nt.containerCollection.EnrichByMntNs(&event.CommonData, event.MountNsID)
	nt.containerCollection.EnrichByNetNs(&event.CommonData, event.NetNsID)

	if nt.kubeIPInstance != nil {
		_ = nt.kubeIPInstance.EnrichEvent(event)
	}
	if nt.kubeNameInstance != nil {
		_ = nt.kubeNameInstance.EnrichEvent(event)
	}

	if nt.eventCallback != nil {
		nt.eventCallback(event)
	}
}

// startKubernetesResolution starts the kubeIP and kube name resolution
func (nt *NetworkTracer) startKubernetesResolution() error {
	kubeIPOp := operators.GetRaw(kubeipresolver.OperatorName).(*kubeipresolver.KubeIPResolver)
	_ = kubeIPOp.Init(nil)

	kubeIPInstance, err := kubeIPOp.Instantiate(nil, nil, nil)
	if err != nil {
		return fmt.Errorf("creating kube ip resolver: %w", err)
	}

	nt.kubeIPInstance = kubeIPInstance
	_ = nt.kubeIPInstance.PreGadgetRun()

	kubeNameOp := operators.GetRaw(kubenameresolver.OperatorName).(*kubenameresolver.KubeNameResolver)
	_ = kubeNameOp.Init(nil)
	kubeNameInstance, err := kubeNameOp.Instantiate(nil, nil, nil)
	if err != nil {
		return fmt.Errorf("creating kube name resolver: %w", err)
	}

	nt.kubeNameInstance = kubeNameInstance
	_ = nt.kubeNameInstance.PreGadgetRun()

	return nil
}
