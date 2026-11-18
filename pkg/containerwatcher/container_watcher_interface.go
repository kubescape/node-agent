package containerwatcher

import (
	"context"
	"errors"
	"time"

	mapset "github.com/deckarep/golang-set/v2"
	"github.com/goradd/maps"
	containercollection "github.com/inspektor-gadget/inspektor-gadget/pkg/container-collection"
	"github.com/inspektor-gadget/inspektor-gadget/pkg/operators"
	"github.com/inspektor-gadget/inspektor-gadget/pkg/operators/socketenricher"
	"github.com/inspektor-gadget/inspektor-gadget/pkg/runtime"
	tracercollection "github.com/inspektor-gadget/inspektor-gadget/pkg/tracer-collection"
	"github.com/kubescape/node-agent/pkg/ebpf/events"
	"github.com/kubescape/node-agent/pkg/utils"
	orasoci "oras.land/oras-go/v2/content/oci"
)

type ResultCallback func(utils.K8sEvent, string, uint32)

// ErrContainerCollection wraps a Start failure of the container collection
// itself (no container discovery; an OnCollectionReady hook never ran).
var ErrContainerCollection = errors.New("starting container collection")

type ContainerWatcher interface {
	Ready() bool
	Start(ctx context.Context) error
	Stop()
	// OnCollectionReady registers a hook Start runs once the container
	// collection is initialized, before any eBPF tracer starts. Start and the
	// eBPF tracers wait at most maxTracerDelay for it; the returned channel is
	// closed once it returned (or will never run).
	OnCollectionReady(fn func(), maxTracerDelay time.Duration) <-chan struct{}
	GetTracerCollection() *tracercollection.TracerCollection
	GetContainerCollection() *containercollection.ContainerCollection
	GetSocketEnricher() *socketenricher.SocketEnricher
	GetContainerSelector() *containercollection.ContainerSelector
	RegisterContainerReceiver(receiver ContainerReceiver)
	UnregisterContainerReceiver(receiver ContainerReceiver)
}

type CustomTracerInitializer interface {
	NewTracer(
		kubeManager operators.DataOperator,
		runtime runtime.Runtime,
		ociStore *orasoci.ReadOnlyStore,
		eventCallback ResultCallback,
		thirdPartyEnricher TaskBasedEnricher,
	) (TracerInterface, error)
}

type GenericEventReceiver any

type EventReceiver interface {
	ReportEvent(eventType utils.EventType, event utils.K8sEvent)
}

type EnrichedEventReceiver interface {
	ReportEnrichedEvent(enrichedEvent *events.EnrichedEvent)
}

type ContainerReceiver interface {
	ContainerCallback(notif containercollection.PubSubEvent)
}

type TaskBasedEnricher interface {
	SubmitEnrichmentTask(event utils.EnrichEvent, syscalls []uint64, callback ResultCallback, containerID string, processID uint32)
}

type ThirdPartyTracers struct {
	ThirdPartyTracersInitializers mapset.Set[CustomTracerInitializer]
	ThirdPartyEventReceivers      *maps.SafeMap[utils.EventType, mapset.Set[GenericEventReceiver]] // TODO: either EventReceiver or EnrichedEventReceiver
}
