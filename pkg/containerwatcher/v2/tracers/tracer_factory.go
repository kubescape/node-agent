package tracers

import (
	containercollection "github.com/inspektor-gadget/inspektor-gadget/pkg/container-collection"
	"github.com/inspektor-gadget/inspektor-gadget/pkg/socketenricher"
	tracercollection "github.com/inspektor-gadget/inspektor-gadget/pkg/tracer-collection"
	"github.com/kubescape/node-agent/pkg/containerwatcher"
	containerwatcherv2 "github.com/kubescape/node-agent/pkg/containerwatcher/v2"
	"github.com/kubescape/node-agent/pkg/utils"
)

// TracerFactory creates and manages all tracer instances
type TracerFactory struct {
	containerCollection *containercollection.ContainerCollection
	tracerCollection    *tracercollection.TracerCollection
	containerSelector   containercollection.ContainerSelector
	orderedEventQueue   *containerwatcherv2.OrderedEventQueue
	socketEnricher      *socketenricher.SocketEnricher
}

// NewTracerFactory creates a new tracer factory
func NewTracerFactory(
	containerCollection *containercollection.ContainerCollection,
	tracerCollection *tracercollection.TracerCollection,
	containerSelector containercollection.ContainerSelector,
	orderedEventQueue *containerwatcherv2.OrderedEventQueue,
	socketEnricher *socketenricher.SocketEnricher,
) *TracerFactory {
	return &TracerFactory{
		containerCollection: containerCollection,
		tracerCollection:    tracerCollection,
		containerSelector:   containerSelector,
		orderedEventQueue:   orderedEventQueue,
		socketEnricher:      socketEnricher,
	}
}

// CreateAllTracers creates all available tracers and registers them with the manager
func (tf *TracerFactory) CreateAllTracers(manager *containerwatcher.TracerManager) {
	// Create exec tracer
	execTracer := NewExecTracer(
		tf.containerCollection,
		tf.tracerCollection,
		tf.containerSelector,
		tf.createEventCallback(utils.ExecveEventType),
	)
	manager.RegisterTracer(execTracer)

	// Create exit tracer
	exitTracer := NewExitTracer(
		tf.containerCollection,
		tf.tracerCollection,
		tf.containerSelector,
		tf.createEventCallback(utils.ExitEventType),
	)
	manager.RegisterTracer(exitTracer)

	// Create fork tracer
	forkTracer := NewForkTracer(
		tf.containerCollection,
		tf.tracerCollection,
		tf.containerSelector,
		tf.createEventCallback(utils.ForkEventType),
	)
	manager.RegisterTracer(forkTracer)

	// Create open tracer
	openTracer := NewOpenTracer(
		tf.containerCollection,
		tf.tracerCollection,
		tf.containerSelector,
		tf.createEventCallback(utils.OpenEventType),
	)
	manager.RegisterTracer(openTracer)

	// Create capabilities tracer
	capabilitiesTracer := NewCapabilitiesTracer(
		tf.containerCollection,
		tf.tracerCollection,
		tf.containerSelector,
		tf.createEventCallback(utils.CapabilitiesEventType),
	)
	manager.RegisterTracer(capabilitiesTracer)

	// Create symlink tracer
	symlinkTracer := NewSymlinkTracer(
		tf.containerCollection,
		tf.tracerCollection,
		tf.containerSelector,
		tf.createEventCallback(utils.SymlinkEventType),
	)
	manager.RegisterTracer(symlinkTracer)

	// Create hardlink tracer
	hardlinkTracer := NewHardlinkTracer(
		tf.containerCollection,
		tf.tracerCollection,
		tf.containerSelector,
		tf.createEventCallback(utils.HardlinkEventType),
	)
	manager.RegisterTracer(hardlinkTracer)

	// Create network tracer (requires socket enricher)
	if tf.socketEnricher != nil {
		networkTracer := NewNetworkTracer(
			tf.containerCollection,
			tf.tracerCollection,
			tf.containerSelector,
			tf.createEventCallback(utils.NetworkEventType),
			tf.socketEnricher,
		)
		manager.RegisterTracer(networkTracer)

		// Create DNS tracer (requires socket enricher)
		dnsTracer := NewDNSTracer(
			tf.containerCollection,
			tf.tracerCollection,
			tf.containerSelector,
			tf.createEventCallback(utils.DnsEventType),
			tf.socketEnricher,
		)
		manager.RegisterTracer(dnsTracer)

		// Create SSH tracer (requires socket enricher)
		sshTracer := NewSSHTracer(
			tf.containerCollection,
			tf.tracerCollection,
			tf.containerSelector,
			tf.createEventCallback(utils.SSHEventType),
			tf.socketEnricher,
		)
		manager.RegisterTracer(sshTracer)
	}

	// Create HTTP tracer
	httpTracer := NewHTTPTracer(
		tf.containerCollection,
		tf.tracerCollection,
		tf.containerSelector,
		tf.createEventCallback(utils.HTTPEventType),
	)
	manager.RegisterTracer(httpTracer)

	// Create ptrace tracer
	ptraceTracer := NewPtraceTracer(
		tf.containerCollection,
		tf.tracerCollection,
		tf.containerSelector,
		tf.createEventCallback(utils.PtraceEventType),
	)
	manager.RegisterTracer(ptraceTracer)

	// Create iouring tracer
	iouringTracer := NewIoUringTracer(
		tf.containerCollection,
		tf.tracerCollection,
		tf.containerSelector,
		tf.createEventCallback(utils.IoUringEventType),
	)
	manager.RegisterTracer(iouringTracer)

	// Create randomx tracer
	randomxTracer := NewRandomXTracer(
		tf.containerCollection,
		tf.tracerCollection,
		tf.containerSelector,
		tf.createEventCallback(utils.RandomXEventType),
	)
	manager.RegisterTracer(randomxTracer)

	// Create top tracer
	topTracer := NewTopTracer(
		tf.containerCollection,
		tf.tracerCollection,
		tf.containerSelector,
		tf.createEventCallback(utils.AllEventType),
	)
	manager.RegisterTracer(topTracer)
}

// createEventCallback creates a simple callback that sends events directly to the ordered event queue
func (tf *TracerFactory) createEventCallback(eventType utils.EventType) func(utils.K8sEvent) {
	return func(event utils.K8sEvent) {
		tf.orderedEventQueue.AddEventDirect(eventType, event)
	}
}
