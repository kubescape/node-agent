package tracers

import (
	mapset "github.com/deckarep/golang-set/v2"
	containercollection "github.com/inspektor-gadget/inspektor-gadget/pkg/container-collection"
	"github.com/inspektor-gadget/inspektor-gadget/pkg/socketenricher"
	tracercollection "github.com/inspektor-gadget/inspektor-gadget/pkg/tracer-collection"
	"github.com/kubescape/node-agent/pkg/config"
	"github.com/kubescape/node-agent/pkg/containerprofilemanager"
	"github.com/kubescape/node-agent/pkg/containerwatcher"
	"github.com/kubescape/node-agent/pkg/processtree"
	"github.com/kubescape/node-agent/pkg/rulemanager"
	"github.com/kubescape/node-agent/pkg/utils"
)

// EventQueueInterface defines the interface for adding events to the queue
type EventQueueInterface interface {
	AddEventDirect(eventType utils.EventType, event utils.K8sEvent, containerID string, processID uint32)
}

// TracerFactory manages the creation and configuration of all tracers
type TracerFactory struct {
	containerCollection     *containercollection.ContainerCollection
	tracerCollection        *tracercollection.TracerCollection
	containerSelector       containercollection.ContainerSelector
	orderedEventQueue       EventQueueInterface
	socketEnricher          *socketenricher.SocketEnricher
	containerProfileManager containerprofilemanager.ContainerProfileManagerClient
	ruleManager             rulemanager.RuleManagerClient
	thirdPartyTracers       mapset.Set[containerwatcher.CustomTracer]
	thirdPartyEnricher      containerwatcher.TaskBasedEnricher
	cfg                     config.Config
	processTreeManager      processtree.ProcessTreeManager
}

// NewTracerFactory creates a new tracer factory
func NewTracerFactory(
	containerCollection *containercollection.ContainerCollection,
	tracerCollection *tracercollection.TracerCollection,
	containerSelector containercollection.ContainerSelector,
	orderedEventQueue EventQueueInterface,
	socketEnricher *socketenricher.SocketEnricher,
	containerProfileManager containerprofilemanager.ContainerProfileManagerClient,
	ruleManager rulemanager.RuleManagerClient,
	thirdPartyTracers mapset.Set[containerwatcher.CustomTracer],
	thirdPartyEnricher containerwatcher.TaskBasedEnricher,
	cfg config.Config,
	processTreeManager processtree.ProcessTreeManager,
) *TracerFactory {
	return &TracerFactory{
		containerCollection:     containerCollection,
		tracerCollection:        tracerCollection,
		containerSelector:       containerSelector,
		orderedEventQueue:       orderedEventQueue,
		socketEnricher:          socketEnricher,
		containerProfileManager: containerProfileManager,
		ruleManager:             ruleManager,
		thirdPartyTracers:       thirdPartyTracers,
		thirdPartyEnricher:      thirdPartyEnricher,
		cfg:                     cfg,
		processTreeManager:      processTreeManager,
	}
}

// CreateAllTracers creates all configured tracers
func (tf *TracerFactory) CreateAllTracers(manager containerwatcher.TracerRegistrer) {
	// Create procfs tracer (starts 5 seconds before other tracers)
	procfsTracer := NewProcfsTracer(
		tf.containerCollection,
		tf.tracerCollection,
		tf.containerSelector,
		tf.createEventCallback(utils.ProcfsEventType),
		tf.createEventCallback(utils.ExitEventType),
		tf.cfg,
		tf.processTreeManager,
	)
	manager.RegisterTracer(procfsTracer)

	// Create syscall tracer (seccomp) - handles its own peek function registration
	syscallTracer := NewSyscallTracer(tf.containerProfileManager, tf.ruleManager)
	manager.RegisterTracer(syscallTracer)

	// Create exec tracer
	execTracer := NewExecTracer(
		tf.containerCollection,
		tf.tracerCollection,
		tf.containerSelector,
		tf.createEventCallback(utils.ExecveEventType),
		tf.thirdPartyEnricher,
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
		tf.thirdPartyEnricher,
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
		tf.thirdPartyEnricher,
	)
	manager.RegisterTracer(symlinkTracer)

	// Create hardlink tracer
	hardlinkTracer := NewHardlinkTracer(
		tf.containerCollection,
		tf.tracerCollection,
		tf.containerSelector,
		tf.createEventCallback(utils.HardlinkEventType),
		tf.thirdPartyEnricher,
	)
	manager.RegisterTracer(hardlinkTracer)

	// Create SSH tracer
	sshTracer := NewSSHTracer(
		tf.containerCollection,
		tf.tracerCollection,
		tf.containerSelector,
		tf.createEventCallback(utils.SSHEventType),
		tf.socketEnricher,
	)
	manager.RegisterTracer(sshTracer)

	// Create HTTP tracer
	httpTracer := NewHTTPTracer(
		tf.containerCollection,
		tf.tracerCollection,
		tf.containerSelector,
		tf.createEventCallback(utils.HTTPEventType),
	)
	manager.RegisterTracer(httpTracer)

	// Create network tracer
	networkTracer := NewNetworkTracer(
		tf.containerCollection,
		tf.tracerCollection,
		tf.containerSelector,
		tf.createEventCallback(utils.NetworkEventType),
		tf.socketEnricher,
	)
	manager.RegisterTracer(networkTracer)

	// Create DNS tracer
	dnsTracer := NewDNSTracer(
		tf.containerCollection,
		tf.tracerCollection,
		tf.containerSelector,
		tf.createEventCallback(utils.DnsEventType),
		tf.socketEnricher,
	)
	manager.RegisterTracer(dnsTracer)

	// Create randomX tracer
	randomXTracer := NewRandomXTracer(
		tf.containerCollection,
		tf.tracerCollection,
		tf.containerSelector,
		tf.createEventCallback(utils.RandomXEventType),
	)
	manager.RegisterTracer(randomXTracer)

	// Create ptrace tracer
	ptraceTracer := NewPtraceTracer(
		tf.containerCollection,
		tf.tracerCollection,
		tf.containerSelector,
		tf.createEventCallback(utils.PtraceEventType),
	)
	manager.RegisterTracer(ptraceTracer)

	// Create io_uring tracer
	iouringTracer := NewIoUringTracer(
		tf.containerCollection,
		tf.tracerCollection,
		tf.containerSelector,
		tf.createEventCallback(utils.IoUringEventType),
	)
	manager.RegisterTracer(iouringTracer)

	// Create top tracer
	topTracer := NewTopTracer(
		tf.containerCollection,
		tf.tracerCollection,
		tf.containerSelector,
		tf.createEventCallback(utils.AllEventType),
	)
	manager.RegisterTracer(topTracer)
}

// GetThirdPartyTracers returns all registered third-party tracers
func (tf *TracerFactory) GetThirdPartyTracers() []containerwatcher.CustomTracer {
	tracers := make([]containerwatcher.CustomTracer, 0, tf.thirdPartyTracers.Cardinality())
	for tracer := range tf.thirdPartyTracers.Iter() {
		tracers = append(tracers, tracer)
	}
	return tracers
}

// createEventCallback creates a simple callback that sends events directly to the ordered event queue
func (tf *TracerFactory) createEventCallback(eventType utils.EventType) func(utils.K8sEvent, string, uint32) {
	return func(event utils.K8sEvent, containerID string, processID uint32) {
		tf.orderedEventQueue.AddEventDirect(eventType, event, containerID, processID)
	}
}
