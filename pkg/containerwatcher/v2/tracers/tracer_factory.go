package tracers

import (
	"context"
	"fmt"

	mapset "github.com/deckarep/golang-set/v2"
	containercollection "github.com/inspektor-gadget/inspektor-gadget/pkg/container-collection"
	"github.com/inspektor-gadget/inspektor-gadget/pkg/socketenricher"
	tracercollection "github.com/inspektor-gadget/inspektor-gadget/pkg/tracer-collection"
	"github.com/kubescape/go-logger"
	"github.com/kubescape/go-logger/helpers"
	"github.com/kubescape/node-agent/pkg/applicationprofilemanager"
	"github.com/kubescape/node-agent/pkg/containerwatcher"
	"github.com/kubescape/node-agent/pkg/rulemanager"
	"github.com/kubescape/node-agent/pkg/utils"
)

// EventQueueInterface defines the interface for adding events to the queue
type EventQueueInterface interface {
	AddEventDirect(eventType utils.EventType, event utils.K8sEvent, containerID string, processID uint32)
}

// TracerFactory creates and manages all tracer instances
type TracerFactory struct {
	containerCollection       *containercollection.ContainerCollection
	tracerCollection          *tracercollection.TracerCollection
	containerSelector         containercollection.ContainerSelector
	orderedEventQueue         EventQueueInterface
	socketEnricher            *socketenricher.SocketEnricher
	applicationProfileManager applicationprofilemanager.ApplicationProfileManagerClient
	ruleManager               rulemanager.RuleManagerClient
	thirdPartyTracers         mapset.Set[containerwatcher.CustomTracer]
}

// NewTracerFactory creates a new tracer factory
func NewTracerFactory(
	containerCollection *containercollection.ContainerCollection,
	tracerCollection *tracercollection.TracerCollection,
	containerSelector containercollection.ContainerSelector,
	orderedEventQueue EventQueueInterface,
	socketEnricher *socketenricher.SocketEnricher,
	applicationProfileManager applicationprofilemanager.ApplicationProfileManagerClient,
	ruleManager rulemanager.RuleManagerClient,
	thirdPartyTracers mapset.Set[containerwatcher.CustomTracer],
) *TracerFactory {
	return &TracerFactory{
		containerCollection:       containerCollection,
		tracerCollection:          tracerCollection,
		containerSelector:         containerSelector,
		orderedEventQueue:         orderedEventQueue,
		socketEnricher:            socketEnricher,
		applicationProfileManager: applicationProfileManager,
		ruleManager:               ruleManager,
		thirdPartyTracers:         thirdPartyTracers,
	}
}

// CreateAllTracers creates all available tracers and registers them with the manager
func (tf *TracerFactory) CreateAllTracers(manager *containerwatcher.TracerManager) {
	// Create syscall tracer (seccomp)
	syscallTracer := NewSyscallTracer()
	manager.RegisterTracer(syscallTracer)

	// Register syscall tracer peek functions with managers
	tf.registerSyscallTracerPeekFunctions(syscallTracer)

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

// StartThirdPartyTracers starts all registered third-party tracers
func (tf *TracerFactory) StartThirdPartyTracers(ctx context.Context) error {
	for tracer := range tf.thirdPartyTracers.Iter() {
		if err := tracer.Start(); err != nil {
			logger.L().Error("error starting custom tracer", helpers.String("tracer", tracer.Name()), helpers.Error(err))
			return fmt.Errorf("starting custom tracer %s: %w", tracer.Name(), err)
		}
		logger.L().Info("started custom tracer", helpers.String("tracer", tracer.Name()))
	}
	return nil
}

// StopThirdPartyTracers stops all registered third-party tracers
func (tf *TracerFactory) StopThirdPartyTracers() {
	for tracer := range tf.thirdPartyTracers.Iter() {
		if err := tracer.Stop(); err != nil {
			logger.L().Error("error stopping custom tracer", helpers.String("tracer", tracer.Name()), helpers.Error(err))
		}
	}
}

// createEventCallback creates a simple callback that sends events directly to the ordered event queue
func (tf *TracerFactory) createEventCallback(eventType utils.EventType) func(utils.K8sEvent, string, uint32) {
	return func(event utils.K8sEvent, containerID string, processID uint32) {
		tf.orderedEventQueue.AddEventDirect(eventType, event, containerID, processID)
	}
}

// registerSyscallTracerPeekFunctions registers the syscall tracer peek functions with the managers
func (tf *TracerFactory) registerSyscallTracerPeekFunctions(syscallTracer *SyscallTracer) {
	if tf.applicationProfileManager != nil {
		tf.applicationProfileManager.RegisterPeekFunc(syscallTracer.Peek)
	}
	if tf.ruleManager != nil {
		tf.ruleManager.RegisterPeekFunc(syscallTracer.Peek)
	}
}
