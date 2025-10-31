package tracers

import (
	"context"

	mapset "github.com/deckarep/golang-set/v2"
	containercollection "github.com/inspektor-gadget/inspektor-gadget/pkg/container-collection"
	_ "github.com/inspektor-gadget/inspektor-gadget/pkg/operators/ebpf"
	"github.com/inspektor-gadget/inspektor-gadget/pkg/operators/kubeipresolver"
	"github.com/inspektor-gadget/inspektor-gadget/pkg/operators/kubenameresolver"
	"github.com/inspektor-gadget/inspektor-gadget/pkg/operators/socketenricher"
	"github.com/inspektor-gadget/inspektor-gadget/pkg/runtime"
	tracercollection "github.com/inspektor-gadget/inspektor-gadget/pkg/tracer-collection"
	"github.com/kubescape/go-logger"
	"github.com/kubescape/go-logger/helpers"
	"github.com/kubescape/node-agent/pkg/config"
	"github.com/kubescape/node-agent/pkg/containerprofilemanager"
	"github.com/kubescape/node-agent/pkg/containerwatcher"
	"github.com/kubescape/node-agent/pkg/kskubemanager"
	"github.com/kubescape/node-agent/pkg/processtree"
	"github.com/kubescape/node-agent/pkg/rulemanager"
	"github.com/kubescape/node-agent/pkg/utils"
	orasoci "oras.land/oras-go/v2/content/oci"
)

const opPriority = 50000

// EventQueueInterface defines the interface for adding events to the queue
type EventQueueInterface interface {
	AddEventDirect(eventType utils.EventType, event utils.K8sEvent, containerID string, processID uint32)
}

// TracerFactory manages the creation and configuration of all tracers
type TracerFactory struct {
	cfg                     config.Config
	containerCollection     *containercollection.ContainerCollection
	containerProfileManager containerprofilemanager.ContainerProfileManagerClient
	containerSelector       containercollection.ContainerSelector
	kubeIPResolver          *kubeipresolver.KubeIPResolver
	kubeManager             *kskubemanager.KubeManager
	kubeNameResolver        *kubenameresolver.KubeNameResolver
	ociStore                *orasoci.ReadOnlyStore
	orderedEventQueue       EventQueueInterface
	processTreeManager      processtree.ProcessTreeManager
	ruleManager             rulemanager.RuleManagerClient
	runtime                 runtime.Runtime
	socketEnricher          *socketenricher.SocketEnricher
	thirdPartyEnricher      containerwatcher.TaskBasedEnricher
	thirdPartyTracersInit   mapset.Set[containerwatcher.CustomTracerInitializer]
	tracerCollection        *tracercollection.TracerCollection
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
	thirdPartyTracers mapset.Set[containerwatcher.CustomTracerInitializer],
	thirdPartyEnricher containerwatcher.TaskBasedEnricher,
	cfg config.Config,
	processTreeManager processtree.ProcessTreeManager,
	runtime runtime.Runtime,
) *TracerFactory {
	ociStore, err := orasoci.NewFromTar(context.Background(), "tracers.tar")
	if err != nil {
		logger.L().Fatal("getting oci store from tarball", helpers.Error(err))
	}
	return &TracerFactory{
		cfg:                     cfg,
		containerCollection:     containerCollection,
		containerProfileManager: containerProfileManager,
		containerSelector:       containerSelector,
		kubeIPResolver:          &kubeipresolver.KubeIPResolver{},
		kubeManager:             kskubemanager.NewKsKubeManager(containerCollection, tracerCollection),
		kubeNameResolver:        &kubenameresolver.KubeNameResolver{},
		ociStore:                ociStore,
		orderedEventQueue:       orderedEventQueue,
		processTreeManager:      processTreeManager,
		ruleManager:             ruleManager,
		runtime:                 runtime,
		socketEnricher:          socketEnricher,
		thirdPartyEnricher:      thirdPartyEnricher,
		thirdPartyTracersInit:   thirdPartyTracers,
		tracerCollection:        tracerCollection,
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

	// Create syscall tracer (seccomp)
	syscallTracer := NewSyscallTracer(
		tf.kubeManager,
		tf.runtime,
		tf.ociStore,
		tf.createEventCallback(utils.SyscallEventType),
	)
	manager.RegisterTracer(syscallTracer)

	// Create exec tracer
	execTracer := NewExecTracer(
		tf.kubeManager,
		tf.runtime,
		tf.ociStore,
		tf.createEventCallback(utils.ExecveEventType),
		tf.thirdPartyEnricher,
	)
	manager.RegisterTracer(execTracer)

	// Create exit tracer
	exitTracer := NewExitTracer(
		tf.kubeManager,
		tf.runtime,
		tf.ociStore,
		tf.createEventCallback(utils.ExitEventType),
	)
	manager.RegisterTracer(exitTracer)

	// Create fork tracer
	forkTracer := NewForkTracer(
		tf.kubeManager,
		tf.runtime,
		tf.ociStore,
		tf.createEventCallback(utils.ForkEventType),
	)
	manager.RegisterTracer(forkTracer)

	// Create open tracer
	openTracer := NewOpenTracer(
		tf.kubeManager,
		tf.runtime,
		tf.ociStore,
		tf.createEventCallback(utils.OpenEventType),
		tf.thirdPartyEnricher,
	)
	manager.RegisterTracer(openTracer)

	// Create capabilities tracer
	capabilitiesTracer := NewCapabilitiesTracer(
		tf.kubeManager,
		tf.runtime,
		tf.ociStore,
		tf.createEventCallback(utils.CapabilitiesEventType),
		tf.thirdPartyEnricher,
	)
	manager.RegisterTracer(capabilitiesTracer)

	// Create symlink tracer
	symlinkTracer := NewSymlinkTracer(
		tf.kubeManager,
		tf.runtime,
		tf.ociStore,
		tf.createEventCallback(utils.SymlinkEventType),
		tf.thirdPartyEnricher,
	)
	manager.RegisterTracer(symlinkTracer)

	// Create kmod tracer
	kmodTracer := NewKmodTracer(
		tf.kubeManager,
		tf.runtime,
		tf.ociStore,
		tf.createEventCallback(utils.KmodEventType),
		tf.thirdPartyEnricher,
	)
	manager.RegisterTracer(kmodTracer)

	// Create hardlink tracer
	hardlinkTracer := NewHardlinkTracer(
		tf.kubeManager,
		tf.runtime,
		tf.ociStore,
		tf.createEventCallback(utils.HardlinkEventType),
		tf.thirdPartyEnricher,
	)
	manager.RegisterTracer(hardlinkTracer)

	// Create SSH tracer
	sshTracer := NewSSHTracer(
		tf.kubeManager,
		tf.runtime,
		tf.ociStore,
		tf.createEventCallback(utils.SSHEventType),
		tf.socketEnricher,
	)
	manager.RegisterTracer(sshTracer)

	// Create HTTP tracer
	httpTracer := NewHTTPTracer(
		tf.kubeManager,
		tf.runtime,
		tf.ociStore,
		tf.createEventCallback(utils.HTTPEventType),
	)
	manager.RegisterTracer(httpTracer)

	// Create network tracer
	networkTracer := NewNetworkTracer(
		tf.kubeIPResolver,
		tf.kubeManager,
		tf.kubeNameResolver,
		tf.runtime,
		tf.ociStore,
		tf.createEventCallback(utils.NetworkEventType),
		tf.thirdPartyEnricher,
		tf.socketEnricher,
	)
	manager.RegisterTracer(networkTracer)

	// Create DNS tracer
	dnsTracer := NewDNSTracer(
		tf.kubeManager,
		tf.runtime,
		tf.ociStore,
		tf.createEventCallback(utils.DnsEventType),
		tf.thirdPartyEnricher,
		tf.socketEnricher,
	)
	manager.RegisterTracer(dnsTracer)

	// Create randomX tracer
	randomXTracer := NewRandomXTracer(
		tf.kubeManager,
		tf.runtime,
		tf.ociStore,
		tf.createEventCallback(utils.RandomXEventType),
	)
	manager.RegisterTracer(randomXTracer)

	// Create ptrace tracer
	ptraceTracer := NewPtraceTracer(
		tf.kubeManager,
		tf.runtime,
		tf.ociStore,
		tf.createEventCallback(utils.PtraceEventType),
	)
	manager.RegisterTracer(ptraceTracer)

	// Create io_uring tracer
	iouringTracer := NewIoUringTracer(
		tf.kubeManager,
		tf.runtime,
		tf.ociStore,
		tf.createEventCallback(utils.IoUringEventType),
	)
	manager.RegisterTracer(iouringTracer)

	// Create unshare tracer
	unshareTracer := NewUnshareTracer(
		tf.kubeManager,
		tf.runtime,
		tf.ociStore,
		tf.createEventCallback(utils.UnshareEventType),
		tf.thirdPartyEnricher,
	)
	manager.RegisterTracer(unshareTracer)

	// Create bpf tracer
	bpfTracer := NewBpfTracer(
		tf.kubeManager,
		tf.runtime,
		tf.ociStore,
		tf.createEventCallback(utils.BpfEventType),
		tf.thirdPartyEnricher,
	)
	manager.RegisterTracer(bpfTracer)

	// Create top tracer
	//topTracer := NewTopTracer(
	//	tf.containerCollection,
	//	tf.tracerCollection,
	//	tf.containerSelector,
	//	tf.createEventCallback(utils.AllEventType),
	//)
	//manager.RegisterTracer(topTracer)

	// Create third-party tracers
	for tracerInit := range tf.thirdPartyTracersInit.Iter() {
		tracer, err := tracerInit.NewTracer(tf.containerCollection, tf.tracerCollection, tf.containerSelector, tf.createEventCallback(utils.AllEventType), tf.thirdPartyEnricher)
		if err != nil {
			logger.L().Error("error creating third-party tracer", helpers.Error(err))
			continue
		}

		manager.RegisterTracer(tracer)
	}

}

// createEventCallback creates a simple callback that sends events directly to the ordered event queue
func (tf *TracerFactory) createEventCallback(eventType utils.EventType) containerwatcher.ResultCallback {
	return func(event utils.K8sEvent, containerID string, processID uint32) {
		tf.orderedEventQueue.AddEventDirect(eventType, event, containerID, processID)
	}
}
