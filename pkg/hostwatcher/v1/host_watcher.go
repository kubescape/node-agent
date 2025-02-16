package hostwatcher

import (
	"context"
	"fmt"
	"os"
	"time"

	containercollection "github.com/inspektor-gadget/inspektor-gadget/pkg/container-collection"
	containerutils "github.com/inspektor-gadget/inspektor-gadget/pkg/container-utils"
	containerutilsTypes "github.com/inspektor-gadget/inspektor-gadget/pkg/container-utils/types"
	tracerexec "github.com/inspektor-gadget/inspektor-gadget/pkg/gadgets/trace/exec/tracer"
	traceropen "github.com/inspektor-gadget/inspektor-gadget/pkg/gadgets/trace/open/tracer"
	tracercollection "github.com/inspektor-gadget/inspektor-gadget/pkg/tracer-collection"
	"github.com/inspektor-gadget/inspektor-gadget/pkg/types"
	"github.com/kubescape/go-logger"
	"github.com/kubescape/go-logger/helpers"
	"github.com/kubescape/node-agent/pkg/config"
	"github.com/kubescape/node-agent/pkg/ebpf/events"
	"github.com/kubescape/node-agent/pkg/hosthashsensor/v1"
	hosthashsensorv1 "github.com/kubescape/node-agent/pkg/hosthashsensor/v1"
	"github.com/kubescape/node-agent/pkg/metricsmanager"
	"github.com/kubescape/node-agent/pkg/processmanager"
	"github.com/kubescape/node-agent/pkg/utils"
	"github.com/panjf2000/ants/v2"
)

const (
	capabilitiesTraceName      = "trace_capabilities"
	execTraceName              = "trace_exec"
	networkTraceName           = "trace_network"
	dnsTraceName               = "trace_dns"
	openTraceName              = "trace_open"
	ptraceTraceName            = "trace_ptrace"
	randomxTraceName           = "trace_randomx"
	symlinkTraceName           = "trace_symlink"
	hardlinkTraceName          = "trace_hardlink"
	sshTraceName               = "trace_ssh"
	httpTraceName              = "trace_http"
	capabilitiesWorkerPoolSize = 1
	execWorkerPoolSize         = 2
	openWorkerPoolSize         = 8
	ptraceWorkerPoolSize       = 1
	networkWorkerPoolSize      = 1
	dnsWorkerPoolSize          = 5
	randomxWorkerPoolSize      = 1
	symlinkWorkerPoolSize      = 1
	hardlinkWorkerPoolSize     = 1
	sshWorkerPoolSize          = 1
	httpWorkerPoolSize         = 4
)

type IGHostWatcher struct {
	running bool
	// Configuration
	cfg            config.Config
	ctx            context.Context
	agentStartTime time.Time

	// Host hash sensor
	hostHashSensor hosthashsensorv1.HostHashSensorServiceInterface

	// IG Collections
	tracerCollection    *tracercollection.TracerCollection
	containerCollection *containercollection.ContainerCollection
	containerSelector   containercollection.ContainerSelector
	// IG Tracers
	execTracer *tracerexec.Tracer
	openTracer *traceropen.Tracer

	// Worker pools
	execWorkerPool *ants.PoolWithFunc
	openWorkerPool *ants.PoolWithFunc

	execWorkerChan chan *events.ExecEvent
	openWorkerChan chan *events.OpenEvent

	metrics metricsmanager.MetricsManager

	// container runtime
	runtime *containerutilsTypes.RuntimeConfig
	// process manager
	processManager processmanager.ProcessManagerClient

	// Own pid
	ownPid uint32
}

func getHostAsContainer() (*containercollection.Container, error) {
	pidOne := 1
	mntns, err := containerutils.GetMntNs(pidOne)
	if err != nil {
		return nil, fmt.Errorf("getting mount namespace ID for host PID %d: %w", pidOne, err)
	}
	return &containercollection.Container{
		Runtime: containercollection.RuntimeMetadata{
			BasicRuntimeMetadata: types.BasicRuntimeMetadata{
				ContainerPID: uint32(pidOne),
			},
		},
		Mntns: mntns,
	}, nil
}

func CreateIGHostWatcher(cfg config.Config, metrics metricsmanager.MetricsManager,
	processManager processmanager.ProcessManagerClient, hostHashSensor hosthashsensor.HostHashSensorServiceInterface) (*IGHostWatcher, error) { // Use container collection to get notified for new containers

	// Get own pid
	ownPid := os.Getpid()

	// Create a container collection instance
	containerCollection := &containercollection.ContainerCollection{}

	// Add the host mount ns as a "container"
	hostContainer, err := getHostAsContainer()
	if err != nil {
		return nil, fmt.Errorf("getting host as container: %w", err)
	}
	containerCollection.AddContainer(hostContainer)

	// Create a tracer collection instance
	tracerCollection, err := tracercollection.NewTracerCollection(containerCollection)
	if err != nil {
		return nil, fmt.Errorf("creating tracer collection: %w", err)
	}

	// Create an exec worker pool
	execWorkerPool, err := ants.NewPoolWithFunc(execWorkerPoolSize, func(i interface{}) {
		event := i.(events.ExecEvent)

		path := event.Comm
		if len(event.Args) > 0 {
			path = event.Args[0]
		}

		if path == "" {
			return
		}

		hostHashSensor.ReportEvent(utils.ExecveEventType, &event)

		metrics.ReportEvent(utils.ExecveEventType)
		processManager.ReportEvent(utils.ExecveEventType, &event)
	})
	if err != nil {
		return nil, fmt.Errorf("creating exec worker pool: %w", err)
	}
	// Create an open worker pool
	openWorkerPool, err := ants.NewPoolWithFunc(openWorkerPoolSize, func(i interface{}) {
		event := i.(events.OpenEvent)

		metrics.ReportEvent(utils.OpenEventType)
		hostHashSensor.ReportEvent(utils.OpenEventType, &event)
	})
	if err != nil {
		return nil, fmt.Errorf("creating open worker pool: %w", err)
	}

	return &IGHostWatcher{
		// Configuration
		cfg:               cfg,
		containerSelector: containercollection.ContainerSelector{}, // Empty selector to get all containers
		agentStartTime:    time.Now(),

		// Clients
		hostHashSensor: hostHashSensor,
		// IG Collections
		tracerCollection:    tracerCollection,
		containerCollection: containerCollection,
		// Worker pools
		execWorkerPool: execWorkerPool,
		openWorkerPool: openWorkerPool,
		metrics:        metrics,

		// Channels
		execWorkerChan: make(chan *events.ExecEvent, 10000),
		openWorkerChan: make(chan *events.OpenEvent, 500000),

		processManager: processManager,

		ownPid: uint32(ownPid),
	}, nil
}

func (ch *IGHostWatcher) GetTracerCollection() *tracercollection.TracerCollection {
	return ch.tracerCollection
}

func (ch *IGHostWatcher) Start(ctx context.Context) error {
	if !ch.running {
		// Start the container collection
		if err := ch.startContainerCollection(ctx); err != nil {
			return fmt.Errorf("setting up container collection: %w", err)
		}

		// We want to populate the initial processes before starting the tracers but after retrieving the shims.
		if err := ch.processManager.PopulateInitialProcesses(); err != nil {
			return fmt.Errorf("populating initial processes: %w", err)
		}

		if err := ch.startTracers(); err != nil {
			return fmt.Errorf("starting app behavior tracing: %w", err)
		}
		logger.L().Info("main container handler started")
		ch.running = true
	}

	return nil
}

func (ch *IGHostWatcher) Stop() {
	if ch.running {
		err := ch.stopTracers()
		if err != nil {
			logger.L().Ctx(ch.ctx).Error("stopping app behavior tracing", helpers.Error(err))
		}
		ch.running = false
	}
}

func (ch *IGHostWatcher) Ready() bool {
	return ch.running
}
