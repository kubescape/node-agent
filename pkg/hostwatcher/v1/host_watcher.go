package hostwatcher

import (
	"context"
	"fmt"
	"os"
	"time"

	containercollection "github.com/inspektor-gadget/inspektor-gadget/pkg/container-collection"
	containerutils "github.com/inspektor-gadget/inspektor-gadget/pkg/container-utils"
	tracerseccomp "github.com/inspektor-gadget/inspektor-gadget/pkg/gadgets/advise/seccomp/tracer"
	tracercapabilities "github.com/inspektor-gadget/inspektor-gadget/pkg/gadgets/trace/capabilities/tracer"
	tracercapabilitiestype "github.com/inspektor-gadget/inspektor-gadget/pkg/gadgets/trace/capabilities/types"
	tracerdns "github.com/inspektor-gadget/inspektor-gadget/pkg/gadgets/trace/dns/tracer"
	tracerdnstype "github.com/inspektor-gadget/inspektor-gadget/pkg/gadgets/trace/dns/types"
	tracerexec "github.com/inspektor-gadget/inspektor-gadget/pkg/gadgets/trace/exec/tracer"
	tracernetwork "github.com/inspektor-gadget/inspektor-gadget/pkg/gadgets/trace/network/tracer"
	tracernetworktype "github.com/inspektor-gadget/inspektor-gadget/pkg/gadgets/trace/network/types"
	traceropen "github.com/inspektor-gadget/inspektor-gadget/pkg/gadgets/trace/open/tracer"
	"github.com/inspektor-gadget/inspektor-gadget/pkg/socketenricher"
	tracercollection "github.com/inspektor-gadget/inspektor-gadget/pkg/tracer-collection"
	"github.com/inspektor-gadget/inspektor-gadget/pkg/types"
	"github.com/kubescape/go-logger"
	"github.com/kubescape/go-logger/helpers"
	"github.com/kubescape/node-agent/pkg/config"
	"github.com/kubescape/node-agent/pkg/dnsmanager"
	"github.com/kubescape/node-agent/pkg/ebpf/events"
	tracerhardlink "github.com/kubescape/node-agent/pkg/ebpf/gadgets/hardlink/tracer"
	tracerhardlinktype "github.com/kubescape/node-agent/pkg/ebpf/gadgets/hardlink/types"
	tracerhttp "github.com/kubescape/node-agent/pkg/ebpf/gadgets/http/tracer"
	tracerhttptype "github.com/kubescape/node-agent/pkg/ebpf/gadgets/http/types"
	traceriouring "github.com/kubescape/node-agent/pkg/ebpf/gadgets/iouring/tracer"
	traceriouringtype "github.com/kubescape/node-agent/pkg/ebpf/gadgets/iouring/tracer/types"
	tracerptrace "github.com/kubescape/node-agent/pkg/ebpf/gadgets/ptrace/tracer"
	tracerptracetype "github.com/kubescape/node-agent/pkg/ebpf/gadgets/ptrace/tracer/types"
	tracerandomx "github.com/kubescape/node-agent/pkg/ebpf/gadgets/randomx/tracer"
	tracerandomxtype "github.com/kubescape/node-agent/pkg/ebpf/gadgets/randomx/types"
	tracerssh "github.com/kubescape/node-agent/pkg/ebpf/gadgets/ssh/tracer"
	tracersshtype "github.com/kubescape/node-agent/pkg/ebpf/gadgets/ssh/types"
	tracersymlink "github.com/kubescape/node-agent/pkg/ebpf/gadgets/symlink/tracer"
	tracersymlinktype "github.com/kubescape/node-agent/pkg/ebpf/gadgets/symlink/types"
	"github.com/kubescape/node-agent/pkg/hosthashsensor/v1"
	"github.com/kubescape/node-agent/pkg/hostnetworksensor"
	"github.com/kubescape/node-agent/pkg/hostrulemanager"
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
	iouringTraceName           = "trace_iouring"
	capabilitiesWorkerPoolSize = 1
	execWorkerPoolSize         = 2
	openWorkerPoolSize         = 8
	ptraceWorkerPoolSize       = 1
	defaultWorkerPoolSize      = 2
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
	hostHashSensor hosthashsensor.HostHashSensorServiceInterface

	// IG Collections
	tracerCollection    *tracercollection.TracerCollection
	containerCollection *containercollection.ContainerCollection
	containerSelector   containercollection.ContainerSelector
	socketEnricher      *socketenricher.SocketEnricher
	// IG Tracers
	capabilitiesTracer *tracercapabilities.Tracer
	execTracer         *tracerexec.Tracer
	openTracer         *traceropen.Tracer
	ptraceTracer       *tracerptrace.Tracer
	syscallTracer      *tracerseccomp.Tracer
	networkTracer      *tracernetwork.Tracer
	dnsTracer          *tracerdns.Tracer
	randomxTracer      *tracerandomx.Tracer
	symlinkTracer      *tracersymlink.Tracer
	hardlinkTracer     *tracerhardlink.Tracer
	sshTracer          *tracerssh.Tracer
	httpTracer         *tracerhttp.Tracer
	iouringTracer      *traceriouring.Tracer

	// Worker pools
	capabilitiesWorkerPool *ants.PoolWithFunc
	execWorkerPool         *ants.PoolWithFunc
	openWorkerPool         *ants.PoolWithFunc
	ptraceWorkerPool       *ants.PoolWithFunc
	networkWorkerPool      *ants.PoolWithFunc
	dnsWorkerPool          *ants.PoolWithFunc
	randomxWorkerPool      *ants.PoolWithFunc
	symlinkWorkerPool      *ants.PoolWithFunc
	hardlinkWorkerPool     *ants.PoolWithFunc
	sshdWorkerPool         *ants.PoolWithFunc
	httpWorkerPool         *ants.PoolWithFunc
	iouringWorkerPool      *ants.PoolWithFunc

	capabilitiesWorkerChan chan *tracercapabilitiestype.Event
	execWorkerChan         chan *events.ExecEvent
	openWorkerChan         chan *events.OpenEvent
	ptraceWorkerChan       chan *tracerptracetype.Event
	networkWorkerChan      chan *tracernetworktype.Event
	dnsWorkerChan          chan *tracerdnstype.Event
	randomxWorkerChan      chan *tracerandomxtype.Event
	symlinkWorkerChan      chan *tracersymlinktype.Event
	hardlinkWorkerChan     chan *tracerhardlinktype.Event
	sshWorkerChan          chan *tracersshtype.Event
	httpWorkerChan         chan *tracerhttptype.Event
	iouringWorkerChan      chan *traceriouringtype.Event

	metrics metricsmanager.MetricsManager

	// process manager
	processManager processmanager.ProcessManagerClient
	// rule manager
	ruleManager hostrulemanager.HostRuleManagerClient

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
	processManager processmanager.ProcessManagerClient, hostHashSensor hosthashsensor.HostHashSensorServiceInterface,
	hostRuleManager hostrulemanager.HostRuleManagerClient, hostNetworkSensorClient hostnetworksensor.HostNetworkSensorClient,
	dnsManagerClient dnsmanager.DNSManagerClient) (*IGHostWatcher, error) { // Use container collection to get notified for new containers

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
		hostRuleManager.ReportEvent(utils.ExecveEventType, &event)
	})
	if err != nil {
		return nil, fmt.Errorf("creating exec worker pool: %w", err)
	}
	// Create an open worker pool
	openWorkerPool, err := ants.NewPoolWithFunc(openWorkerPoolSize, func(i interface{}) {
		event := i.(events.OpenEvent)

		metrics.ReportEvent(utils.OpenEventType)
		hostHashSensor.ReportEvent(utils.OpenEventType, &event)
		hostRuleManager.ReportEvent(utils.OpenEventType, &event)
	})
	if err != nil {
		return nil, fmt.Errorf("creating open worker pool: %w", err)
	}
	// Create a capabilities worker pool
	capabilitiesWorkerPool, err := ants.NewPoolWithFunc(capabilitiesWorkerPoolSize, func(i interface{}) {
		event := i.(tracercapabilitiestype.Event)
		metrics.ReportEvent(utils.CapabilitiesEventType)
		hostRuleManager.ReportEvent(utils.CapabilitiesEventType, &event)
	})
	if err != nil {
		return nil, fmt.Errorf("creating capabilities worker pool: %w", err)
	}

	// Create a ptrace worker pool
	ptraceWorkerPool, err := ants.NewPoolWithFunc(ptraceWorkerPoolSize, func(i interface{}) {
		event := i.(tracerptracetype.Event)
		metrics.ReportEvent(utils.PtraceEventType)
		hostRuleManager.ReportEvent(utils.PtraceEventType, &event)
	})
	if err != nil {
		return nil, fmt.Errorf("creating ptrace worker pool: %w", err)
	}

	// Create a network worker pool
	networkWorkerPool, err := ants.NewPoolWithFunc(networkWorkerPoolSize, func(i interface{}) {
		event := i.(tracernetworktype.Event)
		metrics.ReportEvent(utils.NetworkEventType)
		hostRuleManager.ReportEvent(utils.NetworkEventType, &event)
		hostNetworkSensorClient.ReportEvent(utils.NetworkEventType, &event)
	})
	if err != nil {
		return nil, fmt.Errorf("creating network worker pool: %w", err)
	}

	// Create a DNS worker pool
	dnsWorkerPool, err := ants.NewPoolWithFunc(dnsWorkerPoolSize, func(i interface{}) {
		event := i.(tracerdnstype.Event)

		// ignore DNS events that are not responses
		if event.Qr != tracerdnstype.DNSPktTypeResponse {
			return
		}

		// ignore DNS events that do not have address resolution
		if event.NumAnswers == 0 {
			return
		}

		metrics.ReportEvent(utils.DnsEventType)
		hostRuleManager.ReportEvent(utils.DnsEventType, &event)
		dnsManagerClient.ReportEvent(event)
		hostNetworkSensorClient.ReportEvent(utils.DnsEventType, &event)
	})
	if err != nil {
		return nil, fmt.Errorf("creating dns worker pool: %w", err)
	}

	randomxWorkerPool, err := ants.NewPoolWithFunc(randomxWorkerPoolSize, func(i interface{}) {
		event := i.(tracerandomxtype.Event)
		metrics.ReportEvent(utils.RandomXEventType)
		hostRuleManager.ReportEvent(utils.RandomXEventType, &event)
	})
	if err != nil {
		return nil, fmt.Errorf("creating randomx worker pool: %w", err)
	}

	symlinkWorkerPool, err := ants.NewPoolWithFunc(symlinkWorkerPoolSize, func(i interface{}) {
		event := i.(tracersymlinktype.Event)
		metrics.ReportEvent(utils.SymlinkEventType)
		hostRuleManager.ReportEvent(utils.SymlinkEventType, &event)
	})
	if err != nil {
		return nil, fmt.Errorf("creating symlink worker pool: %w", err)
	}

	hardlinkWorkerPool, err := ants.NewPoolWithFunc(hardlinkWorkerPoolSize, func(i interface{}) {
		event := i.(tracerhardlinktype.Event)
		metrics.ReportEvent(utils.HardlinkEventType)
		hostRuleManager.ReportEvent(utils.HardlinkEventType, &event)
	})
	if err != nil {
		return nil, fmt.Errorf("creating hardlink worker pool: %w", err)
	}

	sshWorkerPool, err := ants.NewPoolWithFunc(sshWorkerPoolSize, func(i interface{}) {
		event := i.(tracersshtype.Event)
		metrics.ReportEvent(utils.SSHEventType)
		hostRuleManager.ReportEvent(utils.SSHEventType, &event)
	})
	if err != nil {
		return nil, fmt.Errorf("creating ssh worker pool: %w", err)
	}

	httpWorkerPool, err := ants.NewPoolWithFunc(httpWorkerPoolSize, func(i interface{}) {
		event := i.(tracerhttptype.Event)
		metrics.ReportEvent(utils.HTTPEventType)
		hostRuleManager.ReportEvent(utils.HTTPEventType, &event)
	})
	if err != nil {
		return nil, fmt.Errorf("creating http worker pool: %w", err)
	}

	iouringWorkerPool, err := ants.NewPoolWithFunc(defaultWorkerPoolSize, func(i interface{}) {
		event := i.(traceriouringtype.Event)
		metrics.ReportEvent(utils.IoUringEventType)
		hostRuleManager.ReportEvent(utils.IoUringEventType, &event)
	})
	if err != nil {
		return nil, fmt.Errorf("creating iouring worker pool: %w", err)
	}

	return &IGHostWatcher{
		// Configuration
		cfg:               cfg,
		containerSelector: containercollection.ContainerSelector{}, // Empty selector to get all containers
		agentStartTime:    time.Now(),

		// Clients
		hostHashSensor: hostHashSensor,
		ruleManager:    hostRuleManager,
		// IG Collections
		tracerCollection:    tracerCollection,
		containerCollection: containerCollection,
		// Worker pools
		execWorkerPool:         execWorkerPool,
		openWorkerPool:         openWorkerPool,
		ptraceWorkerPool:       ptraceWorkerPool,
		capabilitiesWorkerPool: capabilitiesWorkerPool,
		networkWorkerPool:      networkWorkerPool,
		dnsWorkerPool:          dnsWorkerPool,
		randomxWorkerPool:      randomxWorkerPool,
		symlinkWorkerPool:      symlinkWorkerPool,
		hardlinkWorkerPool:     hardlinkWorkerPool,
		sshdWorkerPool:         sshWorkerPool,
		httpWorkerPool:         httpWorkerPool,
		iouringWorkerPool:      iouringWorkerPool,
		metrics:                metrics,

		// Channels
		capabilitiesWorkerChan: make(chan *tracercapabilitiestype.Event, 1000),
		execWorkerChan:         make(chan *events.ExecEvent, 10000),
		openWorkerChan:         make(chan *events.OpenEvent, 500000),
		ptraceWorkerChan:       make(chan *tracerptracetype.Event, 1000),
		networkWorkerChan:      make(chan *tracernetworktype.Event, 500000),
		dnsWorkerChan:          make(chan *tracerdnstype.Event, 100000),
		randomxWorkerChan:      make(chan *tracerandomxtype.Event, 5000),
		symlinkWorkerChan:      make(chan *tracersymlinktype.Event, 1000),
		hardlinkWorkerChan:     make(chan *tracerhardlinktype.Event, 1000),
		sshWorkerChan:          make(chan *tracersshtype.Event, 1000),
		httpWorkerChan:         make(chan *tracerhttptype.Event, 500000),
		iouringWorkerChan:      make(chan *traceriouringtype.Event, 5000),

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
