package containerwatcher

import (
	"context"
	"fmt"
	"os"

	mapset "github.com/deckarep/golang-set/v2"
	containercollection "github.com/inspektor-gadget/inspektor-gadget/pkg/container-collection"
	tracerseccomp "github.com/inspektor-gadget/inspektor-gadget/pkg/gadgets/advise/seccomp/tracer"
	tracercapabilities "github.com/inspektor-gadget/inspektor-gadget/pkg/gadgets/trace/capabilities/tracer"
	tracercapabilitiestype "github.com/inspektor-gadget/inspektor-gadget/pkg/gadgets/trace/capabilities/types"
	tracerdns "github.com/inspektor-gadget/inspektor-gadget/pkg/gadgets/trace/dns/tracer"
	tracerdnstype "github.com/inspektor-gadget/inspektor-gadget/pkg/gadgets/trace/dns/types"
	tracerexec "github.com/inspektor-gadget/inspektor-gadget/pkg/gadgets/trace/exec/tracer"
	tracerexectype "github.com/inspektor-gadget/inspektor-gadget/pkg/gadgets/trace/exec/types"
	tracernetwork "github.com/inspektor-gadget/inspektor-gadget/pkg/gadgets/trace/network/tracer"
	tracernetworktype "github.com/inspektor-gadget/inspektor-gadget/pkg/gadgets/trace/network/types"
	traceropen "github.com/inspektor-gadget/inspektor-gadget/pkg/gadgets/trace/open/tracer"
	traceropentype "github.com/inspektor-gadget/inspektor-gadget/pkg/gadgets/trace/open/types"
	"github.com/inspektor-gadget/inspektor-gadget/pkg/operators"
	"github.com/inspektor-gadget/inspektor-gadget/pkg/socketenricher"
	tracercollection "github.com/inspektor-gadget/inspektor-gadget/pkg/tracer-collection"
	"github.com/inspektor-gadget/inspektor-gadget/pkg/types"
	"github.com/kubescape/go-logger"
	"github.com/kubescape/go-logger/helpers"
	"github.com/kubescape/k8s-interface/k8sinterface"
	"github.com/kubescape/node-agent/pkg/applicationprofilemanager"
	"github.com/kubescape/node-agent/pkg/config"
	"github.com/kubescape/node-agent/pkg/containerwatcher"
	"github.com/kubescape/node-agent/pkg/dnsmanager"
	tracerantitampering "github.com/kubescape/node-agent/pkg/ebpf/gadgets/antitampering/tracer"
	tracerantitamperingtype "github.com/kubescape/node-agent/pkg/ebpf/gadgets/antitampering/types"
	tracerhardlink "github.com/kubescape/node-agent/pkg/ebpf/gadgets/hardlink/tracer"
	tracerhardlinktype "github.com/kubescape/node-agent/pkg/ebpf/gadgets/hardlink/types"
	tracerandomx "github.com/kubescape/node-agent/pkg/ebpf/gadgets/randomx/tracer"
	tracerandomxtype "github.com/kubescape/node-agent/pkg/ebpf/gadgets/randomx/types"
	tracersymlink "github.com/kubescape/node-agent/pkg/ebpf/gadgets/symlink/tracer"
	tracersymlinktype "github.com/kubescape/node-agent/pkg/ebpf/gadgets/symlink/types"
	"github.com/kubescape/node-agent/pkg/malwaremanager"
	"github.com/kubescape/node-agent/pkg/metricsmanager"
	"github.com/kubescape/node-agent/pkg/networkmanager"
	networkmanagerv1 "github.com/kubescape/node-agent/pkg/networkmanager/v1"
	"github.com/kubescape/node-agent/pkg/relevancymanager"
	rulebinding "github.com/kubescape/node-agent/pkg/rulebindingmanager"
	"github.com/kubescape/node-agent/pkg/rulemanager"
	"github.com/kubescape/node-agent/pkg/utils"
	"github.com/panjf2000/ants/v2"
)

const (
	capabilitiesTraceName       = "trace_capabilities"
	execTraceName               = "trace_exec"
	networkTraceName            = "trace_network"
	dnsTraceName                = "trace_dns"
	openTraceName               = "trace_open"
	randomxTraceName            = "trace_randomx"
	symlinkTraceName            = "trace_symlink"
	hardlinkTraceName           = "trace_hardlink"
	antitamperingTraceName      = "trace_antitampering"
	capabilitiesWorkerPoolSize  = 1
	execWorkerPoolSize          = 2
	openWorkerPoolSize          = 8
	networkWorkerPoolSize       = 1
	dnsWorkerPoolSize           = 5
	randomxWorkerPoolSize       = 1
	symlinkWorkerPoolSize       = 1
	hardlinkWorkerPoolSize      = 1
	antitamperingWorkerPoolSize = 1
)

type IGContainerWatcher struct {
	running bool
	// Configuration
	cfg               config.Config
	containerSelector containercollection.ContainerSelector
	ctx               context.Context
	nodeName          string
	podName           string
	namespace         string

	// Clients
	applicationProfileManager applicationprofilemanager.ApplicationProfileManagerClient
	k8sClient                 *k8sinterface.KubernetesApi
	relevancyManager          relevancymanager.RelevancyManagerClient
	networkManagerv1          networkmanagerv1.NetworkManagerClient
	networkManager            networkmanager.NetworkManagerClient
	dnsManager                dnsmanager.DNSManagerClient
	ruleManager               rulemanager.RuleManagerClient
	malwareManager            malwaremanager.MalwareManagerClient
	// IG Collections
	containerCollection *containercollection.ContainerCollection
	tracerCollection    *tracercollection.TracerCollection
	socketEnricher      *socketenricher.SocketEnricher
	// IG Tracers
	capabilitiesTracer  *tracercapabilities.Tracer
	execTracer          *tracerexec.Tracer
	openTracer          *traceropen.Tracer
	syscallTracer       *tracerseccomp.Tracer
	networkTracer       *tracernetwork.Tracer
	dnsTracer           *tracerdns.Tracer
	randomxTracer       *tracerandomx.Tracer
	symlinkTracer       *tracersymlink.Tracer
	hardlinkTracer      *tracerhardlink.Tracer
	antitamperingTracer *tracerantitampering.Tracer
	kubeIPInstance      operators.OperatorInstance
	kubeNameInstance    operators.OperatorInstance

	// Worker pools
	capabilitiesWorkerPool  *ants.PoolWithFunc
	execWorkerPool          *ants.PoolWithFunc
	openWorkerPool          *ants.PoolWithFunc
	networkWorkerPool       *ants.PoolWithFunc
	dnsWorkerPool           *ants.PoolWithFunc
	randomxWorkerPool       *ants.PoolWithFunc
	symlinkWorkerPool       *ants.PoolWithFunc
	hardlinkWorkerPool      *ants.PoolWithFunc
	antitamperingWorkerPool *ants.PoolWithFunc

	capabilitiesWorkerChan chan *tracercapabilitiestype.Event
	execWorkerChan         chan *tracerexectype.Event
	openWorkerChan         chan *traceropentype.Event
	networkWorkerChan      chan *tracernetworktype.Event
	dnsWorkerChan          chan *tracerdnstype.Event
	randomxWorkerChan      chan *tracerandomxtype.Event
	symlinkWorkerChan      chan *tracersymlinktype.Event
	hardlinkWorkerChan     chan *tracerhardlinktype.Event
	antitampWorkerChan     chan *tracerantitamperingtype.Event

	preRunningContainersIDs mapset.Set[string]

	timeBasedContainers mapset.Set[string] // list of containers to track based on ticker
	ruleManagedPods     mapset.Set[string] // list of pods to track based on rules
	metrics             metricsmanager.MetricsManager

	// cache
	ruleBindingPodNotify *chan rulebinding.RuleBindingNotify
}

var _ containerwatcher.ContainerWatcher = (*IGContainerWatcher)(nil)

func CreateIGContainerWatcher(cfg config.Config, applicationProfileManager applicationprofilemanager.ApplicationProfileManagerClient, k8sClient *k8sinterface.KubernetesApi, relevancyManager relevancymanager.RelevancyManagerClient, networkManagerv1Client networkmanagerv1.NetworkManagerClient, networkManagerClient networkmanager.NetworkManagerClient, dnsManagerClient dnsmanager.DNSManagerClient, metrics metricsmanager.MetricsManager, ruleManager rulemanager.RuleManagerClient, malwareManager malwaremanager.MalwareManagerClient, preRunningContainers mapset.Set[string], ruleBindingPodNotify *chan rulebinding.RuleBindingNotify) (*IGContainerWatcher, error) {
	// Use container collection to get notified for new containers
	containerCollection := &containercollection.ContainerCollection{}
	// Create a tracer collection instance
	tracerCollection, err := tracercollection.NewTracerCollection(containerCollection)
	if err != nil {
		return nil, fmt.Errorf("creating tracer collection: %w", err)
	}
	// Create a capabilities worker pool
	capabilitiesWorkerPool, err := ants.NewPoolWithFunc(capabilitiesWorkerPoolSize, func(i interface{}) {
		event := i.(tracercapabilitiestype.Event)
		// ignore events with empty container name
		if event.K8s.ContainerName == "" {
			return
		}
		metrics.ReportEvent(utils.CapabilitiesEventType)
		k8sContainerID := utils.CreateK8sContainerID(event.K8s.Namespace, event.K8s.PodName, event.K8s.ContainerName)
		applicationProfileManager.ReportCapability(k8sContainerID, event.CapName)
		ruleManager.ReportCapability(event)
	})
	if err != nil {
		return nil, fmt.Errorf("creating capabilities worker pool: %w", err)
	}
	// Create an exec worker pool
	execWorkerPool, err := ants.NewPoolWithFunc(execWorkerPoolSize, func(i interface{}) {
		event := i.(tracerexectype.Event)
		// ignore events with empty container name
		if event.K8s.ContainerName == "" {
			return
		}

		k8sContainerID := utils.CreateK8sContainerID(event.K8s.Namespace, event.K8s.PodName, event.K8s.ContainerName)

		// dropped events
		if event.Type != types.NORMAL {
			applicationProfileManager.ReportDroppedEvent(k8sContainerID)
			return
		}

		path := event.Comm
		if len(event.Args) > 0 {
			path = event.Args[0]
		}
		metrics.ReportEvent(utils.ExecveEventType)
		applicationProfileManager.ReportFileExec(k8sContainerID, path, event.Args)
		relevancyManager.ReportFileExec(event.Runtime.ContainerID, k8sContainerID, path)
		ruleManager.ReportFileExec(event)
		malwareManager.ReportFileExec(k8sContainerID, event)
	})
	if err != nil {
		return nil, fmt.Errorf("creating exec worker pool: %w", err)
	}
	// Create an open worker pool
	openWorkerPool, err := ants.NewPoolWithFunc(openWorkerPoolSize, func(i interface{}) {
		event := i.(traceropentype.Event)
		// ignore events with empty container name
		if event.K8s.ContainerName == "" {
			return
		}
		k8sContainerID := utils.CreateK8sContainerID(event.K8s.Namespace, event.K8s.PodName, event.K8s.ContainerName)

		// dropped events
		if event.Type != types.NORMAL {
			applicationProfileManager.ReportDroppedEvent(k8sContainerID)
			return
		}

		path := event.Path
		if cfg.EnableFullPathTracing {
			path = event.FullPath
		}

		metrics.ReportEvent(utils.OpenEventType)
		applicationProfileManager.ReportFileOpen(k8sContainerID, path, event.Flags)
		relevancyManager.ReportFileOpen(event.Runtime.ContainerID, k8sContainerID, path)
		ruleManager.ReportFileOpen(event)
		malwareManager.ReportFileOpen(k8sContainerID, event)
	})
	if err != nil {
		return nil, fmt.Errorf("creating open worker pool: %w", err)
	}
	// Create a network worker pool
	networkWorkerPool, err := ants.NewPoolWithFunc(networkWorkerPoolSize, func(i interface{}) {
		event := i.(tracernetworktype.Event)
		// ignore events with empty container name
		if event.K8s.ContainerName == "" {
			return
		}
		k8sContainerID := utils.CreateK8sContainerID(event.K8s.Namespace, event.K8s.PodName, event.K8s.ContainerName)

		// dropped events
		if event.Type != types.NORMAL {
			networkManagerv1Client.ReportDroppedEvent(event.Runtime.ContainerID, event)
			networkManagerClient.ReportDroppedEvent(k8sContainerID)
			return
		}
		metrics.ReportEvent(utils.NetworkEventType)
		networkManagerv1Client.ReportNetworkEvent(event.Runtime.ContainerID, event)
		networkManagerClient.ReportNetworkEvent(k8sContainerID, event)
		ruleManager.ReportNetworkEvent(event)
	})
	if err != nil {
		return nil, fmt.Errorf("creating network worker pool: %w", err)
	}
	// Create a dns worker pool
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
		dnsManagerClient.ReportDNSEvent(event)
		ruleManager.ReportDNSEvent(event)
	})
	if err != nil {
		return nil, fmt.Errorf("creating dns worker pool: %w", err)
	}
	// Create a randomx worker pool
	randomxWorkerPool, err := ants.NewPoolWithFunc(randomxWorkerPoolSize, func(i interface{}) {
		event := i.(tracerandomxtype.Event)
		if event.K8s.ContainerName == "" {
			return
		}
		metrics.ReportEvent(utils.RandomXEventType)
		ruleManager.ReportRandomxEvent(event)
	})
	if err != nil {
		return nil, fmt.Errorf("creating randomx worker pool: %w", err)
	}
	// Create a symlink worker pool
	symlinkWorkerPool, err := ants.NewPoolWithFunc(symlinkWorkerPoolSize, func(i interface{}) {
		event := i.(tracersymlinktype.Event)
		if event.K8s.ContainerName == "" {
			return
		}
		metrics.ReportEvent(utils.SymlinkEventType)
		ruleManager.ReportSymlinkEvent(event)
	})
	if err != nil {
		return nil, fmt.Errorf("creating symlink worker pool: %w", err)
	}
	// Create a hardlink worker pool
	hardlinkWorkerPool, err := ants.NewPoolWithFunc(symlinkWorkerPoolSize, func(i interface{}) {
		event := i.(tracerhardlinktype.Event)
		if event.K8s.ContainerName == "" {
			return
		}
		metrics.ReportEvent(utils.HardlinkEventType)
		ruleManager.ReportHardlinkEvent(event)
	})
	if err != nil {
		return nil, fmt.Errorf("creating hardlink worker pool: %w", err)
	}
	// Create a antitampering worker pool
	antitamperingWorkerPool, err := ants.NewPoolWithFunc(antitamperingWorkerPoolSize, func(i interface{}) {
		event := i.(tracerantitamperingtype.Event)
		if event.K8s.ContainerName == "" {
			return
		}
		metrics.ReportEvent(utils.AntitamperingEventType)
		ruleManager.ReportAntitamperingEvent(event)
	})
	if err != nil {
		return nil, fmt.Errorf("creating antitampering worker pool: %w", err)
	}

	return &IGContainerWatcher{
		// Configuration
		cfg:               cfg,
		containerSelector: containercollection.ContainerSelector{}, // Empty selector to get all containers
		nodeName:          os.Getenv(config.NodeNameEnvVar),
		podName:           os.Getenv(config.PodNameEnvVar),
		namespace:         os.Getenv(config.NamespaceEnvVar),

		// Clients
		applicationProfileManager: applicationProfileManager,
		k8sClient:                 k8sClient,
		relevancyManager:          relevancyManager,
		networkManagerv1:          networkManagerv1Client,
		networkManager:            networkManagerClient,
		dnsManager:                dnsManagerClient,
		ruleManager:               ruleManager,
		malwareManager:            malwareManager,
		// IG Collections
		containerCollection: containerCollection,
		tracerCollection:    tracerCollection,
		// Worker pools
		capabilitiesWorkerPool:  capabilitiesWorkerPool,
		execWorkerPool:          execWorkerPool,
		openWorkerPool:          openWorkerPool,
		networkWorkerPool:       networkWorkerPool,
		dnsWorkerPool:           dnsWorkerPool,
		randomxWorkerPool:       randomxWorkerPool,
		symlinkWorkerPool:       symlinkWorkerPool,
		hardlinkWorkerPool:      hardlinkWorkerPool,
		antitamperingWorkerPool: antitamperingWorkerPool,
		metrics:                 metrics,
		preRunningContainersIDs: preRunningContainers,

		// Channels
		capabilitiesWorkerChan: make(chan *tracercapabilitiestype.Event, 1000),
		execWorkerChan:         make(chan *tracerexectype.Event, 10000),
		openWorkerChan:         make(chan *traceropentype.Event, 500000),
		networkWorkerChan:      make(chan *tracernetworktype.Event, 500000),
		dnsWorkerChan:          make(chan *tracerdnstype.Event, 100000),
		randomxWorkerChan:      make(chan *tracerandomxtype.Event, 5000),
		symlinkWorkerChan:      make(chan *tracersymlinktype.Event, 1000),
		hardlinkWorkerChan:     make(chan *tracerhardlinktype.Event, 1000),
		antitampWorkerChan:     make(chan *tracerantitamperingtype.Event, 1000),

		// cache
		ruleBindingPodNotify: ruleBindingPodNotify,

		timeBasedContainers: mapset.NewSet[string](),
		ruleManagedPods:     mapset.NewSet[string](),
	}, nil
}

func (ch *IGContainerWatcher) Start(ctx context.Context) error {
	if !ch.running {

		if err := ch.startContainerCollection(ctx); err != nil {
			return fmt.Errorf("setting up container collection: %w", err)
		}

		if err := ch.startTracers(); err != nil {
			ch.stopContainerCollection()
			return fmt.Errorf("starting app behavior tracing: %w", err)
		}
		logger.L().Info("main container handler started")
		ch.running = true
	}

	return nil
}

func (ch *IGContainerWatcher) Stop() {
	if ch.running {
		ch.stopContainerCollection()
		err := ch.stopTracers()
		if err != nil {
			logger.L().Ctx(ch.ctx).Warning("error stopping app behavior tracing", helpers.Error(err))
		}
		ch.running = false
	}
}

func (ch *IGContainerWatcher) Ready() bool {
	return ch.running
}
