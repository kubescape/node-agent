package containerwatcher

import (
	"context"
	"fmt"
	"node-agent/pkg/applicationprofilemanager"
	"node-agent/pkg/config"
	"node-agent/pkg/containerwatcher"
	"node-agent/pkg/dnsmanager"
	"node-agent/pkg/malwaremanager"
	"node-agent/pkg/metricsmanager"
	"node-agent/pkg/networkmanager"
	"node-agent/pkg/relevancymanager"
	"node-agent/pkg/rulemanager"
	"node-agent/pkg/utils"
	"os"

	tracerandomx "node-agent/pkg/ebpf/gadgets/randomx/tracer"
	tracerandomxtype "node-agent/pkg/ebpf/gadgets/randomx/types"

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
	tracercollection "github.com/inspektor-gadget/inspektor-gadget/pkg/tracer-collection"
	"github.com/inspektor-gadget/inspektor-gadget/pkg/types"
	"github.com/kubescape/go-logger"
	"github.com/kubescape/go-logger/helpers"
	"github.com/kubescape/k8s-interface/k8sinterface"
	"github.com/panjf2000/ants/v2"
)

const (
	capabilitiesTraceName      = "trace_capabilities"
	execTraceName              = "trace_exec"
	networkTraceName           = "trace_network"
	dnsTraceName               = "trace_dns"
	openTraceName              = "trace_open"
	randomxTraceName           = "trace_randomx"
	capabilitiesWorkerPoolSize = 1
	execWorkerPoolSize         = 2
	openWorkerPoolSize         = 8
	networkWorkerPoolSize      = 1
	dnsWorkerPoolSize          = 5
	randomxWorkerPoolSize      = 1
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
	networkManager            networkmanager.NetworkManagerClient
	dnsManager                dnsmanager.DNSManagerClient
	ruleManager               rulemanager.RuleManagerClient
	malwareManager            malwaremanager.MalwareManagerClient
	// IG Collections
	containerCollection *containercollection.ContainerCollection
	tracerCollection    *tracercollection.TracerCollection
	// IG Tracers
	capabilitiesTracer *tracercapabilities.Tracer
	execTracer         *tracerexec.Tracer
	openTracer         *traceropen.Tracer
	syscallTracer      *tracerseccomp.Tracer
	networkTracer      *tracernetwork.Tracer
	dnsTracer          *tracerdns.Tracer
	randomxTracer      *tracerandomx.Tracer
	kubeIPInstance     operators.OperatorInstance
	kubeNameInstance   operators.OperatorInstance
	// Worker pools
	capabilitiesWorkerPool *ants.PoolWithFunc
	execWorkerPool         *ants.PoolWithFunc
	openWorkerPool         *ants.PoolWithFunc
	networkWorkerPool      *ants.PoolWithFunc
	dnsWorkerPool          *ants.PoolWithFunc
	randomxWorkerPool      *ants.PoolWithFunc

	capabilitiesWorkerChan chan *tracercapabilitiestype.Event
	execWorkerChan         chan *tracerexectype.Event
	openWorkerChan         chan *traceropentype.Event
	networkWorkerChan      chan *tracernetworktype.Event
	dnsWorkerChan          chan *tracerdnstype.Event
	randomxWorkerChan      chan *tracerandomxtype.Event

	preRunningContainersIDs mapset.Set[string]

	metrics metricsmanager.MetricsManager
}

var _ containerwatcher.ContainerWatcher = (*IGContainerWatcher)(nil)

func CreateIGContainerWatcher(cfg config.Config, applicationProfileManager applicationprofilemanager.ApplicationProfileManagerClient, k8sClient *k8sinterface.KubernetesApi, relevancyManager relevancymanager.RelevancyManagerClient, networkManagerClient networkmanager.NetworkManagerClient, dnsManagerClient dnsmanager.DNSManagerClient, metrics metricsmanager.MetricsManager, ruleManager rulemanager.RuleManagerClient, malwareManager malwaremanager.MalwareManagerClient, preRunningContainers mapset.Set[string]) (*IGContainerWatcher, error) {
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
		ruleManager.ReportCapability(k8sContainerID, event)
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
		ruleManager.ReportFileExec(k8sContainerID, event)
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
		ruleManager.ReportFileOpen(k8sContainerID, event)
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

		// dropped events
		if event.Type != types.NORMAL {
			networkManagerClient.ReportDroppedEvent(event.Runtime.ContainerID, event)
			return
		}
		metrics.ReportEvent(utils.NetworkEventType)
		networkManagerClient.ReportNetworkEvent(event.Runtime.ContainerID, event)
		ruleManager.ReportNetworkEvent(event.Runtime.ContainerID, event)
	})
	if err != nil {
		return nil, fmt.Errorf("creating network worker pool: %w", err)
	}
	// Create a dns worker pool
	dnsWorkerPool, err := ants.NewPoolWithFunc(dnsWorkerPoolSize, func(i interface{}) {
		event := i.(tracerdnstype.Event)
		// ignore events with empty container name
		if event.K8s.ContainerName == "" {
			return
		}
		if event.Qr != tracerdnstype.DNSPktTypeResponse {
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
		ruleManager.ReportRandomxEvent(event.Runtime.ContainerID, event)
	})
	if err != nil {
		return nil, fmt.Errorf("creating randomx worker pool: %w", err)
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
		metrics:                 metrics,
		preRunningContainersIDs: preRunningContainers,

		// Channels
		capabilitiesWorkerChan: make(chan *tracercapabilitiestype.Event, 1000),
		execWorkerChan:         make(chan *tracerexectype.Event, 1000),
		openWorkerChan:         make(chan *traceropentype.Event, 50000),
		networkWorkerChan:      make(chan *tracernetworktype.Event, 50000),
		dnsWorkerChan:          make(chan *tracerdnstype.Event, 10000),
		randomxWorkerChan:      make(chan *tracerandomxtype.Event, 500),
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
