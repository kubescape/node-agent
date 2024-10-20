package containerwatcher

import (
	"context"
	"fmt"
	"os"

	mapset "github.com/deckarep/golang-set/v2"
	"github.com/goradd/maps"
	containercollection "github.com/inspektor-gadget/inspektor-gadget/pkg/container-collection"
	containerutilsTypes "github.com/inspektor-gadget/inspektor-gadget/pkg/container-utils/types"
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
	"github.com/kubescape/go-logger"
	"github.com/kubescape/go-logger/helpers"
	"github.com/kubescape/k8s-interface/k8sinterface"
	"github.com/kubescape/node-agent/pkg/applicationprofilemanager"
	"github.com/kubescape/node-agent/pkg/config"
	"github.com/kubescape/node-agent/pkg/containerwatcher"
	"github.com/kubescape/node-agent/pkg/dnsmanager"
	tracerhardlink "github.com/kubescape/node-agent/pkg/ebpf/gadgets/hardlink/tracer"
	tracerhardlinktype "github.com/kubescape/node-agent/pkg/ebpf/gadgets/hardlink/types"
	tracerhttp "github.com/kubescape/node-agent/pkg/ebpf/gadgets/http/tracer"
	tracerhttptype "github.com/kubescape/node-agent/pkg/ebpf/gadgets/http/types"
	tracerptrace "github.com/kubescape/node-agent/pkg/ebpf/gadgets/ptrace/tracer"
	tracerptracetype "github.com/kubescape/node-agent/pkg/ebpf/gadgets/ptrace/tracer/types"
	tracerandomx "github.com/kubescape/node-agent/pkg/ebpf/gadgets/randomx/tracer"
	tracerandomxtype "github.com/kubescape/node-agent/pkg/ebpf/gadgets/randomx/types"
	tracerssh "github.com/kubescape/node-agent/pkg/ebpf/gadgets/ssh/tracer"
	tracersshtype "github.com/kubescape/node-agent/pkg/ebpf/gadgets/ssh/types"
	tracersymlink "github.com/kubescape/node-agent/pkg/ebpf/gadgets/symlink/tracer"
	tracersymlinktype "github.com/kubescape/node-agent/pkg/ebpf/gadgets/symlink/types"

	"github.com/kubescape/node-agent/pkg/malwaremanager"
	"github.com/kubescape/node-agent/pkg/metricsmanager"
	"github.com/kubescape/node-agent/pkg/networkmanager"
	"github.com/kubescape/node-agent/pkg/relevancymanager"
	rulebinding "github.com/kubescape/node-agent/pkg/rulebindingmanager"
	"github.com/kubescape/node-agent/pkg/rulemanager"
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
	kubeIPInstance     operators.OperatorInstance
	kubeNameInstance   operators.OperatorInstance
	// Third party tracers
	thirdPartyTracers mapset.Set[containerwatcher.CustomTracer]
	// Third party container receivers
	thirdPartyContainerReceivers mapset.Set[containerwatcher.ContainerReceiver]

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

	capabilitiesWorkerChan chan *tracercapabilitiestype.Event
	execWorkerChan         chan *tracerexectype.Event
	openWorkerChan         chan *traceropentype.Event
	ptraceWorkerChan       chan *tracerptracetype.Event
	networkWorkerChan      chan *tracernetworktype.Event
	dnsWorkerChan          chan *tracerdnstype.Event
	randomxWorkerChan      chan *tracerandomxtype.Event
	symlinkWorkerChan      chan *tracersymlinktype.Event
	hardlinkWorkerChan     chan *tracerhardlinktype.Event
	sshWorkerChan          chan *tracersshtype.Event
	httpWorkerChan         chan *tracerhttptype.Event

	preRunningContainersIDs mapset.Set[string]
	timeBasedContainers     mapset.Set[string] // list of containers to track based on ticker
	ruleManagedPods         mapset.Set[string] // list of pods to track based on rules
	metrics                 metricsmanager.MetricsManager
	// cache
	ruleBindingPodNotify *chan rulebinding.RuleBindingNotify
	// container runtime
	runtime *containerutilsTypes.RuntimeConfig
}

var _ containerwatcher.ContainerWatcher = (*IGContainerWatcher)(nil)

func CreateIGContainerWatcher(cfg config.Config, applicationProfileManager applicationprofilemanager.ApplicationProfileManagerClient, k8sClient *k8sinterface.KubernetesApi, relevancyManager relevancymanager.RelevancyManagerClient, networkManagerClient networkmanager.NetworkManagerClient, dnsManagerClient dnsmanager.DNSManagerClient, metrics metricsmanager.MetricsManager, ruleManager rulemanager.RuleManagerClient, malwareManager malwaremanager.MalwareManagerClient, preRunningContainers mapset.Set[string], ruleBindingPodNotify *chan rulebinding.RuleBindingNotify, runtime *containerutilsTypes.RuntimeConfig, thirdPartyEventReceivers *maps.SafeMap[utils.EventType, mapset.Set[containerwatcher.EventReceiver]], thirdPartyEnricher containerwatcher.ThirdPartyEnricher) (*IGContainerWatcher, error) {
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
		ruleManager.ReportEvent(utils.CapabilitiesEventType, &event)

		// Report capabilities to event receivers
		reportEventToThirdPartyTracers(utils.CapabilitiesEventType, &event, thirdPartyEventReceivers)
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

		if isDroppedEvent(event.Type, event.Message) {
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
		ruleManager.ReportEvent(utils.ExecveEventType, &event)
		malwareManager.ReportEvent(utils.ExecveEventType, &event)

		// Report exec events to event receivers
		reportEventToThirdPartyTracers(utils.ExecveEventType, &event, thirdPartyEventReceivers)
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

		if isDroppedEvent(event.Type, event.Message) {
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
		ruleManager.ReportEvent(utils.OpenEventType, &event)
		malwareManager.ReportEvent(utils.OpenEventType, &event)

		// Report open events to event receivers
		reportEventToThirdPartyTracers(utils.OpenEventType, &event, thirdPartyEventReceivers)
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

		if isDroppedEvent(event.Type, event.Message) {
			networkManagerClient.ReportDroppedEvent(k8sContainerID)
			return
		}
		metrics.ReportEvent(utils.NetworkEventType)
		networkManagerClient.ReportNetworkEvent(k8sContainerID, event)
		ruleManager.ReportEvent(utils.NetworkEventType, &event)

		// Report network events to event receivers
		reportEventToThirdPartyTracers(utils.NetworkEventType, &event, thirdPartyEventReceivers)
	})
	if err != nil {
		return nil, fmt.Errorf("creating network worker pool: %w", err)
	}
	// Create a dns worker pool
	dnsWorkerPool, err := ants.NewPoolWithFunc(dnsWorkerPoolSize, func(i interface{}) {
		event := i.(tracerdnstype.Event)

		if event.K8s.ContainerName == "" {
			return
		}

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
		ruleManager.ReportEvent(utils.DnsEventType, &event)

		// Report DNS events to event receivers
		reportEventToThirdPartyTracers(utils.DnsEventType, &event, thirdPartyEventReceivers)
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
		ruleManager.ReportEvent(utils.RandomXEventType, &event)

		// Report randomx events to event receivers
		reportEventToThirdPartyTracers(utils.RandomXEventType, &event, thirdPartyEventReceivers)
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

		thirdPartyEnricher.Enrich(&event)
		metrics.ReportEvent(utils.SymlinkEventType)
		ruleManager.ReportEvent(utils.SymlinkEventType, &event)

		// Report symlink events to event receivers
		reportEventToThirdPartyTracers(utils.SymlinkEventType, &event, thirdPartyEventReceivers)
	})
	if err != nil {
		return nil, fmt.Errorf("creating symlink worker pool: %w", err)
	}
	// Create a hardlink worker pool
	hardlinkWorkerPool, err := ants.NewPoolWithFunc(hardlinkWorkerPoolSize, func(i interface{}) {
		event := i.(tracerhardlinktype.Event)
		if event.K8s.ContainerName == "" {
			return
		}
		metrics.ReportEvent(utils.HardlinkEventType)
		ruleManager.ReportEvent(utils.HardlinkEventType, &event)

		// Report hardlink events to event receivers
		reportEventToThirdPartyTracers(utils.HardlinkEventType, &event, thirdPartyEventReceivers)
	})
	if err != nil {
		return nil, fmt.Errorf("creating hardlink worker pool: %w", err)
	}
	// Create a ssh worker pool
	sshWorkerPool, err := ants.NewPoolWithFunc(sshWorkerPoolSize, func(i interface{}) {
		event := i.(tracersshtype.Event)
		if event.K8s.ContainerName == "" {
			return
		}

		metrics.ReportEvent(utils.SSHEventType)
		ruleManager.ReportEvent(utils.SSHEventType, &event)

		// Report ssh events to event receivers
		reportEventToThirdPartyTracers(utils.SSHEventType, &event, thirdPartyEventReceivers)
	})
	if err != nil {
		return nil, fmt.Errorf("creating ssh worker pool: %w", err)
	}

	// Create a http worker pool
	httpWorkerPool, err := ants.NewPoolWithFunc(httpWorkerPoolSize, func(i interface{}) {
		event := i.(tracerhttptype.Event)
		// ignore events with empty container name
		if event.K8s.ContainerName == "" {
			return
		}

		k8sContainerID := utils.CreateK8sContainerID(event.K8s.Namespace, event.K8s.PodName, event.K8s.ContainerName)

		if isDroppedEvent(event.Type, event.Message) {
			applicationProfileManager.ReportDroppedEvent(k8sContainerID)
			return
		}

		metrics.ReportEvent(utils.HTTPEventType)
		applicationProfileManager.ReportHTTPEvent(k8sContainerID, &event)

		reportEventToThirdPartyTracers(utils.HTTPEventType, &event, thirdPartyEventReceivers)
	})

	if err != nil {
		return nil, fmt.Errorf("creating http worker pool: %w", err)
	}

	// Create a ptrace worker pool
	ptraceWorkerPool, err := ants.NewPoolWithFunc(ptraceWorkerPoolSize, func(i interface{}) {
		event := i.(tracerptracetype.Event)
		if event.K8s.ContainerName == "" {
			return
		}
		ruleManager.ReportEvent(utils.PtraceEventType, &event)
	})

	if err != nil {
		return nil, fmt.Errorf("creating ptrace worker pool: %w", err)
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
		symlinkWorkerPool:       symlinkWorkerPool,
		hardlinkWorkerPool:      hardlinkWorkerPool,
		sshdWorkerPool:          sshWorkerPool,
		httpWorkerPool:          httpWorkerPool,
		ptraceWorkerPool:        ptraceWorkerPool,
		metrics:                 metrics,
		preRunningContainersIDs: preRunningContainers,

		// Channels
		capabilitiesWorkerChan: make(chan *tracercapabilitiestype.Event, 1000),
		execWorkerChan:         make(chan *tracerexectype.Event, 10000),
		openWorkerChan:         make(chan *traceropentype.Event, 500000),
		ptraceWorkerChan:       make(chan *tracerptracetype.Event, 1000),
		networkWorkerChan:      make(chan *tracernetworktype.Event, 500000),
		dnsWorkerChan:          make(chan *tracerdnstype.Event, 100000),
		randomxWorkerChan:      make(chan *tracerandomxtype.Event, 5000),
		symlinkWorkerChan:      make(chan *tracersymlinktype.Event, 1000),
		hardlinkWorkerChan:     make(chan *tracerhardlinktype.Event, 1000),
		sshWorkerChan:          make(chan *tracersshtype.Event, 1000),
		httpWorkerChan:         make(chan *tracerhttptype.Event, 500000),

		// cache
		ruleBindingPodNotify:         ruleBindingPodNotify,
		timeBasedContainers:          mapset.NewSet[string](),
		ruleManagedPods:              mapset.NewSet[string](),
		runtime:                      runtime,
		thirdPartyTracers:            mapset.NewSet[containerwatcher.CustomTracer](),
		thirdPartyContainerReceivers: mapset.NewSet[containerwatcher.ContainerReceiver](),
	}, nil
}

func (ch *IGContainerWatcher) GetContainerCollection() *containercollection.ContainerCollection {
	return ch.containerCollection
}

func (ch *IGContainerWatcher) GetTracerCollection() *tracercollection.TracerCollection {
	return ch.tracerCollection
}

func (ch *IGContainerWatcher) GetSocketEnricher() *socketenricher.SocketEnricher {
	return ch.socketEnricher
}

func (ch *IGContainerWatcher) GetContainerSelector() *containercollection.ContainerSelector {
	return &ch.containerSelector
}

func (ch *IGContainerWatcher) RegisterCustomTracer(tracer containerwatcher.CustomTracer) error {
	for t := range ch.thirdPartyTracers.Iter() {
		if t.Name() == tracer.Name() {
			return fmt.Errorf("tracer with name %s already registered", tracer.Name())
		}
	}

	ch.thirdPartyTracers.Add(tracer)
	return nil
}

func (ch *IGContainerWatcher) UnregisterCustomTracer(tracer containerwatcher.CustomTracer) error {
	ch.thirdPartyTracers.Remove(tracer)
	return nil
}

func (ch *IGContainerWatcher) RegisterContainerReceiver(receiver containerwatcher.ContainerReceiver) {
	ch.thirdPartyContainerReceivers.Add(receiver)
}

func (ch *IGContainerWatcher) UnregisterContainerReceiver(receiver containerwatcher.ContainerReceiver) {
	ch.thirdPartyContainerReceivers.Remove(receiver)
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

func reportEventToThirdPartyTracers(eventType utils.EventType, event utils.K8sEvent, thirdPartyEventReceivers *maps.SafeMap[utils.EventType, mapset.Set[containerwatcher.EventReceiver]]) {
	if thirdPartyEventReceivers != nil && thirdPartyEventReceivers.Has(eventType) {
		for receiver := range thirdPartyEventReceivers.Get(eventType).Iter() {
			receiver.ReportEvent(eventType, event)
		}
	}
}
