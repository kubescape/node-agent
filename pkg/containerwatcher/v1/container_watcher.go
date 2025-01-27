package containerwatcher

import (
	"context"
	"fmt"
	"reflect"
	"time"

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
	tracernetwork "github.com/inspektor-gadget/inspektor-gadget/pkg/gadgets/trace/network/tracer"
	tracernetworktype "github.com/inspektor-gadget/inspektor-gadget/pkg/gadgets/trace/network/types"
	traceropen "github.com/inspektor-gadget/inspektor-gadget/pkg/gadgets/trace/open/tracer"
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
	"github.com/kubescape/node-agent/pkg/ebpf/events"
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
	"github.com/kubescape/node-agent/pkg/eventreporters/rulepolicy"
	"github.com/kubescape/node-agent/pkg/malwaremanager"
	"github.com/kubescape/node-agent/pkg/metricsmanager"
	"github.com/kubescape/node-agent/pkg/networkmanager"
	"github.com/kubescape/node-agent/pkg/objectcache"
	"github.com/kubescape/node-agent/pkg/processmanager"
	rulebinding "github.com/kubescape/node-agent/pkg/rulebindingmanager"
	"github.com/kubescape/node-agent/pkg/rulemanager"
	"github.com/kubescape/node-agent/pkg/sbommanager"
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
	podName           string
	namespace         string
	clusterName       string
	agentStartTime    time.Time

	// Clients
	applicationProfileManager applicationprofilemanager.ApplicationProfileManagerClient
	igK8sClient               *containercollection.K8sClient
	k8sClient                 *k8sinterface.KubernetesApi
	networkManager            networkmanager.NetworkManagerClient
	dnsManager                dnsmanager.DNSManagerClient
	ruleManager               rulemanager.RuleManagerClient
	malwareManager            malwaremanager.MalwareManagerClient
	sbomManager               sbommanager.SbomManagerClient
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
	// Third party event enrichers
	thirdPartyEnricher containerwatcher.ThirdPartyEnricher

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

	objectCache     objectcache.ObjectCache
	ruleManagedPods mapset.Set[string] // list of pods to track based on rules
	metrics         metricsmanager.MetricsManager
	// cache
	ruleBindingPodNotify *chan rulebinding.RuleBindingNotify
	// container runtime
	runtime *containerutilsTypes.RuntimeConfig
	// process manager
	processManager processmanager.ProcessManagerClient
}

var _ containerwatcher.ContainerWatcher = (*IGContainerWatcher)(nil)

func CreateIGContainerWatcher(cfg config.Config, applicationProfileManager applicationprofilemanager.ApplicationProfileManagerClient, k8sClient *k8sinterface.KubernetesApi, igK8sClient *containercollection.K8sClient, networkManagerClient networkmanager.NetworkManagerClient, dnsManagerClient dnsmanager.DNSManagerClient, metrics metricsmanager.MetricsManager, ruleManager rulemanager.RuleManagerClient, malwareManager malwaremanager.MalwareManagerClient, sbomManager sbommanager.SbomManagerClient, ruleBindingPodNotify *chan rulebinding.RuleBindingNotify, runtime *containerutilsTypes.RuntimeConfig, thirdPartyEventReceivers *maps.SafeMap[utils.EventType, mapset.Set[containerwatcher.EventReceiver]], thirdPartyEnricher containerwatcher.ThirdPartyEnricher, processManager processmanager.ProcessManagerClient, clusterName string, objectCache objectcache.ObjectCache) (*IGContainerWatcher, error) { // Use container collection to get notified for new containers
	containerCollection := &containercollection.ContainerCollection{}
	// Create a tracer collection instance
	tracerCollection, err := tracercollection.NewTracerCollection(containerCollection)
	if err != nil {
		return nil, fmt.Errorf("creating tracer collection: %w", err)
	}

	rulePolicyReporter := rulepolicy.NewRulePolicyReporter(ruleManager, applicationProfileManager)

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
		event := i.(events.ExecEvent)
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

		if path == "" {
			return
		}

		ruleManager.ReportEvent(utils.ExecveEventType, &event)
		malwareManager.ReportEvent(utils.ExecveEventType, &event)

		metrics.ReportEvent(utils.ExecveEventType)
		processManager.ReportEvent(utils.ExecveEventType, &event)
		applicationProfileManager.ReportFileExec(k8sContainerID, event)
		rulePolicyReporter.ReportEvent(utils.ExecveEventType, &event, k8sContainerID, event.Comm)

		// Report exec events to event receivers
		reportEventToThirdPartyTracers(utils.ExecveEventType, &event, thirdPartyEventReceivers)
	})
	if err != nil {
		return nil, fmt.Errorf("creating exec worker pool: %w", err)
	}
	// Create an open worker pool
	openWorkerPool, err := ants.NewPoolWithFunc(openWorkerPoolSize, func(i interface{}) {
		event := i.(events.OpenEvent)
		// ignore events with empty container name
		if event.K8s.ContainerName == "" {
			return
		}
		k8sContainerID := utils.CreateK8sContainerID(event.K8s.Namespace, event.K8s.PodName, event.K8s.ContainerName)

		if isDroppedEvent(event.Type, event.Message) {
			applicationProfileManager.ReportDroppedEvent(k8sContainerID)
			return
		}

		if cfg.EnableFullPathTracing {
			event.Path = event.FullPath
		}

		metrics.ReportEvent(utils.OpenEventType)
		applicationProfileManager.ReportFileOpen(k8sContainerID, event)
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
		dnsManagerClient.ReportEvent(event)
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
		k8sContainerID := utils.CreateK8sContainerID(event.K8s.Namespace, event.K8s.PodName, event.K8s.ContainerName)

		metrics.ReportEvent(utils.SymlinkEventType)
		ruleManager.ReportEvent(utils.SymlinkEventType, &event)
		rulePolicyReporter.ReportEvent(utils.SymlinkEventType, &event, k8sContainerID, event.Comm)
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

		k8sContainerID := utils.CreateK8sContainerID(event.K8s.Namespace, event.K8s.PodName, event.K8s.ContainerName)

		metrics.ReportEvent(utils.HardlinkEventType)
		ruleManager.ReportEvent(utils.HardlinkEventType, &event)
		rulePolicyReporter.ReportEvent(utils.HardlinkEventType, &event, k8sContainerID, event.Comm)
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
		ruleManager.ReportEvent(utils.HTTPEventType, &event)

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
		clusterName:       clusterName,
		agentStartTime:    time.Now(),

		// Clients
		applicationProfileManager: applicationProfileManager,
		igK8sClient:               igK8sClient,
		k8sClient:                 k8sClient,
		networkManager:            networkManagerClient,
		dnsManager:                dnsManagerClient,
		ruleManager:               ruleManager,
		malwareManager:            malwareManager,
		sbomManager:               sbomManager,
		// IG Collections
		containerCollection: containerCollection,
		tracerCollection:    tracerCollection,
		// Worker pools
		capabilitiesWorkerPool: capabilitiesWorkerPool,
		execWorkerPool:         execWorkerPool,
		openWorkerPool:         openWorkerPool,
		networkWorkerPool:      networkWorkerPool,
		dnsWorkerPool:          dnsWorkerPool,
		randomxWorkerPool:      randomxWorkerPool,
		symlinkWorkerPool:      symlinkWorkerPool,
		hardlinkWorkerPool:     hardlinkWorkerPool,
		sshdWorkerPool:         sshWorkerPool,
		httpWorkerPool:         httpWorkerPool,
		ptraceWorkerPool:       ptraceWorkerPool,
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

		// cache
		ruleBindingPodNotify:         ruleBindingPodNotify,
		ruleManagedPods:              mapset.NewSet[string](),
		runtime:                      runtime,
		thirdPartyTracers:            mapset.NewSet[containerwatcher.CustomTracer](),
		thirdPartyContainerReceivers: mapset.NewSet[containerwatcher.ContainerReceiver](),
		thirdPartyEnricher:           thirdPartyEnricher,
		processManager:               processManager,
		objectCache:                  objectCache,
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

		// We want to populate the initial processes before starting the tracers but after retrieving the shims.
		if err := ch.processManager.PopulateInitialProcesses(); err != nil {
			ch.stopContainerCollection()
			return fmt.Errorf("populating initial processes: %w", err)
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
			logger.L().Ctx(ch.ctx).Error("stopping app behavior tracing", helpers.Error(err))
		}
		ch.running = false
	}
}

func (ch *IGContainerWatcher) Ready() bool {
	return ch.running
}

func (ch *IGContainerWatcher) enrichEvent(event utils.EnrichEvent, syscalls []uint64) {
	if ch.thirdPartyEnricher != nil && !reflect.ValueOf(ch.thirdPartyEnricher).IsNil() {
		ch.thirdPartyEnricher.Enrich(event, syscalls)
	}
}

func reportEventToThirdPartyTracers(eventType utils.EventType, event utils.K8sEvent, thirdPartyEventReceivers *maps.SafeMap[utils.EventType, mapset.Set[containerwatcher.EventReceiver]]) {
	if thirdPartyEventReceivers != nil && thirdPartyEventReceivers.Has(eventType) {
		for receiver := range thirdPartyEventReceivers.Get(eventType).Iter() {
			receiver.ReportEvent(eventType, event)
		}
	}
}
