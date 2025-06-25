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
	"github.com/inspektor-gadget/inspektor-gadget/pkg/gadgets/top"
	toptracer "github.com/inspektor-gadget/inspektor-gadget/pkg/gadgets/top/ebpf/tracer"
	toptypes "github.com/inspektor-gadget/inspektor-gadget/pkg/gadgets/top/ebpf/types"
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
	"github.com/kubescape/node-agent/pkg/eventreporters/rulepolicy"
	"github.com/kubescape/node-agent/pkg/malwaremanager"
	"github.com/kubescape/node-agent/pkg/metricsmanager"
	"github.com/kubescape/node-agent/pkg/networkmanager"
	"github.com/kubescape/node-agent/pkg/networkstream"
	"github.com/kubescape/node-agent/pkg/objectcache"
	"github.com/kubescape/node-agent/pkg/processmanager"
	containerprocesstree "github.com/kubescape/node-agent/pkg/processtree/container"
	"github.com/kubescape/node-agent/pkg/processtree/feeder"
	rulebinding "github.com/kubescape/node-agent/pkg/rulebindingmanager"
	"github.com/kubescape/node-agent/pkg/rulemanager"
	"github.com/kubescape/node-agent/pkg/sbommanager"
	"github.com/kubescape/node-agent/pkg/utils"

	"github.com/kubescape/workerpool"
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
	topTraceName               = "trace_top"
	capabilitiesWorkerPoolSize = 1
	execWorkerPoolSize         = 2
	openWorkerPoolSize         = 8
	defaultWorkerPoolSize      = 2
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
	networkStreamClient       networkstream.NetworkStreamClient
	containerProcessTree      containerprocesstree.ContainerProcessTree

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
	topTracer          *toptracer.Tracer
	randomxTracer      *tracerandomx.Tracer
	symlinkTracer      *tracersymlink.Tracer
	hardlinkTracer     *tracerhardlink.Tracer
	sshTracer          *tracerssh.Tracer
	httpTracer         *tracerhttp.Tracer
	iouringTracer      *traceriouring.Tracer

	kubeIPInstance   operators.OperatorInstance
	kubeNameInstance operators.OperatorInstance
	// Third party tracers
	thirdPartyTracers mapset.Set[containerwatcher.CustomTracer]
	// Third party container receivers
	thirdPartyContainerReceivers mapset.Set[containerwatcher.ContainerReceiver]
	// Third party event enrichers
	thirdPartyEnricher containerwatcher.TaskBasedEnricher

	// Worker pools
	capabilitiesWorkerPool *ants.PoolWithFunc
	execWorkerPool         *ants.PoolWithFunc
	openWorkerPool         *ants.PoolWithFunc
	topWorkerPool          *ants.PoolWithFunc
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
	topWorkerChan          chan *top.Event[toptypes.Stats]
	ptraceWorkerChan       chan *tracerptracetype.Event
	networkWorkerChan      chan *tracernetworktype.Event
	dnsWorkerChan          chan *tracerdnstype.Event
	randomxWorkerChan      chan *tracerandomxtype.Event
	symlinkWorkerChan      chan *tracersymlinktype.Event
	hardlinkWorkerChan     chan *tracerhardlinktype.Event
	sshWorkerChan          chan *tracersshtype.Event
	httpWorkerChan         chan *tracerhttptype.Event
	iouringWorkerChan      chan *traceriouringtype.Event

	callbacks       []containercollection.FuncNotify
	pool            *workerpool.WorkerPool
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

func CreateIGContainerWatcher(cfg config.Config,
	applicationProfileManager applicationprofilemanager.ApplicationProfileManagerClient, k8sClient *k8sinterface.KubernetesApi,
	igK8sClient *containercollection.K8sClient, networkManagerClient networkmanager.NetworkManagerClient,
	dnsManagerClient dnsmanager.DNSManagerClient, metrics metricsmanager.MetricsManager, ruleManager rulemanager.RuleManagerClient,
	malwareManager malwaremanager.MalwareManagerClient, sbomManager sbommanager.SbomManagerClient,
	ruleBindingPodNotify *chan rulebinding.RuleBindingNotify, runtime *containerutilsTypes.RuntimeConfig,
	thirdPartyEventReceivers *maps.SafeMap[utils.EventType, mapset.Set[containerwatcher.EventReceiver]],
	thirdPartyEnricher containerwatcher.TaskBasedEnricher, processManager processmanager.ProcessManagerClient,
	clusterName string, objectCache objectcache.ObjectCache, networkStreamClient networkstream.NetworkStreamClient,
	containerProcessTree containerprocesstree.ContainerProcessTree, processTreeFeeder *feeder.EventFeeder) (*IGContainerWatcher, error) { // Use container collection to get notified for new containers

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

		if cfg.IgnoreContainer(event.GetNamespace(), event.GetPod(), event.K8s.PodLabels) {
			return
		}

		metrics.ReportEvent(utils.CapabilitiesEventType)
		k8sContainerID := utils.CreateK8sContainerID(event.K8s.Namespace, event.K8s.PodName, event.Runtime.ContainerID)
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

		path := event.Comm
		if len(event.Args) > 0 {
			path = event.Args[0]
		}

		if path == "" {
			return
		}

		// ignore events with empty container name
		if event.K8s.ContainerName == "" {
			return
		}

		if cfg.IgnoreContainer(event.GetNamespace(), event.GetPod(), event.K8s.PodLabels) {
			return
		}

		k8sContainerID := utils.CreateK8sContainerID(event.K8s.Namespace, event.K8s.PodName, event.Runtime.ContainerID)

		if isDroppedEvent(event.Type, event.Message) {
			applicationProfileManager.ReportDroppedEvent(k8sContainerID)
			return
		}

		// ProcessManager must be notified before the event is reported to the other managers.
		processManager.ReportEvent(utils.ExecveEventType, &event)

		processTreeFeeder.ReportEvent(utils.ExecveEventType, &event)

		ruleManager.ReportEvent(utils.ExecveEventType, &event)
		malwareManager.ReportEvent(utils.ExecveEventType, &event)
		metrics.ReportEvent(utils.ExecveEventType)
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

		if cfg.IgnoreContainer(event.GetNamespace(), event.GetPod(), event.K8s.PodLabels) {
			return
		}

		k8sContainerID := utils.CreateK8sContainerID(event.K8s.Namespace, event.K8s.PodName, event.Runtime.ContainerID)

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

		if cfg.IgnoreContainer(event.GetNamespace(), event.GetPod(), event.K8s.PodLabels) {
			return
		}
		k8sContainerID := utils.CreateK8sContainerID(event.K8s.Namespace, event.K8s.PodName, event.Runtime.ContainerID)

		if isDroppedEvent(event.Type, event.Message) {
			networkManagerClient.ReportDroppedEvent(k8sContainerID)
			return
		}
		metrics.ReportEvent(utils.NetworkEventType)
		networkManagerClient.ReportNetworkEvent(k8sContainerID, event)
		ruleManager.ReportEvent(utils.NetworkEventType, &event)
		networkStreamClient.ReportEvent(utils.NetworkEventType, &event)

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

		if cfg.IgnoreContainer(event.GetNamespace(), event.GetPod(), event.K8s.PodLabels) {
			return
		}

		metrics.ReportEvent(utils.DnsEventType)
		dnsManagerClient.ReportEvent(event)
		ruleManager.ReportEvent(utils.DnsEventType, &event)
		networkStreamClient.ReportEvent(utils.DnsEventType, &event)

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

		if cfg.IgnoreContainer(event.GetNamespace(), event.GetPod(), event.K8s.PodLabels) {
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
		if cfg.IgnoreContainer(event.GetNamespace(), event.GetPod(), event.K8s.PodLabels) {
			return
		}
		k8sContainerID := utils.CreateK8sContainerID(event.K8s.Namespace, event.K8s.PodName, event.Runtime.ContainerID)

		metrics.ReportEvent(utils.SymlinkEventType)
		applicationProfileManager.ReportSymlinkEvent(k8sContainerID, &event)
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
		if cfg.IgnoreContainer(event.GetNamespace(), event.GetPod(), event.K8s.PodLabels) {
			return
		}

		k8sContainerID := utils.CreateK8sContainerID(event.K8s.Namespace, event.K8s.PodName, event.Runtime.ContainerID)

		metrics.ReportEvent(utils.HardlinkEventType)
		applicationProfileManager.ReportHardlinkEvent(k8sContainerID, &event)
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
		if cfg.IgnoreContainer(event.GetNamespace(), event.GetPod(), event.K8s.PodLabels) {
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
		if cfg.IgnoreContainer(event.GetNamespace(), event.GetPod(), event.K8s.PodLabels) {
			return
		}

		k8sContainerID := utils.CreateK8sContainerID(event.K8s.Namespace, event.K8s.PodName, event.Runtime.ContainerID)

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
	ptraceWorkerPool, err := ants.NewPoolWithFunc(defaultWorkerPoolSize, func(i interface{}) {
		event := i.(tracerptracetype.Event)
		if event.K8s.ContainerName == "" {
			return
		}
		if cfg.IgnoreContainer(event.GetNamespace(), event.GetPod(), event.K8s.PodLabels) {
			return
		}
		ruleManager.ReportEvent(utils.PtraceEventType, &event)
	})

	if err != nil {
		return nil, fmt.Errorf("creating ptrace worker pool: %w", err)
	}

	// Create a ebpf top worker pool
	ebpftopWorkerPool, err := ants.NewPoolWithFunc(defaultWorkerPoolSize, func(i interface{}) {
		event := i.(top.Event[toptypes.Stats])
		metrics.ReportEbpfStats(&event)
	})
	if err != nil {
		return nil, fmt.Errorf("creating ebpftop worker pool: %w", err)
	}

	// Create a iouring worker pool
	iouringWorkerPool, err := ants.NewPoolWithFunc(defaultWorkerPoolSize, func(i interface{}) {
		event := i.(traceriouringtype.Event)
		if event.K8s.ContainerName == "" {
			return
		}
		if cfg.IgnoreContainer(event.GetNamespace(), event.GetPod(), event.K8s.PodLabels) {
			return
		}

		k8sContainerID := utils.CreateK8sContainerID(event.K8s.Namespace, event.K8s.PodName, event.Runtime.ContainerID)

		if isDroppedEvent(event.Type, event.Message) {
			applicationProfileManager.ReportDroppedEvent(k8sContainerID)
			return
		}

		ruleManager.ReportEvent(utils.IoUringEventType, &event)
		rulePolicyReporter.ReportEvent(utils.IoUringEventType, &event, k8sContainerID, event.Identifier)
	})

	if err != nil {
		return nil, fmt.Errorf("creating iouring worker pool: %w", err)
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
		networkStreamClient:       networkStreamClient,
		containerProcessTree:      containerProcessTree,

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
		topWorkerPool:          ebpftopWorkerPool,
		iouringWorkerPool:      iouringWorkerPool,
		metrics:                metrics,

		// Channels
		capabilitiesWorkerChan: make(chan *tracercapabilitiestype.Event, 1000),
		execWorkerChan:         make(chan *events.ExecEvent, 10000),
		openWorkerChan:         make(chan *events.OpenEvent, 500000),
		topWorkerChan:          make(chan *top.Event[toptypes.Stats], 1000),
		ptraceWorkerChan:       make(chan *tracerptracetype.Event, 1000),
		networkWorkerChan:      make(chan *tracernetworktype.Event, 500000),
		dnsWorkerChan:          make(chan *tracerdnstype.Event, 100000),
		randomxWorkerChan:      make(chan *tracerandomxtype.Event, 5000),
		symlinkWorkerChan:      make(chan *tracersymlinktype.Event, 1000),
		hardlinkWorkerChan:     make(chan *tracerhardlinktype.Event, 1000),
		sshWorkerChan:          make(chan *tracersshtype.Event, 1000),
		httpWorkerChan:         make(chan *tracerhttptype.Event, 500000),
		iouringWorkerChan:      make(chan *traceriouringtype.Event, 5000),

		// cache
		ruleBindingPodNotify:         ruleBindingPodNotify,
		ruleManagedPods:              mapset.NewSet[string](),
		runtime:                      runtime,
		thirdPartyTracers:            mapset.NewSet[containerwatcher.CustomTracer](),
		thirdPartyContainerReceivers: mapset.NewSet[containerwatcher.ContainerReceiver](),
		thirdPartyEnricher:           thirdPartyEnricher,
		processManager:               processManager,
		pool:                         workerpool.NewWithMaxRunningTime(cfg.WorkerPoolSize, 30*time.Second),
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
		var err error

		logger.L().TimedWrapper(utils.FuncName(ch.startContainerCollection), 5*time.Second, func() {
			err = ch.startContainerCollection(ctx)
		})
		if err != nil {
			return fmt.Errorf("setting up container collection: %w", err)
		}

		// We want to populate the initial processes before starting the tracers but after retrieving the shims.
		logger.L().TimedWrapper(utils.FuncName(ch.processManager.PopulateInitialProcesses), 5*time.Second, func() {
			err = ch.processManager.PopulateInitialProcesses()
		})
		if err != nil {
			ch.stopContainerCollection()
			return fmt.Errorf("populating initial processes: %w", err)
		}

		logger.L().TimedWrapper(utils.FuncName(ch.startTracers), 10*time.Second, func() {
			err = ch.startTracers()
		})
		if err != nil {
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

func (ch *IGContainerWatcher) handleEvent(event utils.EnrichEvent, syscalls []uint64, callback containerwatcher.ResultCallback) {
	if ch.thirdPartyEnricher != nil && !reflect.ValueOf(ch.thirdPartyEnricher).IsNil() {
		ch.thirdPartyEnricher.SubmitEnrichmentTask(event, syscalls, callback)
	} else {
		callback(event)
	}
}

func reportEventToThirdPartyTracers(eventType utils.EventType, event utils.K8sEvent, thirdPartyEventReceivers *maps.SafeMap[utils.EventType, mapset.Set[containerwatcher.EventReceiver]]) {
	if thirdPartyEventReceivers != nil && thirdPartyEventReceivers.Has(eventType) {
		for receiver := range thirdPartyEventReceivers.Get(eventType).Iter() {
			receiver.ReportEvent(eventType, event)
		}
	}
}
