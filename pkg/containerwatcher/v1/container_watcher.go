package containerwatcher

import (
	"context"
	"fmt"
	"node-agent/pkg/applicationprofilemanager"
	"node-agent/pkg/config"
	"node-agent/pkg/containerwatcher"
	"node-agent/pkg/networkmanager"
	"node-agent/pkg/relevancymanager"
	"node-agent/pkg/utils"

	containercollection "github.com/inspektor-gadget/inspektor-gadget/pkg/container-collection"
	tracerseccomp "github.com/inspektor-gadget/inspektor-gadget/pkg/gadgets/advise/seccomp/tracer"
	tracercapabilities "github.com/inspektor-gadget/inspektor-gadget/pkg/gadgets/trace/capabilities/tracer"
	tracercapabilitiestype "github.com/inspektor-gadget/inspektor-gadget/pkg/gadgets/trace/capabilities/types"
	tracerexec "github.com/inspektor-gadget/inspektor-gadget/pkg/gadgets/trace/exec/tracer"
	tracerexectype "github.com/inspektor-gadget/inspektor-gadget/pkg/gadgets/trace/exec/types"
	tracernetwork "github.com/inspektor-gadget/inspektor-gadget/pkg/gadgets/trace/network/tracer"
	tracernetworktype "github.com/inspektor-gadget/inspektor-gadget/pkg/gadgets/trace/network/types"
	traceropen "github.com/inspektor-gadget/inspektor-gadget/pkg/gadgets/trace/open/tracer"
	traceropentype "github.com/inspektor-gadget/inspektor-gadget/pkg/gadgets/trace/open/types"
	"github.com/inspektor-gadget/inspektor-gadget/pkg/operators"
	tracercollection "github.com/inspektor-gadget/inspektor-gadget/pkg/tracer-collection"
	"github.com/kubescape/go-logger"
	"github.com/kubescape/go-logger/helpers"
	"github.com/kubescape/k8s-interface/k8sinterface"
	"github.com/panjf2000/ants/v2"
)

const (
	capabilitiesTraceName      = "trace_capabilities"
	execTraceName              = "trace_exec"
	networkTraceName           = "trace_network"
	openTraceName              = "trace_open"
	capabilitiesWorkerPoolSize = 1
	execWorkerPoolSize         = 2
	openWorkerPoolSize         = 8
	networkWorkerPoolSize      = 1
)

type IGContainerWatcher struct {
	running bool
	// Configuration
	cfg               config.Config
	containerSelector containercollection.ContainerSelector
	ctx               context.Context
	// Clients
	applicationProfileManager applicationprofilemanager.ApplicationProfileManagerClient
	k8sClient                 *k8sinterface.KubernetesApi
	relevancyManager          relevancymanager.RelevancyManagerClient
	networkManager            networkmanager.NetworkManagerClient
	// IG Collections
	containerCollection *containercollection.ContainerCollection
	tracerCollection    *tracercollection.TracerCollection
	// IG Tracers
	capabilitiesTracer *tracercapabilities.Tracer
	execTracer         *tracerexec.Tracer
	openTracer         *traceropen.Tracer
	syscallTracer      *tracerseccomp.Tracer
	networkTracer      *tracernetwork.Tracer
	kubeIPInstance     operators.OperatorInstance
	kubeNameInstance   operators.OperatorInstance
	// Worker pools
	capabilitiesWorkerPool *ants.PoolWithFunc
	execWorkerPool         *ants.PoolWithFunc
	openWorkerPool         *ants.PoolWithFunc
	networkWorkerPool      *ants.PoolWithFunc
}

var _ containerwatcher.ContainerWatcher = (*IGContainerWatcher)(nil)

func CreateIGContainerWatcher(cfg config.Config, applicationProfileManager applicationprofilemanager.ApplicationProfileManagerClient, k8sClient *k8sinterface.KubernetesApi, relevancyManager relevancymanager.RelevancyManagerClient, networkManagerClient networkmanager.NetworkManagerClient) (*IGContainerWatcher, error) {
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
		k8sContainerID := utils.CreateK8sContainerID(event.K8s.Namespace, event.K8s.PodName, event.K8s.ContainerName)
		applicationProfileManager.ReportCapability(k8sContainerID, event.CapName)
	})
	if err != nil {
		return nil, fmt.Errorf("creating capabilities worker pool: %w", err)
	}
	// Create an exec worker pool
	execWorkerPool, err := ants.NewPoolWithFunc(execWorkerPoolSize, func(i interface{}) {
		event := i.(tracerexectype.Event)
		k8sContainerID := utils.CreateK8sContainerID(event.K8s.Namespace, event.K8s.PodName, event.K8s.ContainerName)
		path := event.Comm
		if len(event.Args) > 0 {
			path = event.Args[0]
		}
		applicationProfileManager.ReportFileExec(k8sContainerID, path, event.Args)
		relevancyManager.ReportFileAccess(k8sContainerID, path)
	})
	if err != nil {
		return nil, fmt.Errorf("creating exec worker pool: %w", err)
	}

	// Create an open worker pool
	openWorkerPool, err := ants.NewPoolWithFunc(openWorkerPoolSize, func(i interface{}) {
		event := i.(traceropentype.Event)
		k8sContainerID := utils.CreateK8sContainerID(event.K8s.Namespace, event.K8s.PodName, event.K8s.ContainerName)
		path := event.Path
		if cfg.EnableFullPathTracing {
			path = event.FullPath
		}
		applicationProfileManager.ReportFileOpen(k8sContainerID, path, event.Flags)
		relevancyManager.ReportFileAccess(k8sContainerID, path)
	})
	if err != nil {
		return nil, fmt.Errorf("creating open worker pool: %w", err)
	}

	// Create a network worker pool
	networkWorkerPool, err := ants.NewPoolWithFunc(networkWorkerPoolSize, func(i interface{}) {
		event := i.(tracernetworktype.Event)

		k8sContainerID := utils.CreateK8sContainerID(event.K8s.Namespace, event.K8s.PodName, event.K8s.ContainerName)

		if k8sContainerID == "//" {
			logger.L().Debug("k8sContainerID is empty in network event", helpers.String("namespace", event.K8s.Namespace), helpers.String("podName", event.K8s.PodName), helpers.String("containerName", event.K8s.ContainerName))
			return
		}

		networkManagerClient.SaveNetworkEvent(event.Runtime.ContainerID, event.K8s.PodName, event)
	})

	if err != nil {
		return nil, fmt.Errorf("creating open network pool: %w", err)
	}

	return &IGContainerWatcher{
		// Configuration
		cfg:               cfg,
		containerSelector: containercollection.ContainerSelector{}, // Empty selector to get all containers
		// Clients
		applicationProfileManager: applicationProfileManager,
		k8sClient:                 k8sClient,
		relevancyManager:          relevancyManager,
		networkManager:            networkManagerClient,
		// IG Collections
		containerCollection: containerCollection,
		tracerCollection:    tracerCollection,
		// Worker pools
		capabilitiesWorkerPool: capabilitiesWorkerPool,
		execWorkerPool:         execWorkerPool,
		openWorkerPool:         openWorkerPool,
		networkWorkerPool:      networkWorkerPool,
	}, nil
}

func (ch *IGContainerWatcher) Start(ctx context.Context) error {
	if !ch.running {
		err := ch.startContainerCollection(ctx)
		if err != nil {
			return fmt.Errorf("setting up container collection: %w", err)
		}
		err = ch.startTracers()
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
			logger.L().Ctx(ch.ctx).Warning("error stopping app behavior tracing", helpers.Error(err))
		}
		ch.running = false
	}
}
