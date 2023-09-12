package containerwatcher

import (
	"context"
	"fmt"
	"node-agent/pkg/config"
	"node-agent/pkg/containerwatcher"
	"node-agent/pkg/relevancymanager"
	"node-agent/pkg/utils"

	containercollection "github.com/inspektor-gadget/inspektor-gadget/pkg/container-collection"
	tracerseccomp "github.com/inspektor-gadget/inspektor-gadget/pkg/gadgets/advise/seccomp/tracer"
	tracercapabilities "github.com/inspektor-gadget/inspektor-gadget/pkg/gadgets/trace/capabilities/tracer"
	tracerexec "github.com/inspektor-gadget/inspektor-gadget/pkg/gadgets/trace/exec/tracer"
	traceropen "github.com/inspektor-gadget/inspektor-gadget/pkg/gadgets/trace/open/tracer"
	tracercollection "github.com/inspektor-gadget/inspektor-gadget/pkg/tracer-collection"
	"github.com/kubescape/go-logger"
	"github.com/kubescape/go-logger/helpers"
	"github.com/kubescape/k8s-interface/k8sinterface"
	"github.com/panjf2000/ants/v2"
)

const (
	capabilitiesTraceName = "trace_capabilities"
	execTraceName         = "trace_exec"
	openTraceName         = "trace_open"
)

type IGContainerWatcher struct {
	running bool
	// Configuration
	cfg               config.Config
	containerSelector containercollection.ContainerSelector
	ctx               context.Context
	// Clients
	k8sClient        *k8sinterface.KubernetesApi
	relevancyManager relevancymanager.RelevancyManagerClient
	// IG Collections
	containerCollection *containercollection.ContainerCollection
	tracerCollection    *tracercollection.TracerCollection
	// IG Tracers
	capabilitiesTracer *tracercapabilities.Tracer
	execTracer         *tracerexec.Tracer
	openTracer         *traceropen.Tracer
	syscallTracer      *tracerseccomp.Tracer
	// Worker pools
	capabilitiesWorkerPool *ants.PoolWithFunc
	execWorkerPool         *ants.PoolWithFunc
	openWorkerPool         *ants.PoolWithFunc
}

var _ containerwatcher.ContainerWatcher = (*IGContainerWatcher)(nil)

func CreateIGContainerWatcher(cfg config.Config, k8sClient *k8sinterface.KubernetesApi, relevancyManager relevancymanager.RelevancyManagerClient) (*IGContainerWatcher, error) {
	// Use container collection to get notified for new containers
	containerCollection := &containercollection.ContainerCollection{}
	// Create a tracer collection instance
	tracerCollection, err := tracercollection.NewTracerCollection(containerCollection)
	if err != nil {
		return nil, fmt.Errorf("creating tracer collection: %w", err)
	}
	// Create a capabilities worker pool
	capabilitiesWorkerPool, err := ants.NewPoolWithFunc(1, func(i interface{}) {
		s := i.([5]string)
		k8sContainerID := utils.CreateK8sContainerID(s[0], s[1], s[2])
		logger.L().Info("capability detected", helpers.String("k8sContainerID", k8sContainerID), helpers.String("syscall", s[3]), helpers.String("capability", s[4]))
	})
	if err != nil {
		return nil, fmt.Errorf("creating capabilities worker pool: %w", err)
	}
	// Create an exec worker pool
	execWorkerPool, err := ants.NewPoolWithFunc(2, func(i interface{}) {
		s := i.([4]string)
		relevancyManager.ReportFileAccess(s[0], s[1], s[2], s[3])
	})
	if err != nil {
		return nil, fmt.Errorf("creating exec worker pool: %w", err)
	}
	// Create an open worker pool
	openWorkerPool, err := ants.NewPoolWithFunc(8, func(i interface{}) {
		s := i.([4]string)
		relevancyManager.ReportFileAccess(s[0], s[1], s[2], s[3])
	})
	if err != nil {
		return nil, fmt.Errorf("creating open worker pool: %w", err)
	}

	return &IGContainerWatcher{
		// Configuration
		cfg:               cfg,
		containerSelector: containercollection.ContainerSelector{}, // Empty selector to get all containers
		// Clients
		k8sClient:        k8sClient,
		relevancyManager: relevancyManager,
		// IG Collections
		containerCollection: containerCollection,
		tracerCollection:    tracerCollection,
		// Worker pools
		capabilitiesWorkerPool: capabilitiesWorkerPool,
		execWorkerPool:         execWorkerPool,
		openWorkerPool:         openWorkerPool,
	}, nil
}

func (ch *IGContainerWatcher) PeekSyscallInContainer(nsMountId uint64) ([]string, error) {
	if ch == nil || !ch.running {
		return nil, fmt.Errorf("tracing not running")
	}
	return ch.syscallTracer.Peek(nsMountId)
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
