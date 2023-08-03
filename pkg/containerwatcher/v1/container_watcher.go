package containerwatcher

import (
	"context"
	"fmt"
	"node-agent/pkg/config"
	"node-agent/pkg/containerwatcher"
	"node-agent/pkg/relevancymanager"
	"os"
	"time"

	containercollection "github.com/inspektor-gadget/inspektor-gadget/pkg/container-collection"
	tracerexec "github.com/inspektor-gadget/inspektor-gadget/pkg/gadgets/trace/exec/tracer"
	tracerexectype "github.com/inspektor-gadget/inspektor-gadget/pkg/gadgets/trace/exec/types"
	traceropen "github.com/inspektor-gadget/inspektor-gadget/pkg/gadgets/trace/open/tracer"
	traceropentype "github.com/inspektor-gadget/inspektor-gadget/pkg/gadgets/trace/open/types"
	tracercollection "github.com/inspektor-gadget/inspektor-gadget/pkg/tracer-collection"
	"github.com/inspektor-gadget/inspektor-gadget/pkg/types"
	"github.com/kubescape/go-logger"
	"github.com/kubescape/go-logger/helpers"
	"github.com/kubescape/k8s-interface/k8sinterface"
)

const (
	execTraceName = "trace_exec"
	openTraceName = "trace_open"
)

type IGContainerWatcher struct {
	cfg                 config.Config
	containerCollection *containercollection.ContainerCollection
	k8sClient           *k8sinterface.KubernetesApi
	relevancyManager    relevancymanager.RelevancyManagerClient
	tracerCollection    *tracercollection.TracerCollection
	tracerExec          *tracerexec.Tracer
	tracerOpen          *traceropen.Tracer
}

var _ containerwatcher.ContainerWatcher = (*IGContainerWatcher)(nil)

func CreateIGContainerWatcher(cfg config.Config, k8sClient *k8sinterface.KubernetesApi, relevancyManager relevancymanager.RelevancyManagerClient) (*IGContainerWatcher, error) {
	// Use container collection to get notified for new containers
	containerCollection := &containercollection.ContainerCollection{}
	// Create a tracer collection instance
	tracerCollection, err := tracercollection.NewTracerCollection(containerCollection)
	if err != nil {
		return nil, fmt.Errorf("failed to create trace-collection: %s\n", err)
	}

	return &IGContainerWatcher{
		cfg:                 cfg,
		containerCollection: containerCollection,
		k8sClient:           k8sClient,
		tracerCollection:    tracerCollection,
		relevancyManager:    relevancyManager,
	}, nil
}

func (ch *IGContainerWatcher) Start(ctx context.Context) error {

	ch.relevancyManager.SetContainerHandler(ch)
	ch.relevancyManager.StartRelevancyManager(ctx)

	callback := func(notif containercollection.PubSubEvent) {
		logger.L().Debug("GetEventCallback", helpers.String("namespace", notif.Container.K8s.Namespace), helpers.String("Pod name", notif.Container.K8s.PodName), helpers.String("ContainerID", notif.Container.Runtime.ContainerID), helpers.String("Container name", notif.Container.K8s.ContainerName), helpers.String("type", notif.Type.String()))
		switch notif.Type {
		case containercollection.EventTypeAddContainer:
			logger.L().Debug("container has started", helpers.String("namespace", notif.Container.K8s.Namespace), helpers.String("Pod name", notif.Container.K8s.PodName), helpers.String("ContainerID", notif.Container.Runtime.ContainerID), helpers.String("Container name", notif.Container.K8s.ContainerName))
			// notify the relevancy manager that a new container has started
			ch.relevancyManager.ReportContainerStarted(ctx, notif.Container)
		case containercollection.EventTypeRemoveContainer:
			logger.L().Debug("container has Terminated", helpers.String("namespace", notif.Container.K8s.Namespace), helpers.String("Pod name", notif.Container.K8s.PodName), helpers.String("ContainerID", notif.Container.Runtime.ContainerID), helpers.String("Container name", notif.Container.K8s.ContainerName))
			// notify the relevancy manager that a container has terminated
			ch.relevancyManager.ReportContainerTerminated(ctx, notif.Container)
		}
	}
	containerEventFuncs := []containercollection.FuncNotify{callback}

	// Define the different options for the container collection instance
	opts := []containercollection.ContainerCollectionOption{
		containercollection.WithTracerCollection(ch.tracerCollection),

		// Get containers created with runc
		containercollection.WithRuncFanotify(),

		// Get containers created with docker
		containercollection.WithCgroupEnrichment(),

		// Enrich events with Linux namespaces information, it is needed for per container filtering
		containercollection.WithLinuxNamespaceEnrichment(),

		// Enrich those containers with data from the Kubernetes API
		containercollection.WithKubernetesEnrichment(os.Getenv(config.NodeNameEnvVar), ch.k8sClient.K8SConfig),

		// Get Notifications from the container collection
		containercollection.WithPubSub(containerEventFuncs...),
	}

	// Initialize the container collection
	if err := ch.containerCollection.Initialize(opts...); err != nil {
		return fmt.Errorf("failed to initialize container collection: %s\n", err)
	}

	// Empty selector to get all containers
	containerSelector := containercollection.ContainerSelector{}

	// Define a callback to handle exec events
	execEventCallback := func(event *tracerexectype.Event) {
		if event.Type != types.NORMAL {
			// dropped event
			logger.L().Ctx(ctx).Warning("container monitoring got drop events - we may miss some realtime data", helpers.Interface("event", event), helpers.String("error", event.Message))
			return
		}
		if event.Retval > -1 {
			procImageName := event.Comm
			if len(event.Args) > 0 {
				procImageName = event.Args[0]
			}
			ch.relevancyManager.ReportFileAccess(ctx, event.K8s.Namespace, event.K8s.PodName, event.K8s.ContainerName, procImageName)
		}
	}
	if err := ch.tracerCollection.AddTracer(execTraceName, containerSelector); err != nil {
		return fmt.Errorf("error adding exec tracer: %s\n", err)
	}

	// Define a callback to handle open events
	openEventCallback := func(event *traceropentype.Event) {
		if event.Type != types.NORMAL {
			// dropped event
			logger.L().Ctx(ctx).Warning("container monitoring got drop events - we may miss some realtime data", helpers.Interface("event", event), helpers.String("error", event.Message))
			return
		}
		if event.Ret > -1 {
			ch.relevancyManager.ReportFileAccess(ctx, event.K8s.Namespace, event.K8s.PodName, event.K8s.ContainerName, event.Path)
		}
	}
	if err := ch.tracerCollection.AddTracer(openTraceName, containerSelector); err != nil {
		return fmt.Errorf("error adding open tracer: %s\n", err)
	}

	// Get mount namespace map to filter by containers
	execMountnsmap, err := ch.tracerCollection.TracerMountNsMap(execTraceName)
	if err != nil {
		return fmt.Errorf("failed to get execMountnsmap: %s\n", err)
	}

	// Get mount namespace map to filter by containers
	openMountnsmap, err := ch.tracerCollection.TracerMountNsMap(openTraceName)
	if err != nil {
		return fmt.Errorf("failed to get openMountnsmap: %s\n", err)
	}

	// Create the exec tracer
	ch.tracerExec, err = tracerexec.NewTracer(&tracerexec.Config{MountnsMap: execMountnsmap}, ch.containerCollection, execEventCallback)
	if err != nil {
		return fmt.Errorf("error creating tracerExec: %s\n", err)
	}

	// Create the open tracer
	ch.tracerOpen, err = traceropen.NewTracer(&traceropen.Config{MountnsMap: openMountnsmap, FullPath: ch.cfg.EnableFullPathTracing}, ch.containerCollection, openEventCallback)
	if err != nil {
		return fmt.Errorf("error creating tracerOpen: %s\n", err)
	}

	logger.L().Info("main container handler started")

	return nil
}

//lint:ignore U1000 Ignore unused function temporarily for debugging
func (ch *IGContainerWatcher) printNsMap(id string) {
	nsMap, _ := ch.tracerCollection.TracerMountNsMap(id)
	var (
		key     string
		value   uint32
		entries = nsMap.Iterate()
	)
	for entries.Next(&key, &value) { // Order of keys is non-deterministic due to randomized map seed
		logger.L().Debug("map entry", helpers.String("key", key), helpers.Int("value", int(value)))
	}
}

func (ch *IGContainerWatcher) Stop() {
	ch.containerCollection.Close()
	ch.tracerExec.Stop()
	_ = ch.tracerCollection.RemoveTracer(execTraceName)
	ch.tracerOpen.Stop()
	_ = ch.tracerCollection.RemoveTracer(openTraceName)
	ch.tracerCollection.Close()
}

func (ch *IGContainerWatcher) UnregisterContainer(container *containercollection.Container) {

	event := containercollection.PubSubEvent{
		Timestamp: time.Now().Format(time.RFC3339),
		Type:      containercollection.EventTypeRemoveContainer,
		Container: container,
	}
	ch.tracerCollection.TracerMapsUpdater()(event)
}
