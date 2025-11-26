package containerwatcher

import (
	"context"
	"fmt"
	"time"

	containercollection "github.com/inspektor-gadget/inspektor-gadget/pkg/container-collection"
	"github.com/inspektor-gadget/inspektor-gadget/pkg/operators/socketenricher"
	"github.com/inspektor-gadget/inspektor-gadget/pkg/params"
	"github.com/inspektor-gadget/inspektor-gadget/pkg/utils/host"
	"github.com/kubescape/go-logger"
	"github.com/kubescape/go-logger/helpers"
	"github.com/kubescape/node-agent/pkg/rulebindingmanager"
	"github.com/kubescape/node-agent/pkg/utils"
)

// StartContainerCollection starts the container collection
func (cw *ContainerWatcher) StartContainerCollection(ctx context.Context) error {
	cw.ctx = ctx

	// This is needed when not running as gadget.
	// https://github.com/inspektor-gadget/inspektor-gadget/blob/9a797dc046f8bc1f45e85f15db7e99dd4e5cb6e5/cmd/ig/containers/containers.go#L45-L46
	if err := host.Init(host.Config{AutoMountFilesystems: true}); err != nil {
		return fmt.Errorf("initializing host package: %w", err)
	}

	// Start the container collection
	containerEventFuncs := []containercollection.FuncNotify{
		func(event containercollection.PubSubEvent) {
			logger.L().TimedWrapper("synchronous containerCallback", 5*time.Second, func() {
				cw.containerCallback(event)
			})
		},
	}

	// Initialize socket enricher for network tracers
	if cw.cfg.EnableNetworkTracing || cw.cfg.EnableRuntimeDetection {
		socketEnricherFields := params.ParamDescs{
			{
				Key:         "socket-enricher-fields",
				Description: "Fields to enrich the socket event with",
				TypeHint:    params.TypeString,
			},
		}
		socketEnricherOp := &socketenricher.SocketEnricher{}
		socketEnricherParams := socketEnricherFields.ToParams()
		socketEnricherParams.Get("socket-enricher-fields").Set("cwd=512,exepath=512")
		if err := socketEnricherOp.Init(socketEnricherParams); err != nil {
			return fmt.Errorf("init socket enricher: %w", err)
		}
		cw.socketEnricher = socketEnricherOp
	}

	// Set up container callbacks
	cw.callbacks = []containercollection.FuncNotify{
		cw.containerCallbackAsync,
		cw.containerProcessTree.ContainerCallback,
		cw.containerProfileManager.ContainerCallback,
		cw.objectCache.ApplicationProfileCache().ContainerCallback,
		cw.objectCache.NetworkNeighborhoodCache().ContainerCallback,
		cw.malwareManager.ContainerCallback,
		cw.ruleManager.ContainerCallback,
		cw.sbomManager.ContainerCallback,
		cw.dnsManager.ContainerCallback,
		cw.networkStreamClient.ContainerCallback,
	}

	for receiver := range cw.thirdPartyContainerReceivers.Iter() {
		cw.callbacks = append(cw.callbacks, receiver.ContainerCallback)
	}

	// Define the different options for the container collection instance
	opts := []containercollection.ContainerCollectionOption{
		// Get Notifications from the container collection
		containercollection.WithPubSub(containerEventFuncs...),

		// Enrich events with OCI config information
		containercollection.WithOCIConfigEnrichment(),

		// Get containers enriched with cgroup information
		containercollection.WithCgroupEnrichment(),

		// Enrich events with Linux namespaces information, it is needed for per container filtering
		containercollection.WithLinuxNamespaceEnrichment(),

		// Get containers created with container runtimes
		containercollection.WithContainerRuntimeEnrichment(cw.runtime),

		// Get containers created with ebpf (works also if hostPid=false)
		containercollection.WithContainerFanotifyEbpf(),

		// WithTracerCollection enables the interation between the TracerCollection and ContainerCollection packages.
		containercollection.WithTracerCollection(cw.tracerCollection),

		// WithProcEnrichment enables the enrichment of events with process information
		containercollection.WithProcEnrichment(),
	}

	// Initialize the container collection
	logger.L().Info("ContainerManager - initializing container collection with options", helpers.Int("optionCount", len(opts)))
	if err := cw.containerCollection.Initialize(opts...); err != nil {
		return fmt.Errorf("initializing container collection: %w", err)
	}
	logger.L().Info("ContainerManager - container collection initialized successfully")

	// Start monitoring for rule bindings notifications
	go cw.startRunningContainers()

	return nil
}

// StopContainerCollection stops the container collection
func (cw *ContainerWatcher) StopContainerCollection() {
	if cw.containerCollection != nil {
		cw.tracerCollection.Close()
		cw.containerCollection.Close()
	}
}

// startRunningContainers monitors for rule binding notifications
func (cw *ContainerWatcher) startRunningContainers() {
	for n := range *cw.ruleBindingPodNotify {
		cw.addRunningContainers(&n)
	}
}

// addRunningContainers handles rule binding notifications
func (cw *ContainerWatcher) addRunningContainers(notf *rulebindingmanager.RuleBindingNotify) {
	pod := notf.GetPod()

	// Mark that we've received at least one rule binding notification
	cw.ruleBindingsInitialized = true

	// skip containers that should be ignored
	if cw.cfg.IgnoreContainer(pod.GetNamespace(), pod.GetName(), pod.GetLabels()) {
		logger.L().Debug("ContainerWatcher - skipping pod", helpers.String("namespace", pod.GetNamespace()), helpers.String("pod name", pod.GetName()))
		return
	}

	k8sPodID := utils.CreateK8sPodID(pod.GetNamespace(), pod.GetName())

	switch notf.GetAction() {
	case rulebindingmanager.Added:
		// add to the list of pods that are being monitored because of rules
		cw.ruleManagedPods.Add(k8sPodID)
	case rulebindingmanager.Removed:
		cw.ruleManagedPods.Remove(k8sPodID)
	}
}
