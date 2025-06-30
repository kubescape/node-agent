package containerwatcher

import (
	"context"
	"errors"
	"fmt"
	"runtime"
	"time"

	"github.com/armosec/utils-k8s-go/wlid"
	"github.com/cenkalti/backoff"
	containercollection "github.com/inspektor-gadget/inspektor-gadget/pkg/container-collection"
	"github.com/inspektor-gadget/inspektor-gadget/pkg/socketenricher"
	"github.com/inspektor-gadget/inspektor-gadget/pkg/utils/host"
	"github.com/kubescape/go-logger"
	"github.com/kubescape/go-logger/helpers"
	"github.com/kubescape/k8s-interface/instanceidhandler/v1"
	"github.com/kubescape/k8s-interface/workloadinterface"
	"github.com/kubescape/node-agent/pkg/rulebindingmanager"
	"github.com/kubescape/node-agent/pkg/utils"
)

const (
	MaxSniffingTimeLabel = "kubescape.io/max-sniffing-time"
)

func (ch *IGContainerWatcher) containerCallback(notif containercollection.PubSubEvent) {
	logger.L().Debug("IGContainerWatcher.containerCallback - received container event", helpers.String("event", fmt.Sprintf("%+v", notif)), helpers.String("container", fmt.Sprintf("%+v", notif.Container)))
	if notif.Container == nil || notif.Container.Runtime.ContainerID == "" {
		return
	}
	// check if the container should be ignored
	if ch.cfg.IgnoreContainer(notif.Container.K8s.Namespace, notif.Container.K8s.PodName, notif.Container.K8s.PodLabels) {
		// avoid loops when the container is being removed
		if notif.Type == containercollection.EventTypeAddContainer {
			ch.unregisterContainer(notif.Container)
		}
		return
	}
	// scale up the pool size if needed pkg/config/config.go:66
	for _, callback := range ch.callbacks {
		ch.pool.Submit(func() {
			callback(notif)
		}, utils.FuncName(callback))
	}
}

func (ch *IGContainerWatcher) containerCallbackAsync(notif containercollection.PubSubEvent) {
	k8sContainerID := utils.CreateK8sContainerID(notif.Container.K8s.Namespace, notif.Container.K8s.PodName, notif.Container.Runtime.ContainerID)

	switch notif.Type {
	case containercollection.EventTypeAddContainer:
		logger.L().Debug("IGContainerWatcher.containerCallback - add container event received",
			helpers.String("container ID", notif.Container.Runtime.ContainerID),
			helpers.String("k8s workload", k8sContainerID),
			helpers.String("ContainerImageDigest", notif.Container.Runtime.ContainerImageDigest),
			helpers.String("ContainerImageName", notif.Container.Runtime.ContainerImageName))
		// Check if Pod has a label of max sniffing time
		sniffingTime := utils.AddJitter(ch.cfg.MaxSniffingTime, ch.cfg.MaxJitterPercentage)
		if podLabelMaxSniffingTime, ok := notif.Container.K8s.PodLabels[MaxSniffingTimeLabel]; ok {
			if duration, err := time.ParseDuration(podLabelMaxSniffingTime); err == nil {
				sniffingTime = duration
			} else {
				logger.L().Debug("IGContainerWatcher.containerCallback - parsing sniffing time in label", helpers.Error(err), helpers.String("podLabelMaxSniffingTime", podLabelMaxSniffingTime))
			}
		}

		// Set shared watched container data
		go ch.setSharedWatchedContainerData(notif.Container)

		time.AfterFunc(sniffingTime, func() {
			logger.L().Debug("IGContainerWatcher.containerCallback - monitoring time ended",
				helpers.String("container ID", notif.Container.Runtime.ContainerID),
				helpers.String("k8s workload", k8sContainerID),
				helpers.String("ContainerImageDigest", notif.Container.Runtime.ContainerImageDigest),
				helpers.String("ContainerImageName", notif.Container.Runtime.ContainerImageName))
			ch.applicationProfileManager.ContainerReachedMaxTime(notif.Container.Runtime.ContainerID)
			ch.networkManager.ContainerReachedMaxTime(notif.Container.Runtime.ContainerID)
			ch.unregisterContainer(notif.Container)
		})
	case containercollection.EventTypeRemoveContainer:
		logger.L().Debug("IGContainerWatcher.containerCallback - remove container event received",
			helpers.String("container ID", notif.Container.Runtime.ContainerID),
			helpers.String("k8s workload", k8sContainerID),
			helpers.String("ContainerImageDigest", notif.Container.Runtime.ContainerImageDigest),
			helpers.String("ContainerImageName", notif.Container.Runtime.ContainerImageName))
		ch.objectCache.K8sObjectCache().DeleteSharedContainerData(notif.Container.Runtime.ContainerID)
	}
}

func (ch *IGContainerWatcher) setSharedWatchedContainerData(container *containercollection.Container) {
	// don't start monitoring until we have the instanceID - need to retry until the Pod is updated
	var sharedWatchedContainerData *utils.WatchedContainerData
	err := backoff.Retry(func() error {
		data, err := ch.getSharedWatchedContainerData(container)
		if err != nil {
			return err
		}
		if data == nil {
			return fmt.Errorf("received nil container data")
		}
		sharedWatchedContainerData = data
		return nil
	}, backoff.NewExponentialBackOff())

	if err != nil {
		logger.L().Error("IGContainerWatcher.containerCallback - error getting shared watched container data", helpers.Error(err))
		return // Exit early on error
	}

	if sharedWatchedContainerData == nil {
		logger.L().Error("IGContainerWatcher.containerCallback - shared watched container data is nil after retry")
		return
	}

	ch.objectCache.K8sObjectCache().SetSharedContainerData(container.Runtime.ContainerID, sharedWatchedContainerData)
}

func (ch *IGContainerWatcher) getSharedWatchedContainerData(container *containercollection.Container) (*utils.WatchedContainerData, error) {
	watchedContainer := utils.WatchedContainerData{
		ContainerID: container.Runtime.ContainerID,
		// we get ImageID and ImageTag from the pod spec for consistency with operator
	}

	wl, err := ch.k8sClient.GetWorkload(container.K8s.Namespace, "Pod", container.K8s.PodName)
	if err != nil {
		return nil, fmt.Errorf("failed to get workload: %w", err)
	}
	// make sure the pod is not pending (otherwise ImageID is empty in containerStatuses)
	podStatus, err := wl.GetPodStatus()
	if err != nil {
		return nil, fmt.Errorf("failed to get pod status: %w", err)
	}
	if podStatus.Phase == "Pending" {
		return nil, fmt.Errorf("pod is still pending")
	}
	pod := wl.(*workloadinterface.Workload)
	// fill container type, index and names
	if watchedContainer.ContainerType == utils.Unknown {
		if err := watchedContainer.SetContainerInfo(pod, container.K8s.ContainerName); err != nil {
			return nil, fmt.Errorf("failed to set container info: %w", err)
		}
	}
	// find parentWlid
	kind, name, err := ch.k8sClient.CalculateWorkloadParentRecursive(pod)
	if err != nil {
		return nil, fmt.Errorf("failed to calculate parent workload: %w", err)
	}
	parentWorkload, err := ch.k8sClient.GetWorkload(pod.GetNamespace(), kind, name)
	if err != nil {
		return nil, fmt.Errorf("failed to get parent workload: %w", err)
	}
	w := parentWorkload.(*workloadinterface.Workload)
	watchedContainer.Wlid = w.GenerateWlid(ch.clusterName)
	err = wlid.IsWlidValid(watchedContainer.Wlid)
	if err != nil {
		return nil, fmt.Errorf("failed to validate wlid: %w", err)
	}
	watchedContainer.ParentResourceVersion = w.GetResourceVersion()
	// find parent selector
	selector, err := w.GetSelector()
	if err != nil {
		return nil, fmt.Errorf("failed to get selector: %w", err)
	}
	watchedContainer.ParentWorkloadSelector = selector
	preRunning := time.Unix(0, int64(container.Runtime.ContainerStartedAt)).Before(ch.agentStartTime)
	watchedContainer.PreRunningContainer = preRunning
	// find instanceID - this has to be the last one
	instanceIDs, err := instanceidhandler.GenerateInstanceID(pod, ch.cfg.ExcludeJsonPaths)
	if err != nil {
		return nil, fmt.Errorf("failed to generate instance id: %w", err)
	}
	for i := range instanceIDs {
		if instanceIDs[i].GetContainerName() == container.K8s.ContainerName {
			watchedContainer.InstanceID = instanceIDs[i]
		}
	}
	if watchedContainer.InstanceID == nil {
		return nil, fmt.Errorf("failed to find instance id for container %s", container.K8s.ContainerName)
	}
	return &watchedContainer, nil
}

func (ch *IGContainerWatcher) startContainerCollection(ctx context.Context) error {
	ch.ctx = ctx

	// This is needed when not running as gadget.
	// https://github.com/inspektor-gadget/inspektor-gadget/blob/9a797dc046f8bc1f45e85f15db7e99dd4e5cb6e5/cmd/ig/containers/containers.go#L45-L46
	if err := host.Init(host.Config{AutoMountFilesystems: true}); err != nil {
		return fmt.Errorf("initializing host package: %w", err)
	}

	// Start the container collection
	containerEventFuncs := []containercollection.FuncNotify{
		func(event containercollection.PubSubEvent) {
			logger.L().TimedWrapper("synchronous containerCallback", 5*time.Second, func() {
				ch.containerCallback(event)
			})
		},
		// other callbacks should be put in ch.callbacks to be called from ch.containerCallback
	}

	ch.callbacks = []containercollection.FuncNotify{
		ch.containerCallbackAsync,
		ch.applicationProfileManager.ContainerCallback,
		ch.networkManager.ContainerCallback,
		ch.objectCache.ApplicationProfileCache().ContainerCallback,
		ch.objectCache.NetworkNeighborhoodCache().ContainerCallback,
		ch.malwareManager.ContainerCallback,
		ch.ruleManager.ContainerCallback,
		ch.sbomManager.ContainerCallback,
		ch.dnsManager.ContainerCallback,
		ch.networkStreamClient.ContainerCallback,
		ch.containerProcessTree.ContainerCallback,
	}

	for receiver := range ch.thirdPartyContainerReceivers.Iter() {
		ch.callbacks = append(ch.callbacks, receiver.ContainerCallback)
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
		containercollection.WithContainerRuntimeEnrichment(ch.runtime),

		// Get containers created with ebpf (works also if hostPid=false)
		containercollection.WithContainerFanotifyEbpf(),

		// WithTracerCollection enables the interation between the TracerCollection and ContainerCollection packages.
		containercollection.WithTracerCollection(ch.tracerCollection),

		// WithProcEnrichment enables the enrichment of events with process information
		containercollection.WithProcEnrichment(),
	}

	// Initialize the container collection
	if err := ch.containerCollection.Initialize(opts...); err != nil {
		return fmt.Errorf("initializing container collection: %w", err)
	}

	// This routine will keep monitoring for rule bindings notifications for the entire lifecycle of the node-agent.
	go ch.startRunningContainers()

	return nil
}

func (ch *IGContainerWatcher) startRunningContainers() {
	for n := range *ch.ruleBindingPodNotify {
		ch.addRunningContainers(&n)
	}
}

func (ch *IGContainerWatcher) addRunningContainers(notf *rulebindingmanager.RuleBindingNotify) {
	pod := notf.GetPod()

	// skip containers that should be ignored
	if ch.cfg.IgnoreContainer(pod.GetNamespace(), pod.GetName(), pod.GetLabels()) {
		logger.L().Debug("IGContainerWatcher - skipping pod", helpers.String("namespace", pod.GetNamespace()), helpers.String("pod name", pod.GetName()))
		return
	}

	k8sPodID := utils.CreateK8sPodID(pod.GetNamespace(), pod.GetName())

	switch notf.GetAction() {
	case rulebindingmanager.Added:
		// add to the list of pods that are being monitored because of rules
		ch.ruleManagedPods.Add(k8sPodID)
	case rulebindingmanager.Removed:
		ch.ruleManagedPods.Remove(k8sPodID)
	}
}

func (ch *IGContainerWatcher) stopContainerCollection() {
	if ch.containerCollection != nil {
		ch.tracerCollection.Close()
		ch.containerCollection.Close()
	}
}

func (ch *IGContainerWatcher) startTracers() error {
	if ch.cfg.EnableRuntimeDetection || ch.cfg.EnableSeccomp {
		// Start syscall tracer
		if err := ch.startSystemcallTracing(); err != nil {
			logger.L().Error("IGContainerWatcher - error starting seccomp tracing", helpers.Error(err))
			return err
		}
		logger.L().Info("started syscall tracing")
	}
	if ch.cfg.EnableApplicationProfile || ch.cfg.EnableRuntimeDetection {
		// Start exec tracer
		if err := ch.startExecTracing(); err != nil {
			logger.L().Error("IGContainerWatcher - error starting exec tracing", helpers.Error(err))
			return err
		}
		logger.L().Info("started exec tracing")
		// Start open tracer
		if err := ch.startOpenTracing(); err != nil {
			logger.L().Error("IGContainerWatcher - error starting open tracing", helpers.Error(err))
			return err
		}
		logger.L().Info("started open tracing")
	}

	if ch.cfg.EnableNetworkTracing || ch.cfg.EnableRuntimeDetection {
		if err := ch.startKubernetesResolution(); err != nil {
			logger.L().Error("IGContainerWatcher - error starting kubernetes resolution", helpers.Error(err))
			return err
		}

		socketEnricher, err := socketenricher.NewSocketEnricher()
		if err != nil {
			logger.L().Error("IGContainerWatcher - error creating socket enricher", helpers.Error(err))
			return err
		}
		ch.socketEnricher = socketEnricher

		if err := ch.startDNSTracing(); err != nil {
			// not failing on dns tracing error
			logger.L().Error("IGContainerWatcher - error starting dns tracing", helpers.Error(err))
		}
		logger.L().Info("started dns tracing")

		if err := ch.startNetworkTracing(); err != nil {
			logger.L().Error("IGContainerWatcher - error starting network tracing", helpers.Error(err))
			return err
		}
		logger.L().Info("started network tracing")
	}

	if ch.cfg.EnableRuntimeDetection {
		// Start capabilities tracer
		if err := ch.startCapabilitiesTracing(); err != nil {
			logger.L().Error("IGContainerWatcher - error starting capabilities tracing", helpers.Error(err))
			return err
		}
		logger.L().Info("started capabilities tracing")
		// The randomx tracing is only supported on amd64 architecture.
		if runtime.GOARCH == "amd64" {
			if err := ch.startRandomxTracing(); err != nil {
				logger.L().Error("IGContainerWatcher - error starting randomx tracing", helpers.Error(err))
				return err
			}
			logger.L().Info("started randomx tracing")
		} else {
			logger.L().Warning("randomx tracing is not supported on this architecture", helpers.String("architecture", runtime.GOARCH))
		}

		if err := ch.startSymlinkTracing(); err != nil {
			logger.L().Error("IGContainerWatcher - error starting symlink tracing", helpers.Error(err))
			return err
		}
		logger.L().Info("started symlink tracing")

		if err := ch.startForkTracing(); err != nil {
			logger.L().Error("IGContainerWatcher - error starting fork tracing", helpers.Error(err))
			return err
		}
		logger.L().Info("started fork tracing")

		if err := ch.startHardlinkTracing(); err != nil {
			logger.L().Error("IGContainerWatcher - error starting hardlink tracing", helpers.Error(err))
			return err
		}
		logger.L().Info("started hardlink tracing")

		// NOTE: SSH tracing relies on the network tracer, so it must be started after the network tracer.
		if err := ch.startSshTracing(); err != nil {
			logger.L().Error("IGContainerWatcher - error starting ssh tracing", helpers.Error(err))
			return err
		}
		logger.L().Info("started ssh tracing")

		if err := ch.startPtraceTracing(); err != nil {
			logger.L().Error("IGContainerWatcher - error starting ptrace tracing", helpers.Error(err))
			return err
		}
		logger.L().Info("started ptrace tracing")

		if err := ch.startIouringTracing(); err != nil {
			logger.L().Error("IGContainerWatcher - error starting io_uring tracing, skipping.", helpers.Error(err))
			ch.stopIouringTracing()
		}
		logger.L().Info("started io_uring tracing")

		if ch.cfg.EnableHttpDetection {
			if err := ch.startHttpTracing(); err != nil {
				logger.L().Error("IGContainerWatcher - error starting http tracing", helpers.Error(err))
				return err
			}
			logger.L().Info("started http tracing")
		}

		// Start third party tracers
		for tracer := range ch.thirdPartyTracers.Iter() {
			if err := tracer.Start(); err != nil {
				logger.L().Error("IGContainerWatcher - error starting custom tracer", helpers.String("tracer", tracer.Name()), helpers.Error(err))
				return err
			}
			logger.L().Info("started custom tracer", helpers.String("tracer", tracer.Name()))
		}
	}

	if ch.cfg.EnablePrometheusExporter {
		if err := ch.startTopTracing(); err != nil {
			logger.L().Error("IGContainerWatcher - error starting top tracing", helpers.Error(err))
			return err
		}
		logger.L().Info("started top tracing")
	}

	return nil
}

func (ch *IGContainerWatcher) stopTracers() error {
	var errs error
	if ch.cfg.EnableApplicationProfile || ch.cfg.EnableRuntimeDetection {
		// Stop capabilities tracer
		if err := ch.stopCapabilitiesTracing(); err != nil {
			logger.L().Error("IGContainerWatcher - error stopping capabilities tracing", helpers.Error(err))
			errs = errors.Join(errs, err)
		}
		// Stop syscall tracer
		if err := ch.stopSystemcallTracing(); err != nil {
			logger.L().Error("IGContainerWatcher - error stopping seccomp tracing", helpers.Error(err))
			errs = errors.Join(errs, err)
		}
	}
	if ch.cfg.EnableApplicationProfile || ch.cfg.EnableRuntimeDetection {
		// Stop exec tracer
		if err := ch.stopExecTracing(); err != nil {
			logger.L().Error("IGContainerWatcher - error stopping exec tracing", helpers.Error(err))
			errs = errors.Join(errs, err)
		}
		// Stop open tracer
		if err := ch.stopOpenTracing(); err != nil {
			logger.L().Error("IGContainerWatcher - error stopping open tracing", helpers.Error(err))
			errs = errors.Join(errs, err)
		}
	}

	if ch.cfg.EnableNetworkTracing || ch.cfg.EnableRuntimeDetection {
		// Stop network tracer
		if err := ch.stopNetworkTracing(); err != nil {
			logger.L().Error("IGContainerWatcher - error stopping network tracing", helpers.Error(err))
			errs = errors.Join(errs, err)
		}
		// Stop dns tracer
		if err := ch.stopDNSTracing(); err != nil {
			logger.L().Error("IGContainerWatcher - error stopping dns tracing", helpers.Error(err))
			errs = errors.Join(errs, err)
		}
	}

	if ch.cfg.EnableRuntimeDetection {
		// Stop randomx tracer
		if runtime.GOARCH == "amd64" && ch.randomxTracer != nil {
			if err := ch.stopRandomxTracing(); err != nil {
				logger.L().Error("IGContainerWatcher - error stopping randomx tracing", helpers.Error(err))
				errs = errors.Join(errs, err)
			}
		}

		// Stop symlink tracer
		if err := ch.stopSymlinkTracing(); err != nil {
			logger.L().Error("IGContainerWatcher - error stopping symlink tracing", helpers.Error(err))
			errs = errors.Join(errs, err)
		}

		// Stop fork tracer
		if err := ch.stopForkTracing(); err != nil {
			logger.L().Error("IGContainerWatcher - error stopping fork tracing", helpers.Error(err))
			errs = errors.Join(errs, err)
		}

		// Stop hardlink tracer
		if err := ch.stopHardlinkTracing(); err != nil {
			logger.L().Error("IGContainerWatcher - error stopping hardlink tracing", helpers.Error(err))
			errs = errors.Join(errs, err)
		}

		// Stop ssh tracer
		if err := ch.stopSshTracing(); err != nil {
			logger.L().Error("IGContainerWatcher - error starting ssh tracing", helpers.Error(err))
			errs = errors.Join(errs, err)
		}

		// Stop ptrace tracer
		if err := ch.stopPtraceTracing(); err != nil {
			logger.L().Error("IGContainerWatcher - error starting ptrace tracing", helpers.Error(err))
			errs = errors.Join(errs, err)
		}

		if err := ch.stopIouringTracing(); err != nil {
			logger.L().Error("IGContainerWatcher - error stopping io_uring tracing", helpers.Error(err))
			errs = errors.Join(errs, err)
		}

		// Stop third party tracers
		for tracer := range ch.thirdPartyTracers.Iter() {
			if err := tracer.Stop(); err != nil {
				logger.L().Error("IGContainerWatcher - error stopping custom tracer", helpers.String("tracer", tracer.Name()), helpers.Error(err))
				errs = errors.Join(errs, err)
			}
		}
	}

	if ch.cfg.EnableHttpDetection {
		// Stop http tracer
		if err := ch.stopHttpTracing(); err != nil {
			logger.L().Error("IGContainerWatcher - error stopping http tracing", helpers.Error(err))
			errs = errors.Join(errs, err)
		}
	}

	if ch.cfg.EnablePrometheusExporter {
		// Stop top tracer
		if err := ch.stopTopTracing(); err != nil {
			logger.L().Error("IGContainerWatcher - error stopping top tracing", helpers.Error(err))
			errs = errors.Join(errs, err)
		}
	}

	return errs
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
		logger.L().Debug("printNsMap - map entry", helpers.String("key", key), helpers.Int("value", int(value)))
	}
}

func (ch *IGContainerWatcher) unregisterContainer(container *containercollection.Container) {
	if ch.ruleManagedPods.Contains(utils.CreateK8sPodID(container.K8s.Namespace, container.K8s.PodName)) {
		// the container should still be monitored
		logger.L().Debug("IGContainerWatcher - container should still be monitored",
			helpers.String("container ID", container.Runtime.ContainerID),
			helpers.String("namespace", container.K8s.Namespace), helpers.String("PodName", container.K8s.PodName), helpers.String("ContainerName", container.K8s.ContainerName),
		)
		return
	}

	logger.L().Debug("IGContainerWatcher - stopping to monitor on container", helpers.String("container ID", container.Runtime.ContainerID), helpers.String("namespace", container.K8s.Namespace), helpers.String("PodName", container.K8s.PodName), helpers.String("ContainerName", container.K8s.ContainerName))

	ch.containerCollection.RemoveContainer(container.Runtime.ContainerID)
	ch.objectCache.K8sObjectCache().DeleteSharedContainerData(container.Runtime.ContainerID)
}
