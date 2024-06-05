package containerwatcher

import (
	"context"
	"errors"
	"fmt"
	"node-agent/pkg/rulebindingmanager"
	"node-agent/pkg/utils"
	"runtime"
	"time"

	containercollection "github.com/inspektor-gadget/inspektor-gadget/pkg/container-collection"
	"github.com/inspektor-gadget/inspektor-gadget/pkg/socketenricher"
	"github.com/inspektor-gadget/inspektor-gadget/pkg/utils/host"
	"github.com/kubescape/go-logger"
	"github.com/kubescape/go-logger/helpers"
)

func (ch *IGContainerWatcher) containerCallback(notif containercollection.PubSubEvent) {

	// do not trace the node-agent pod
	if ch.ignoreContainer(notif.Container.K8s.Namespace, notif.Container.K8s.PodName) {
		ch.unregisterContainer(notif.Container)
		return
	}

	k8sContainerID := utils.CreateK8sContainerID(notif.Container.K8s.Namespace, notif.Container.K8s.PodName, notif.Container.K8s.ContainerName)

	if !ch.preRunningContainersIDs.Contains(notif.Container.Runtime.ContainerID) {
		// container is not in preRunningContainersIDs, it is a new container
		ch.timeBasedContainers.Add(notif.Container.Runtime.ContainerID)
	}

	switch notif.Type {
	case containercollection.EventTypeAddContainer:
		logger.L().Info("start monitor on container", helpers.String("container ID", notif.Container.Runtime.ContainerID), helpers.String("k8s workload", k8sContainerID))

		if ch.syscallTracer != nil {
			// Attach the container to the syscall tracer
			if err := ch.syscallTracer.Attach(notif.Container.Runtime.ContainerID, notif.Container.Mntns); err != nil {
				logger.L().Fatal("attaching container to syscall tracer", helpers.String("container ID", notif.Container.Runtime.ContainerID), helpers.String("k8s workload", k8sContainerID), helpers.Error(err))
			}

			// Read the syscall tracer events in a separate goroutine.
			go func() {
				for {
					if !ch.timeBasedContainers.Contains(notif.Container.Runtime.ContainerID) && !ch.preRunningContainersIDs.Contains(notif.Container.Runtime.ContainerID) {
						logger.L().Info("stop monitor on container - container has been removed",
							helpers.String("container ID", notif.Container.Runtime.ContainerID),
							helpers.String("k8s workload", k8sContainerID))
						return
					}

					evs, err := ch.syscallTracer.Read(notif.Container.Runtime.ContainerID)
					if err != nil {
						logger.L().Debug("syscalls perf buffer closed", helpers.String("error", err.Error()))
						return
					}
					for _, ev := range evs {
						ev.SetContainerMetadata(notif.Container)
						ch.syscallEventCallback(ev)
					}

					// Sleep for a while before reading the next batch of events.
					time.Sleep(2 * time.Second) // TODO: make this configurable.
				}
			}()
		}

		time.AfterFunc(ch.cfg.MaxSniffingTime, func() {
			logger.L().Info("monitoring time ended", helpers.String("container ID", notif.Container.Runtime.ContainerID), helpers.String("k8s workload", k8sContainerID))
			ch.timeBasedContainers.Remove(notif.Container.Runtime.ContainerID)
			ch.applicationProfileManager.ContainerReachedMaxTime(notif.Container.Runtime.ContainerID)
			ch.relevancyManager.ContainerReachedMaxTime(notif.Container.Runtime.ContainerID)
			ch.networkManagerv1.ContainerReachedMaxTime(notif.Container.Runtime.ContainerID)
			ch.networkManager.ContainerReachedMaxTime(notif.Container.Runtime.ContainerID)
			ch.unregisterContainer(notif.Container)
		})
	case containercollection.EventTypeRemoveContainer:
		logger.L().Info("stop monitor on container - container has terminated",
			helpers.String("container ID", notif.Container.Runtime.ContainerID),
			helpers.String("k8s workload", k8sContainerID))
		ch.preRunningContainersIDs.Remove(notif.Container.Runtime.ContainerID)
		ch.timeBasedContainers.Remove(notif.Container.Runtime.ContainerID)
		ch.syscallTracer.Detach(notif.Container.Mntns)
		ch.syscallTracer.Delete(notif.Container.Runtime.ContainerID)
	}
}
func (ch *IGContainerWatcher) startContainerCollection(ctx context.Context) error {
	ch.ctx = ctx

	// Start the container collection
	containerEventFuncs := []containercollection.FuncNotify{
		ch.containerCallback,
		ch.applicationProfileManager.ContainerCallback,
		ch.relevancyManager.ContainerCallback,
		ch.networkManagerv1.ContainerCallback,
		ch.networkManager.ContainerCallback,
		ch.malwareManager.ContainerCallback,
		ch.ruleManager.ContainerCallback,
	}

	// Define the different options for the container collection instance
	opts := []containercollection.ContainerCollectionOption{
		containercollection.WithTracerCollection(ch.tracerCollection),

		// Enrich events with OCI config information
		containercollection.WithOCIConfigEnrichment(),

		// Get containers created with ebpf (works also if hostPid=false)
		containercollection.WithContainerFanotifyEbpf(),

		// Get containers created with docker
		containercollection.WithCgroupEnrichment(),

		// Enrich events with Linux namespaces information, it is needed for per container filtering
		containercollection.WithLinuxNamespaceEnrichment(),

		// Enrich those containers with data from the Kubernetes API
		containercollection.WithKubernetesEnrichment(ch.nodeName, ch.k8sClient.K8SConfig),

		// Get Notifications from the container collection
		containercollection.WithPubSub(containerEventFuncs...),
	}

	// Initialize the container collection
	if err := ch.containerCollection.Initialize(opts...); err != nil {
		return fmt.Errorf("initializing container collection: %w", err)
	}

	// add containers that are already running
	go ch.startRunningContainers()

	return nil
}

func (ch *IGContainerWatcher) startRunningContainers() error {
	k8sClient, err := containercollection.NewK8sClient(ch.nodeName)
	if err != nil {
		logger.L().Fatal("creating IG Kubernetes client", helpers.Error(err))
	}
	defer k8sClient.Close()
	for n := range *ch.ruleBindingPodNotify {
		ch.addRunningContainers(k8sClient, &n)
	}
	return nil
}

func (ch *IGContainerWatcher) addRunningContainers(k8sClient IGK8sClient, notf *rulebindingmanager.RuleBindingNotify) {
	pod := notf.GetPod()

	// skip containers that should be ignored
	if ch.ignoreContainer(pod.GetNamespace(), pod.GetName()) {
		logger.L().Info("skipping pod", helpers.String("namespace", pod.GetNamespace()), helpers.String("pod name", pod.GetName()))
		return
	}

	k8sPodID := utils.CreateK8sPodID(pod.GetNamespace(), pod.GetName())
	runningContainers := k8sClient.GetRunningContainers(pod)

	switch notf.GetAction() {
	case rulebindingmanager.Removed:
		ch.ruleManagedPods.Remove(k8sPodID)
		for i := range runningContainers {
			logger.L().Info("removing container - pod not managed by rules or removed",
				helpers.String("containerID", runningContainers[i].Runtime.ContainerID),
				helpers.String("namespace", runningContainers[i].K8s.Namespace),
				helpers.String("pod", runningContainers[i].K8s.PodName),
				helpers.String("containerName", runningContainers[i].K8s.ContainerName))

			ch.unregisterContainer(&runningContainers[i])
		}
	case rulebindingmanager.Added:
		// add to the list of pods that are being monitored because of rules
		ch.ruleManagedPods.Add(k8sPodID)

		for i := range runningContainers {
			if ch.timeBasedContainers.Contains(runningContainers[i].Runtime.ContainerID) || ch.preRunningContainersIDs.Contains(runningContainers[i].Runtime.ContainerID) {
				// the container is already being monitored
				continue
			}

			logger.L().Debug("adding to pre running containers",
				helpers.String("containerID", runningContainers[i].Runtime.ContainerID),
				helpers.String("namespace", runningContainers[i].K8s.Namespace),
				helpers.String("pod", runningContainers[i].K8s.PodName),
				helpers.String("containerName", runningContainers[i].K8s.ContainerName))

			ch.preRunningContainersIDs.Add(runningContainers[i].Runtime.ContainerID)
			ch.containerCollection.AddContainer(&runningContainers[i])
		}
	}

}
func (ch *IGContainerWatcher) stopContainerCollection() {
	if ch.containerCollection != nil {
		ch.tracerCollection.Close()
		ch.containerCollection.Close()
	}
}

func (ch *IGContainerWatcher) startTracers() error {
	if ch.cfg.EnableApplicationProfile {
		// Start syscall tracer
		if err := ch.startSyscallTracing(); err != nil {
			logger.L().Error("error starting syscall tracing", helpers.Error(err))
			return err
		}
		// Start capabilities tracer
		if err := ch.startCapabilitiesTracing(); err != nil {
			logger.L().Error("error starting capabilities tracing", helpers.Error(err))
			return err
		}
	}
	if ch.cfg.EnableRelevancy || ch.cfg.EnableApplicationProfile {
		// Start exec tracer
		if err := ch.startExecTracing(); err != nil {
			logger.L().Error("error starting exec tracing", helpers.Error(err))
			return err
		}
		// Start open tracer
		if err := ch.startOpenTracing(); err != nil {
			logger.L().Error("error starting open tracing", helpers.Error(err))
			return err
		}
	}

	if ch.cfg.EnableNetworkTracing {
		host.Init(host.Config{AutoMountFilesystems: true})

		if err := ch.startKubernetesResolution(); err != nil {
			logger.L().Error("error starting kubernetes resolution", helpers.Error(err))
			return err
		}

		socketEnricher, err := socketenricher.NewSocketEnricher()
		if err != nil {
			logger.L().Error("error creating socket enricher", helpers.Error(err))
			return err
		}
		ch.socketEnricher = socketEnricher

		if err := ch.startDNSTracing(); err != nil {
			// not failing on dns tracing error
			logger.L().Error("error starting dns tracing", helpers.Error(err))
		}

		if err := ch.startNetworkTracing(); err != nil {
			logger.L().Error("error starting network tracing", helpers.Error(err))
			return err
		}
	}

	if ch.cfg.EnableRuntimeDetection {
		// The randomx tracing is only supported on amd64 architecture.
		if runtime.GOARCH == "amd64" {
			if err := ch.startRandomxTracing(); err != nil {
				logger.L().Error("error starting randomx tracing", helpers.Error(err))
				return err
			}
		} else {
			logger.L().Warning("randomx tracing is not supported on this architecture", helpers.String("architecture", runtime.GOARCH))
		}

		if err := ch.startSymlinkTracing(); err != nil {
			logger.L().Error("error starting symlink tracing", helpers.Error(err))
			return err
		}

		if err := ch.startHardlinkTracing(); err != nil {
			logger.L().Error("error starting hardlink tracing", helpers.Error(err))
			return err
		}
	}

	return nil
}

func (ch *IGContainerWatcher) stopTracers() error {
	var errs error
	if ch.cfg.EnableApplicationProfile {
		// Stop capabilities tracer
		if err := ch.stopCapabilitiesTracing(); err != nil {
			logger.L().Error("error stopping capabilities tracing", helpers.Error(err))
			errs = errors.Join(errs, err)
		}
		// Stop syscall tracer
		if err := ch.stopSystemcallTracing(); err != nil {
			logger.L().Error("error stopping syscall tracing", helpers.Error(err))
			errs = errors.Join(errs, err)
		}
	}
	if ch.cfg.EnableRelevancy || ch.cfg.EnableApplicationProfile {
		// Stop exec tracer
		if err := ch.stopExecTracing(); err != nil {
			logger.L().Error("error stopping exec tracing", helpers.Error(err))
			errs = errors.Join(errs, err)
		}
		// Stop open tracer
		if err := ch.stopOpenTracing(); err != nil {
			logger.L().Error("error stopping open tracing", helpers.Error(err))
			errs = errors.Join(errs, err)
		}
	}

	if ch.cfg.EnableNetworkTracing {
		// Stop network tracer
		if err := ch.stopNetworkTracing(); err != nil {
			logger.L().Error("error stopping network tracing", helpers.Error(err))
			errs = errors.Join(errs, err)
		}
		// Stop dns tracer
		if err := ch.stopDNSTracing(); err != nil {
			logger.L().Error("error stopping dns tracing", helpers.Error(err))
			errs = errors.Join(errs, err)
		}
	}

	if ch.cfg.EnableRuntimeDetection {
		// Stop randomx tracer
		if runtime.GOARCH == "amd64" && ch.randomxTracer != nil {
			if err := ch.stopRandomxTracing(); err != nil {
				logger.L().Error("error stopping randomx tracing", helpers.Error(err))
				errs = errors.Join(errs, err)
			}
		}

		// Stop symlink tracer
		if err := ch.stopSymlinkTracing(); err != nil {
			logger.L().Error("error stopping symlink tracing", helpers.Error(err))
			errs = errors.Join(errs, err)
		}

		// Stop hardlink tracer
		if err := ch.stopHardlinkTracing(); err != nil {
			logger.L().Error("error stopping hardlink tracing", helpers.Error(err))
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
		logger.L().Debug("map entry", helpers.String("key", key), helpers.Int("value", int(value)))
	}
}

func (ch *IGContainerWatcher) unregisterContainer(container *containercollection.Container) {
	if ch.timeBasedContainers.Contains(container.Runtime.ContainerID) ||
		ch.ruleManagedPods.Contains(utils.CreateK8sPodID(container.K8s.Namespace, container.K8s.PodName)) {
		// the container should still be monitored
		logger.L().Debug("container should still be monitored",
			helpers.String("container ID", container.Runtime.ContainerID),
			helpers.String("namespace", container.K8s.Namespace), helpers.String("PodName", container.K8s.PodName), helpers.String("ContainerName", container.K8s.ContainerName),
		)
		return
	}

	logger.L().Info("stopping to monitor on container", helpers.String("container ID", container.Runtime.ContainerID), helpers.String("namespace", container.K8s.Namespace), helpers.String("PodName", container.K8s.PodName), helpers.String("ContainerName", container.K8s.ContainerName))

	ch.containerCollection.RemoveContainer(container.Runtime.ContainerID)

	// TODO: I dont think we need the following code ->
	event := containercollection.PubSubEvent{
		Timestamp: time.Now().Format(time.RFC3339),
		Type:      containercollection.EventTypeRemoveContainer,
		Container: container,
	}
	ch.tracerCollection.TracerMapsUpdater()(event)
}

func (ch *IGContainerWatcher) ignoreContainer(namespace, name string) bool {
	return name == ch.podName && namespace == ch.namespace
}
