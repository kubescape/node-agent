package containerwatcher

import (
	"context"
	"fmt"
	"node-agent/pkg/config"
	"node-agent/pkg/utils"
	"os"
	"time"

	containercollection "github.com/inspektor-gadget/inspektor-gadget/pkg/container-collection"
	"github.com/kubescape/go-logger"
	"github.com/kubescape/go-logger/helpers"
)

func (ch *IGContainerWatcher) containerCallback(notif containercollection.PubSubEvent) {
	if notif.Type == containercollection.EventTypeAddContainer {
		time.AfterFunc(ch.cfg.MaxSniffingTime, func() {
			k8sContainerID := utils.CreateK8sContainerID(notif.Container.K8s.Namespace, notif.Container.K8s.PodName, notif.Container.K8s.ContainerName)
			logger.L().Info("stop monitor on container - after monitoring time", helpers.String("container ID", notif.Container.Runtime.ContainerID), helpers.String("k8s workload", k8sContainerID))
			ch.unregisterContainer(notif.Container)
		})
	}
}

func (ch *IGContainerWatcher) startContainerCollection(ctx context.Context) error {
	ch.ctx = ctx

	// Start the container collection
	containerEventFuncs := []containercollection.FuncNotify{
		ch.containerCallback,
		ch.relevancyManager.ContainerCallback,
	}

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
		return fmt.Errorf("initializing container collection: %w", err)
	}

	return nil
}

func (ch *IGContainerWatcher) stopContainerCollection() {
	if ch.containerCollection != nil {
		ch.tracerCollection.Close()
		ch.containerCollection.Close()
	}
}

func (ch *IGContainerWatcher) startTracers() error {
	var err error
	// Start capabilities tracer
	err = ch.startCapabilitiesTracing()
	if err != nil {
		logger.L().Error("error starting capabilities tracing", helpers.Error(err))
		return err
	}
	// Start exec tracer
	err = ch.startExecTracing()
	if err != nil {
		logger.L().Error("error starting exec tracing", helpers.Error(err))
		return err
	}
	// Start open tracer
	err = ch.startOpenTracing()
	if err != nil {
		logger.L().Error("error starting open tracing", helpers.Error(err))
		return err
	}
	// Start syscall tracer
	err = ch.startSystemcallTracing()
	if err != nil {
		logger.L().Error("error starting seccomp tracing", helpers.Error(err))
		return err
	}
	return nil
}

func (ch *IGContainerWatcher) stopTracers() error {
	var err error
	// Stop capabilities tracer
	if err = ch.stopCapabilitiesTracing(); err != nil {
		logger.L().Error("error stopping capabilities tracing", helpers.Error(err))
	}
	// Stop exec tracer
	if err = ch.stopExecTracing(); err != nil {
		logger.L().Error("error stopping exec tracing", helpers.Error(err))
	}
	// Stop open tracer
	if err = ch.stopOpenTracing(); err != nil {
		logger.L().Error("error stopping open tracing", helpers.Error(err))
	}
	// Stop syscall tracer
	if err = ch.stopSystemcallTracing(); err != nil {
		logger.L().Error("error stopping seccomp tracing", helpers.Error(err))
	}
	return err
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
	event := containercollection.PubSubEvent{
		Timestamp: time.Now().Format(time.RFC3339),
		Type:      containercollection.EventTypeRemoveContainer,
		Container: container,
	}
	ch.tracerCollection.TracerMapsUpdater()(event)
	ch.relevancyManager.ContainerCallback(event)
}
