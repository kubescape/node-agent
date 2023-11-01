package containerwatcher

import (
	"context"
	"errors"
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
	k8sContainerID := utils.CreateK8sContainerID(notif.Container.K8s.Namespace, notif.Container.K8s.PodName, notif.Container.K8s.ContainerName)
	switch notif.Type {
	case containercollection.EventTypeAddContainer:
		logger.L().Info("start monitor on container", helpers.String("container ID", notif.Container.Runtime.ContainerID), helpers.String("k8s workload", k8sContainerID))
		time.AfterFunc(ch.cfg.MaxSniffingTime, func() {
			logger.L().Info("stop monitor on container - after monitoring time", helpers.String("container ID", notif.Container.Runtime.ContainerID), helpers.String("k8s workload", k8sContainerID))
			ch.unregisterContainer(notif.Container)
		})
	case containercollection.EventTypeRemoveContainer:
		logger.L().Info("stop monitor on container - container has terminated", helpers.String("container ID", notif.Container.Runtime.ContainerID), helpers.String("k8s workload", k8sContainerID))
	}
}

func (ch *IGContainerWatcher) startContainerCollection(ctx context.Context) error {
	ch.ctx = ctx

	// Start the container collection
	containerEventFuncs := []containercollection.FuncNotify{
		ch.containerCallback,
		ch.applicationProfileManager.ContainerCallback,
		ch.relevancyManager.ContainerCallback,
		ch.networkManager.ContainerCallback,
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
	if ch.cfg.EnableApplicationProfile {
		// Start capabilities tracer
		if err := ch.startCapabilitiesTracing(); err != nil {
			logger.L().Error("error starting capabilities tracing", helpers.Error(err))
			return err
		}
		// Start syscall tracer
		if err := ch.startSystemcallTracing(); err != nil {
			logger.L().Error("error starting seccomp tracing", helpers.Error(err))
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
		// Start network tracer
		if err := ch.startNetworkTracing(); err != nil {
			logger.L().Error("error starting network tracing", helpers.Error(err))
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
			errs = errors.Join(err, ch.stopCapabilitiesTracing())
		}
		// Stop syscall tracer
		if err := ch.stopSystemcallTracing(); err != nil {
			logger.L().Error("error stopping seccomp tracing", helpers.Error(err))
			errs = errors.Join(err, ch.stopCapabilitiesTracing())
		}
	}
	if ch.cfg.EnableRelevancy || ch.cfg.EnableApplicationProfile {
		// Stop exec tracer
		if err := ch.stopExecTracing(); err != nil {
			logger.L().Error("error stopping exec tracing", helpers.Error(err))
			errs = errors.Join(err, ch.stopCapabilitiesTracing())
		}
		// Stop open tracer
		if err := ch.stopOpenTracing(); err != nil {
			logger.L().Error("error stopping open tracing", helpers.Error(err))
			errs = errors.Join(err, ch.stopCapabilitiesTracing())
		}
	}

	if ch.cfg.EnableNetworkTracing {
		// Stop network tracer
		if err := ch.stopNetworkTracing(); err != nil {
			logger.L().Error("error stopping network tracing", helpers.Error(err))
			errs = errors.Join(err, ch.stopNetworkTracing())
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
	event := containercollection.PubSubEvent{
		Timestamp: time.Now().Format(time.RFC3339),
		Type:      containercollection.EventTypeRemoveContainer,
		Container: container,
	}
	ch.tracerCollection.TracerMapsUpdater()(event)
	ch.applicationProfileManager.ContainerCallback(event)
	ch.relevancyManager.ContainerCallback(event)
	ch.networkManager.ContainerCallback(event)
}
