package hostwatcher

import (
	"context"
	"errors"
	"fmt"

	containercollection "github.com/inspektor-gadget/inspektor-gadget/pkg/container-collection"
	"github.com/inspektor-gadget/inspektor-gadget/pkg/utils/host"
	"github.com/kubescape/go-logger"
	"github.com/kubescape/go-logger/helpers"
)

const (
	MaxSniffingTimeLabel = "kubescape.io/max-sniffing-time"
)

func (ch *IGHostWatcher) startContainerCollection(ctx context.Context) error {
	ch.ctx = ctx

	// This is needed when not running as gadget.
	// https://github.com/inspektor-gadget/inspektor-gadget/blob/9a797dc046f8bc1f45e85f15db7e99dd4e5cb6e5/cmd/ig/containers/containers.go#L45-L46
	if err := host.Init(host.Config{AutoMountFilesystems: true}); err != nil {
		return fmt.Errorf("initializing host package: %w", err)
	}

	// Define the different options for the container collection instance
	opts := []containercollection.ContainerCollectionOption{
		// Enrich events with OCI config information
		containercollection.WithOCIConfigEnrichment(),

		// Get containers enriched with cgroup information
		containercollection.WithCgroupEnrichment(),

		// Enrich events with Linux namespaces information, it is needed for per container filtering
		containercollection.WithLinuxNamespaceEnrichment(),

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

	return nil
}

func (ch *IGHostWatcher) startTracers() error {
	if ch.cfg.EnableHostMalwareSensor {
		// Start exec tracer
		if err := ch.startExecTracing(); err != nil {
			logger.L().Error("IGHostWatcher - error starting exec tracing", helpers.Error(err))
			return err
		}
		logger.L().Info("started exec tracing")
		// Start open tracer
		if err := ch.startOpenTracing(); err != nil {
			logger.L().Error("IGHostWatcher - error starting open tracing", helpers.Error(err))
			return err
		}
		logger.L().Info("started open tracing")
	}

	return nil
}

func (ch *IGHostWatcher) stopTracers() error {
	var errs error

	if ch.cfg.EnableHostMalwareSensor {
		// Stop exec tracer
		if err := ch.stopExecTracing(); err != nil {
			logger.L().Error("IGHostWatcher - error stopping exec tracing", helpers.Error(err))
			errs = errors.Join(errs, err)
		}
		// Stop open tracer
		if err := ch.stopOpenTracing(); err != nil {
			logger.L().Error("IGHostWatcher - error stopping open tracing", helpers.Error(err))
			errs = errors.Join(errs, err)
		}
	}

	return errs
}

//lint:ignore U1000 Ignore unused function temporarily for debugging
func (ch *IGHostWatcher) printNsMap(id string) {
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
