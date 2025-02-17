package hostwatcher

import (
	"context"
	"errors"
	"fmt"
	"runtime"

	containercollection "github.com/inspektor-gadget/inspektor-gadget/pkg/container-collection"
	"github.com/inspektor-gadget/inspektor-gadget/pkg/socketenricher"
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
	if ch.cfg.EnableHostMalwareSensor || ch.cfg.EnableRuntimeDetection {
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

	if ch.cfg.EnableRuntimeDetection {
		socketEnricher, err := socketenricher.NewSocketEnricher()
		if err != nil {
			logger.L().Error("IGContainerWatcher - error creating socket enricher", helpers.Error(err))
			return err
		}
		ch.socketEnricher = socketEnricher

		// Start network tracer
		if err := ch.startNetworkTracing(); err != nil {
			logger.L().Error("IGHostWatcher - error starting network tracing", helpers.Error(err))
			return err
		}
		logger.L().Info("started network tracing")
		// Start dns tracer
		if err := ch.startDNSTracing(); err != nil {
			logger.L().Error("IGHostWatcher - error starting dns tracing", helpers.Error(err))
			return err
		}
		logger.L().Info("started dns tracing")
		// Start http tracer
		if err := ch.startHttpTracing(); err != nil {
			logger.L().Error("IGHostWatcher - error starting http tracing", helpers.Error(err))
			return err
		}
		logger.L().Info("started http tracing")
		// Start capabilities tracer
		if err := ch.startCapabilitiesTracing(); err != nil {
			logger.L().Error("IGHostWatcher - error starting capabilities tracing", helpers.Error(err))
			return err
		}
		logger.L().Info("started capabilities tracing")
		// Start symlink tracer
		if err := ch.startSymlinkTracing(); err != nil {
			logger.L().Error("IGHostWatcher - error starting symlink tracing", helpers.Error(err))
			return err
		}
		logger.L().Info("started symlink tracing")
		// Start hardlink tracer
		if err := ch.startHardlinkTracing(); err != nil {
			logger.L().Error("IGHostWatcher - error starting hardlink tracing", helpers.Error(err))
			return err
		}
		logger.L().Info("started hardlink tracing")
		// Start iouring tracer
		if err := ch.startIouringTracing(); err != nil {
			logger.L().Error("IGHostWatcher - error starting iouring tracing", helpers.Error(err))
			return err
		}
		logger.L().Info("started iouring tracing")
		if runtime.GOARCH == "amd64" {
			if err := ch.startRandomxTracing(); err != nil {
				logger.L().Error("IGHostWatcher - error starting randomx tracing", helpers.Error(err))
				return err
			}
			logger.L().Info("started randomx tracing")
		} else {
			logger.L().Warning("randomx tracing is not supported on this architecture", helpers.String("architecture", runtime.GOARCH))
		}
		// Start ssh tracer
		if err := ch.startSshTracing(); err != nil {
			logger.L().Error("IGHostWatcher - error starting ssh tracing", helpers.Error(err))
			return err
		}
		logger.L().Info("started ssh tracing")
		// Start ptrace tracer
		if err := ch.startPtraceTracing(); err != nil {
			logger.L().Error("IGHostWatcher - error starting ptrace tracing", helpers.Error(err))
			return err
		}
		logger.L().Info("started ptrace tracing")
		// Start syscall tracer
		if err := ch.startSystemcallTracing(); err != nil {
			logger.L().Error("IGHostWatcher - error starting syscall tracing", helpers.Error(err))
			return err
		}
		logger.L().Info("started syscalls tracing")
	}

	return nil
}

func (ch *IGHostWatcher) stopTracers() error {
	var errs error

	if ch.cfg.EnableHostMalwareSensor || ch.cfg.EnableRuntimeDetection {
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

	if ch.cfg.EnableRuntimeDetection {
		// Stop network tracer
		if err := ch.stopNetworkTracing(); err != nil {
			logger.L().Error("IGHostWatcher - error stopping network tracing", helpers.Error(err))
			errs = errors.Join(errs, err)
		}
		// Stop dns tracer
		if err := ch.stopDNSTracing(); err != nil {
			logger.L().Error("IGHostWatcher - error stopping dns tracing", helpers.Error(err))
			errs = errors.Join(errs, err)
		}
		// Stop http tracer
		if err := ch.stopHttpTracing(); err != nil {
			logger.L().Error("IGHostWatcher - error stopping http tracing", helpers.Error(err))
			errs = errors.Join(errs, err)
		}
		// Stop capabilities tracer
		if err := ch.stopCapabilitiesTracing(); err != nil {
			logger.L().Error("IGHostWatcher - error stopping capabilities tracing", helpers.Error(err))
			errs = errors.Join(errs, err)
		}
		// Stop symlink tracer
		if err := ch.stopSymlinkTracing(); err != nil {
			logger.L().Error("IGHostWatcher - error stopping symlink tracing", helpers.Error(err))
			errs = errors.Join(errs, err)
		}
		// Stop hardlink tracer
		if err := ch.stopHardlinkTracing(); err != nil {
			logger.L().Error("IGHostWatcher - error stopping hardlink tracing", helpers.Error(err))
			errs = errors.Join(errs, err)
		}
		// Stop iouring tracer
		if err := ch.stopIouringTracing(); err != nil {
			logger.L().Error("IGHostWatcher - error stopping iouring tracing", helpers.Error(err))
			errs = errors.Join(errs, err)
		}
		if runtime.GOARCH == "amd64" {
			if err := ch.stopRandomxTracing(); err != nil {
				logger.L().Error("IGHostWatcher - error stopping randomx tracing", helpers.Error(err))
				errs = errors.Join(errs, err)
			}
		}
		// Stop ssh tracer
		if err := ch.stopSshTracing(); err != nil {
			logger.L().Error("IGHostWatcher - error stopping ssh tracing", helpers.Error(err))
			errs = errors.Join(errs, err)
		}
		// Stop ptrace tracer
		if err := ch.stopPtraceTracing(); err != nil {
			logger.L().Error("IGHostWatcher - error stopping ptrace tracing", helpers.Error(err))
			errs = errors.Join(errs, err)
		}
		// Stop syscall tracer
		if err := ch.stopSystemcallTracing(); err != nil {
			logger.L().Error("IGHostWatcher - error stopping syscall tracing", helpers.Error(err))
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
