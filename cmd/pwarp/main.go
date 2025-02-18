package main

import (
	"context"
	_ "net/http/pprof"
	"os"
	"os/signal"
	"syscall"

	apitypes "github.com/armosec/armoapi-go/armotypes"
	utilsmetadata "github.com/armosec/utils-k8s-go/armometadata"
	"github.com/kubescape/go-logger"
	"github.com/kubescape/go-logger/helpers"
	"github.com/kubescape/node-agent/pkg/cloudmetadata"
	"github.com/kubescape/node-agent/pkg/config"
	"github.com/kubescape/node-agent/pkg/exporters"
	"github.com/kubescape/node-agent/pkg/healthmanager"
	hosthashsensorv1 "github.com/kubescape/node-agent/pkg/hosthashsensor/v1"
	hostrulemanagerv1 "github.com/kubescape/node-agent/pkg/hostrulemanager/v1"
	"github.com/kubescape/node-agent/pkg/metricsmanager"
	"github.com/kubescape/node-agent/pkg/processmanager"
	processmanagerv1 "github.com/kubescape/node-agent/pkg/processmanager/v1"
	"github.com/kubescape/node-agent/pkg/ptracewatcher"
	"github.com/kubescape/node-agent/pkg/utils"
)

func main() {
	ctx := context.Background()

	configDir := "/etc/config"
	if envPath := os.Getenv("CONFIG_DIR"); envPath != "" {
		configDir = envPath
	}

	cfg, err := config.LoadConfig(configDir)
	if err != nil {
		logger.L().Ctx(ctx).Fatal("load config error", helpers.Error(err))
	}

	clusterData := &utilsmetadata.ClusterConfig{
		ClusterName: "local",
	}

	// Start the health manager
	healthManager := healthmanager.NewHealthManager()
	healthManager.Start(ctx)

	// Create Prometheus metrics exporter

	prometheusExporter := metricsmanager.NewMetricsMock()

	var processManager processmanager.ProcessManagerClient
	var hostHashSensor hosthashsensorv1.HostHashSensorServiceInterface
	var cloudMetadata *apitypes.CloudMetadata

	if cfg.EnableRuntimeDetection || cfg.EnableMalwareDetection {
		cloudMetadata, err = cloudmetadata.GetCloudMetadataWithIMDS(ctx)
		if err != nil {
			logger.L().Ctx(ctx).Error("error getting cloud metadata with IMDS", helpers.Error(err))
		}
	}

	if cfg.EnableRuntimeDetection {
		// create the process manager
		processManager = processmanagerv1.CreateProcessManager(ctx)

		// create exporter
		exporter := exporters.InitExporters(cfg.Exporters, clusterData.ClusterName, cfg.NodeName, cloudMetadata)

		if cfg.EnableHostMalwareSensor {
			hostHashSensor, err = hosthashsensorv1.CreateHostHashSensor(cfg, exporter, prometheusExporter)
			if err != nil {
				logger.L().Ctx(ctx).Fatal("error creating HostHashSensor", helpers.Error(err))
			}
		} else {
			hostHashSensor = hosthashsensorv1.CreateHostHashSensorMock()
		}

	} else {
		hostHashSensor = hosthashsensorv1.CreateHostHashSensorMock()
		processManager = processmanager.CreateProcessManagerMock()
	}

	// create exporter
	exporter := exporters.InitExporters(cfg.Exporters, clusterData.ClusterName, cfg.NodeName, cloudMetadata)
	hostRuleManager := hostrulemanagerv1.NewRuleManager(ctx, exporter, nil, processManager)
	ptraceWatcher, err := ptracewatcher.CreatePtraceWatcher(cfg, prometheusExporter, processManager, hostHashSensor, hostRuleManager)
	if err != nil {
		logger.L().Ctx(ctx).Fatal("error creating the host watcher", helpers.Error(err))
	}

	err = ptraceWatcher.Start(os.Args[1:])
	if err != nil {
		logger.L().Ctx(ctx).Fatal("error starting the host watcher", helpers.Error(err))
	}
	logger.L().Info("PtraceWatcher started in pid", helpers.Int("pid", os.Getpid()))

	// Wait for shutdown signal
	shutdown := make(chan os.Signal, 1)
	signal.Notify(shutdown, os.Interrupt, syscall.SIGTERM)
	<-shutdown

	// Exit with success
	os.Exit(utils.ExitCodeSuccess)
}
