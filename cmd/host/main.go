package main

import (
	"context"
	"net/http"
	_ "net/http/pprof"
	"os"
	"os/signal"
	"strings"
	"syscall"

	apitypes "github.com/armosec/armoapi-go/armotypes"
	utilsmetadata "github.com/armosec/utils-k8s-go/armometadata"
	"github.com/cilium/ebpf/rlimit"
	"github.com/grafana/pyroscope-go"
	"github.com/kubescape/go-logger"
	"github.com/kubescape/go-logger/helpers"
	"github.com/kubescape/node-agent/pkg/cloudmetadata"
	"github.com/kubescape/node-agent/pkg/config"
	"github.com/kubescape/node-agent/pkg/dnsmanager"
	"github.com/kubescape/node-agent/pkg/exporters"
	"github.com/kubescape/node-agent/pkg/healthmanager"
	hosthashsensorv1 "github.com/kubescape/node-agent/pkg/hosthashsensor/v1"
	hostnetworksensor "github.com/kubescape/node-agent/pkg/hostnetworksensor"
	hostnetworksensorv1 "github.com/kubescape/node-agent/pkg/hostnetworksensor/v1"
	hostrulemanagerv1 "github.com/kubescape/node-agent/pkg/hostrulemanager/v1"
	hostwatcherv1 "github.com/kubescape/node-agent/pkg/hostwatcher/v1"
	"github.com/kubescape/node-agent/pkg/metricsmanager"
	metricprometheus "github.com/kubescape/node-agent/pkg/metricsmanager/prometheus"
	"github.com/kubescape/node-agent/pkg/processmanager"
	processmanagerv1 "github.com/kubescape/node-agent/pkg/processmanager/v1"
	"github.com/kubescape/node-agent/pkg/utils"
	"github.com/kubescape/node-agent/pkg/validator"
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

	// Check if we need to validate the kernel version.
	if os.Getenv("SKIP_KERNEL_VERSION_CHECK") == "" {
		err = validator.CheckPrerequisites(cfg)
		if err != nil {
			logger.L().Ctx(ctx).Error("error during kernel validation", helpers.Error(err))

			if strings.Contains(err.Error(), utils.ErrKernelVersion) {
				os.Exit(utils.ExitCodeIncompatibleKernel)
			} else {
				os.Exit(utils.ExitCodeError)
			}
		}
	} else {
		if err := rlimit.RemoveMemlock(); err != nil {
			logger.L().Ctx(ctx).Error("error removing memlock limit", helpers.Error(err))
			os.Exit(utils.ExitCodeError)
		}
	}

	if _, present := os.LookupEnv("ENABLE_PROFILER"); present {
		logger.L().Info("starting profiler on port 6060")
		go func() {
			_ = http.ListenAndServe("localhost:6060", nil)
		}()
	}

	if pyroscopeServerSvc, present := os.LookupEnv("PYROSCOPE_SERVER_SVC"); present {
		logger.L().Info("starting pyroscope profiler")

		if os.Getenv("APPLICATION_NAME") == "" {
			os.Setenv("APPLICATION_NAME", "node-agent")
		}

		_, err := pyroscope.Start(pyroscope.Config{
			ApplicationName: os.Getenv("APPLICATION_NAME"),
			ServerAddress:   pyroscopeServerSvc,
			Logger:          pyroscope.StandardLogger,
			Tags:            map[string]string{"node": cfg.NodeName, "app": "node-agent", "pod": os.Getenv("POD_NAME")},
		})

		if err != nil {
			logger.L().Ctx(ctx).Error("error starting pyroscope", helpers.Error(err))
		}
	}

	if m := os.Getenv("MULTIPLY"); m == "true" {
		logger.L().Info("MULTIPLY environment variable is true. Multiplying feature enabled - this is a feature for testing purposes only")
	}

	// Start the health manager
	healthManager := healthmanager.NewHealthManager()
	healthManager.Start(ctx)

	// Create clients
	logger.L().Info("Kubernetes mode is false")

	// Create Prometheus metrics exporter
	var prometheusExporter metricsmanager.MetricsManager
	if cfg.EnablePrometheusExporter {
		prometheusExporter = metricprometheus.NewPrometheusMetric()
	} else {
		prometheusExporter = metricsmanager.NewMetricsMock()
	}

	var processManager processmanager.ProcessManagerClient
	var dnsManagerClient dnsmanager.DNSManagerClient
	var dnsResolver dnsmanager.DNSResolver
	var hostHashSensor hosthashsensorv1.HostHashSensorServiceInterface
	var hostNetworkSensor hostnetworksensor.HostNetworkSensorClient
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

		if cfg.EnableHostNetworkSensor {
			dnsManager := dnsmanager.CreateDNSManager()
			dnsManagerClient = dnsManager
			dnsResolver = dnsManager

			hostNetworkSensor, err = hostnetworksensorv1.CreateHostNetworkSensor(exporter, dnsResolver, processManager)
			if err != nil {
				logger.L().Ctx(ctx).Fatal("error creating HostNetworkSensor", helpers.Error(err))
			}
		} else {
			hostNetworkSensor = hostnetworksensor.CreateHostNetworkSensorMock()
		}

	} else {
		hostHashSensor = hosthashsensorv1.CreateHostHashSensorMock()
		processManager = processmanager.CreateProcessManagerMock()
		hostNetworkSensor = hostnetworksensor.CreateHostNetworkSensorMock()
		dnsManagerClient = dnsmanager.CreateDNSManagerMock()
	}

	// create exporter
	exporter := exporters.InitExporters(cfg.Exporters, clusterData.ClusterName, cfg.NodeName, cloudMetadata)
	hostRuleManager := hostrulemanagerv1.NewRuleManager(ctx, exporter, nil, processManager)
	hostWatcher, err := hostwatcherv1.CreateIGHostWatcher(cfg, prometheusExporter, processManager, hostHashSensor, hostRuleManager, hostNetworkSensor, dnsManagerClient)
	if err != nil {
		logger.L().Ctx(ctx).Fatal("error creating the host watcher", helpers.Error(err))
	}
	err = hostWatcher.Start(ctx)
	if err != nil {
		logger.L().Ctx(ctx).Error("error starting the host watcher", helpers.Error(err))
	}
	defer hostWatcher.Stop()

	// Wait for shutdown signal
	shutdown := make(chan os.Signal, 1)
	signal.Notify(shutdown, os.Interrupt, syscall.SIGTERM)
	<-shutdown

	// Exit with success
	os.Exit(utils.ExitCodeSuccess)
}
