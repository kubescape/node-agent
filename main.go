package main

import (
	"context"
	"strings"

	"net/http"
	"net/url"
	"node-agent/internal/validator"
	"node-agent/pkg/applicationprofilemanager"
	applicationprofilemanagerv1 "node-agent/pkg/applicationprofilemanager/v1"
	"node-agent/pkg/config"
	"node-agent/pkg/containerwatcher/v1"
	"node-agent/pkg/dnsmanager"
	"node-agent/pkg/filehandler/v1"
	metricsmanager "node-agent/pkg/metricsmanager"
	metricprometheus "node-agent/pkg/metricsmanager/prometheus"
	"node-agent/pkg/networkmanager"
	"node-agent/pkg/relevancymanager"
	relevancymanagerv1 "node-agent/pkg/relevancymanager/v1"
	rulebindingcache "node-agent/pkg/rulebindingmanager/cache"
	"node-agent/pkg/ruleengine/objectcache/applicationactivitiescache"
	"node-agent/pkg/ruleengine/objectcache/applicationprofilecache"
	"node-agent/pkg/ruleengine/objectcache/k8scache"
	"node-agent/pkg/ruleengine/objectcache/networkneighborscache"
	"node-agent/pkg/ruleengine/objectcache/v1"
	"node-agent/pkg/rulemanager"
	"node-agent/pkg/rulemanager/exporters"
	rulemanagerv1 "node-agent/pkg/rulemanager/v1"
	"node-agent/pkg/sbomhandler/syfthandler"
	"node-agent/pkg/storage/v1"
	"node-agent/pkg/utils"
	"node-agent/pkg/watcher/dynamicwatcher"
	"os"
	"os/signal"
	"syscall"

	utilsmetadata "github.com/armosec/utils-k8s-go/armometadata"

	beUtils "github.com/kubescape/backend/pkg/utils"
	"github.com/kubescape/go-logger"
	"github.com/kubescape/go-logger/helpers"
	"github.com/kubescape/k8s-interface/k8sinterface"
)

func main() {
	ctx := context.Background()

	cfg, err := config.LoadConfig("/etc/config")
	if err != nil {
		logger.L().Ctx(ctx).Fatal("load config error", helpers.Error(err))
	}

	clusterData, err := utilsmetadata.LoadConfig("/etc/config/clusterData.json")
	if err != nil {
		logger.L().Ctx(ctx).Fatal("load clusterData error", helpers.Error(err))
	}

	// to enable otel, set OTEL_COLLECTOR_SVC=otel-collector:4317
	if otelHost, present := os.LookupEnv("OTEL_COLLECTOR_SVC"); present {
		var accountId string
		if credentials, err := beUtils.LoadCredentialsFromFile("/etc/credentials"); err != nil {
			logger.L().Warning("failed to load credentials", helpers.Error(err))
		} else {
			accountId = credentials.Account
			logger.L().Info("credentials loaded", helpers.Int("accountLength", len(credentials.Account)))
		}

		ctx = logger.InitOtel("node-agent",
			os.Getenv("RELEASE"),
			accountId,
			clusterData.ClusterName,
			url.URL{Host: otelHost})
		defer logger.ShutdownOtel(ctx)
	}

	err = validator.CheckPrerequisites()
	if err != nil {
		logger.L().Ctx(ctx).Error("error during validation", helpers.Error(err))

		if strings.Contains(err.Error(), utils.ErrKernelVersion) {
			os.Exit(utils.ExitCodeIncompatibleKernel)
		} else {
			os.Exit(utils.ExitCodeError)
		}
	}

	if _, present := os.LookupEnv("ENABLE_PROFILER"); present {
		logger.L().Info("Starting profiler on port 6060")
		go func() {
			_ = http.ListenAndServe("localhost:6060", nil)
		}()
	}

	// Create clients
	k8sClient := k8sinterface.NewKubernetesApi()
	storageClient, err := storage.CreateStorageNoCache(clusterData.Namespace)
	if err != nil {
		logger.L().Ctx(ctx).Fatal("error creating the storage client", helpers.Error(err))
	}

	// Create Prometheus metrics exporter
	var prometheusExporter metricsmanager.MetricsManager
	if cfg.EnablePrometheusExporter {
		prometheusExporter = metricprometheus.NewPrometheusMetric()
	} else {
		prometheusExporter = metricsmanager.NewMetricsMock()
	}

	// Create the application profile manager
	var applicationProfileManager applicationprofilemanager.ApplicationProfileManagerClient
	if cfg.EnableApplicationProfile {
		applicationProfileManager, err = applicationprofilemanagerv1.CreateApplicationProfileManager(ctx, cfg, clusterData.ClusterName, k8sClient, storageClient)
		if err != nil {
			logger.L().Ctx(ctx).Fatal("error creating the application profile manager", helpers.Error(err))
		}
	} else {
		applicationProfileManager = applicationprofilemanager.CreateApplicationProfileManagerMock()
	}

	// Create the relevancy manager
	var relevancyManager relevancymanager.RelevancyManagerClient
	if cfg.EnableRelevancy {
		fileHandler, err := filehandler.CreateInMemoryFileHandler()
		if err != nil {
			logger.L().Ctx(ctx).Fatal("failed to create the filehandler for relevancy manager", helpers.Error(err))
		}

		sbomHandler := syfthandler.CreateSyftSBOMHandler(storageClient)
		relevancyManager, err = relevancymanagerv1.CreateRelevancyManager(ctx, cfg, clusterData.ClusterName, fileHandler, k8sClient, sbomHandler)
		if err != nil {
			logger.L().Ctx(ctx).Fatal("error creating the relevancy manager", helpers.Error(err))
		}
	} else {
		relevancyManager = relevancymanager.CreateRelevancyManagerMock()
	}

	// Create the relevancy manager
	var ruleManager rulemanager.RuleManagerClient
	if cfg.EnableRuntimeDetection {
		nodeName := os.Getenv(config.NodeNameEnvVar)
		// Create watchers
		dWatcher := dynamicwatcher.NewWatchHandler(k8sClient)

		// create ruleBinding cache
		ruleBindingCache := rulebindingcache.NewCache(nodeName, k8sClient)
		dWatcher.AddAdaptor(ruleBindingCache)

		// create k8sObject cache
		k8sObjectCache, err := k8scache.NewK8sObjectCache(nodeName, k8sClient)
		if err != nil {
			logger.L().Ctx(ctx).Fatal("error creating K8sObjectCache", helpers.Error(err))
		}
		dWatcher.AddAdaptor(k8sObjectCache)

		apc := applicationprofilecache.NewApplicationProfileCache(nodeName, k8sClient)
		dWatcher.AddAdaptor(apc)

		nnc := networkneighborscache.NewNetworkNeighborsCache(nodeName, k8sClient)
		dWatcher.AddAdaptor(nnc)

		aac := applicationactivitiescache.NewApplicationActivityCache(nodeName, k8sClient)
		dWatcher.AddAdaptor(aac)

		// start watching
		dWatcher.Start(ctx)

		// create object cache
		objCache := objectcache.NewObjectCache(k8sObjectCache, apc, aac, nnc)

		// create exporter
		ex := exporters.InitExporters(cfg.Exporters)

		// create runtimeDetection manager
		ruleManager, err = rulemanagerv1.CreateRuleManager(ctx, cfg, k8sClient, ruleBindingCache, objCache, ex, prometheusExporter)
		if err != nil {
			logger.L().Ctx(ctx).Fatal("error creating RuleManager", helpers.Error(err))
		}
	} else {
		ruleManager = rulemanager.CreateRuleManagerMock()
	}

	// Create the network and DNS managers
	var networkManagerClient networkmanager.NetworkManagerClient
	var dnsManagerClient dnsmanager.DNSManagerClient
	if cfg.EnableNetworkTracing {
		dnsManager := dnsmanager.CreateDNSManager()
		dnsManagerClient = dnsManager
		networkManagerClient = networkmanager.CreateNetworkManager(ctx, cfg, k8sClient, storageClient, clusterData.ClusterName, dnsManager)
	} else {
		networkManagerClient = networkmanager.CreateNetworkManagerMock()
		dnsManagerClient = dnsmanager.CreateDNSManagerMock()
	}

	// Create the container handler
	mainHandler, err := containerwatcher.CreateIGContainerWatcher(cfg, applicationProfileManager, k8sClient, relevancyManager, networkManagerClient, dnsManagerClient, prometheusExporter, ruleManager)
	if err != nil {
		logger.L().Ctx(ctx).Fatal("error creating the container watcher", helpers.Error(err))
	}

	// Start the prometheusExporter
	prometheusExporter.Start()

	// Start the container handler
	err = mainHandler.Start(ctx)
	if err != nil {
		logger.L().Ctx(ctx).Error("error starting the container watcher", helpers.Error(err))
		switch {
		case strings.Contains(err.Error(), utils.ErrKernelVersion):
			os.Exit(utils.ExitCodeIncompatibleKernel)
		case strings.Contains(err.Error(), utils.ErrMacOS):
			os.Exit(utils.ExitCodeMacOS)
		default:
			os.Exit(utils.ExitCodeError)
		}
	}
	defer mainHandler.Stop()

	// Wait for shutdown signal
	shutdown := make(chan os.Signal, 1)
	signal.Notify(shutdown, os.Interrupt, syscall.SIGTERM)
	<-shutdown

	// Exit with success
	os.Exit(utils.ExitCodeSuccess)
}
