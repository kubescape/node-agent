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
	"node-agent/pkg/exporters"
	"node-agent/pkg/filehandler/v1"
	"node-agent/pkg/malwaremanager"
	malwaremanagerv1 "node-agent/pkg/malwaremanager/v1"
	"node-agent/pkg/metricsmanager"
	metricprometheus "node-agent/pkg/metricsmanager/prometheus"
	"node-agent/pkg/networkmanager"
	networkmanagerv1 "node-agent/pkg/networkmanager/v1"
	networkmanagerv2 "node-agent/pkg/networkmanager/v2"
	"node-agent/pkg/objectcache"
	"node-agent/pkg/objectcache/applicationprofilecache"
	"node-agent/pkg/objectcache/k8scache"
	"node-agent/pkg/objectcache/networkneighborscache"
	objectcachev1 "node-agent/pkg/objectcache/v1"
	"node-agent/pkg/relevancymanager"
	relevancymanagerv1 "node-agent/pkg/relevancymanager/v1"
	rulebinding "node-agent/pkg/rulebindingmanager"
	rulebindingcachev1 "node-agent/pkg/rulebindingmanager/cache"
	"node-agent/pkg/rulemanager"
	rulemanagerv1 "node-agent/pkg/rulemanager/v1"
	"node-agent/pkg/sbomhandler/syfthandler"
	"node-agent/pkg/storage/v1"
	"node-agent/pkg/utils"
	"node-agent/pkg/watcher/dynamicwatcher"
	"os"
	"os/signal"
	"syscall"

	utilsmetadata "github.com/armosec/utils-k8s-go/armometadata"
	mapset "github.com/deckarep/golang-set/v2"

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
	storageClient, err := storage.CreateStorage(clusterData.Namespace)
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

	nodeName := os.Getenv(config.NodeNameEnvVar)
	// Create watchers
	dWatcher := dynamicwatcher.NewWatchHandler(k8sClient)
	// create k8sObject cache
	k8sObjectCache, err := k8scache.NewK8sObjectCache(nodeName, k8sClient)
	if err != nil {
		logger.L().Ctx(ctx).Fatal("error creating K8sObjectCache", helpers.Error(err))
	}
	dWatcher.AddAdaptor(k8sObjectCache)

	// Initiate pre-existing containers
	preRunningContainersIDs := mapset.NewSet[string]() // Set of container IDs

	// Create the application profile manager
	var applicationProfileManager applicationprofilemanager.ApplicationProfileManagerClient
	if cfg.EnableApplicationProfile {
		applicationProfileManager, err = applicationprofilemanagerv1.CreateApplicationProfileManager(ctx, cfg, clusterData.ClusterName, k8sClient, storageClient, preRunningContainersIDs, k8sObjectCache)
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
		relevancyManager, err = relevancymanagerv1.CreateRelevancyManager(ctx, cfg, clusterData.ClusterName, fileHandler, k8sClient, sbomHandler, preRunningContainersIDs)
		if err != nil {
			logger.L().Ctx(ctx).Fatal("error creating the relevancy manager", helpers.Error(err))
		}
	} else {
		relevancyManager = relevancymanager.CreateRelevancyManagerMock()
	}

	var ruleManager rulemanager.RuleManagerClient
	var objCache objectcache.ObjectCache
	var ruleBindingNotify chan rulebinding.RuleBindingNotify

	if cfg.EnableRuntimeDetection {

		// create ruleBinding cache
		ruleBindingCache := rulebindingcachev1.NewCache(nodeName, k8sClient)
		dWatcher.AddAdaptor(ruleBindingCache)

		ruleBindingNotify = make(chan rulebinding.RuleBindingNotify, 100)
		ruleBindingCache.AddNotifier(&ruleBindingNotify)

		apc := applicationprofilecache.NewApplicationProfileCache(nodeName, k8sClient)
		dWatcher.AddAdaptor(apc)

		nnc := networkneighborscache.NewNetworkNeighborsCache(nodeName, k8sClient)
		dWatcher.AddAdaptor(nnc)

		// create object cache
		objCache = objectcachev1.NewObjectCache(k8sObjectCache, apc, nnc)

		// create exporter
		exporter := exporters.InitExporters(cfg.Exporters, clusterData.ClusterName, nodeName)

		// create runtimeDetection managers
		ruleManager, err = rulemanagerv1.CreateRuleManager(ctx, cfg, k8sClient, ruleBindingCache, objCache, exporter, prometheusExporter, preRunningContainersIDs, nodeName, clusterData.ClusterName)
		if err != nil {
			logger.L().Ctx(ctx).Fatal("error creating RuleManager", helpers.Error(err))
		}

	} else {
		ruleManager = rulemanager.CreateRuleManagerMock()
		objCache = objectcache.NewObjectCacheMock()
		ruleBindingNotify = make(chan rulebinding.RuleBindingNotify, 1)
	}

	var malwareManager malwaremanager.MalwareManagerClient
	if cfg.EnableMalwareDetection {
		// create exporter
		exporter := exporters.InitExporters(cfg.Exporters, clusterData.ClusterName, nodeName)
		malwareManager, err = malwaremanagerv1.CreateMalwareManager(cfg, k8sClient, nodeName, clusterData.ClusterName, exporter, prometheusExporter)
		if err != nil {
			logger.L().Ctx(ctx).Fatal("error creating MalwareManager", helpers.Error(err))
		}
	} else {
		malwareManager = malwaremanager.CreateMalwareManagerMock()
	}

	// Create the network and DNS managers
	var networkManagerv1Client networkmanagerv1.NetworkManagerClient
	var networkManagerClient networkmanager.NetworkManagerClient
	var dnsManagerClient dnsmanager.DNSManagerClient
	if cfg.EnableNetworkTracing {
		dnsManager := dnsmanager.CreateDNSManager()
		dnsManagerClient = dnsManager
		networkManagerv1Client = networkmanagerv1.CreateNetworkManager(ctx, cfg, k8sClient, storageClient, clusterData.ClusterName, dnsManager, preRunningContainersIDs, k8sObjectCache)
		networkManagerClient = networkmanagerv2.CreateNetworkManager(ctx, cfg, clusterData.ClusterName, k8sClient, storageClient, dnsManager, preRunningContainersIDs, k8sObjectCache)
	} else {
		networkManagerv1Client = networkmanagerv1.CreateNetworkManagerMock()
		networkManagerClient = networkmanager.CreateNetworkManagerMock()
		dnsManagerClient = dnsmanager.CreateDNSManagerMock()
	}

	// Create the container handler
	mainHandler, err := containerwatcher.CreateIGContainerWatcher(cfg, applicationProfileManager, k8sClient, relevancyManager, networkManagerv1Client, networkManagerClient, dnsManagerClient, prometheusExporter, ruleManager, malwareManager, preRunningContainersIDs, &ruleBindingNotify)
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

	// start watching
	dWatcher.Start(ctx)
	defer dWatcher.Stop(ctx)

	// Wait for shutdown signal
	shutdown := make(chan os.Signal, 1)
	signal.Notify(shutdown, os.Interrupt, syscall.SIGTERM)
	<-shutdown

	// Exit with success
	os.Exit(utils.ExitCodeSuccess)
}
