package main

import (
	"context"
	"net/http"
	_ "net/http/pprof"
	"net/url"
	"os"
	"os/signal"
	"strings"
	"syscall"

	apitypes "github.com/armosec/armoapi-go/armotypes"
	utilsmetadata "github.com/armosec/utils-k8s-go/armometadata"
	"github.com/cilium/ebpf/rlimit"
	mapset "github.com/deckarep/golang-set/v2"
	"github.com/goradd/maps"
	"github.com/grafana/pyroscope-go"

	igconfig "github.com/inspektor-gadget/inspektor-gadget/pkg/config"
	containercollection "github.com/inspektor-gadget/inspektor-gadget/pkg/container-collection"
	beUtils "github.com/kubescape/backend/pkg/utils"
	"github.com/kubescape/go-logger"
	"github.com/kubescape/go-logger/helpers"
	"github.com/kubescape/k8s-interface/k8sinterface"
	"github.com/kubescape/node-agent/pkg/cloudmetadata"
	"github.com/kubescape/node-agent/pkg/config"
	"github.com/kubescape/node-agent/pkg/containerprofilemanager"
	containerprofilemanagerv1 "github.com/kubescape/node-agent/pkg/containerprofilemanager/v1"
	"github.com/kubescape/node-agent/pkg/containerwatcher"
	containerwatcherv2 "github.com/kubescape/node-agent/pkg/containerwatcher/v2"
	"github.com/kubescape/node-agent/pkg/dnsmanager"
	"github.com/kubescape/node-agent/pkg/exporters"
	"github.com/kubescape/node-agent/pkg/healthmanager"
	"github.com/kubescape/node-agent/pkg/malwaremanager"
	malwaremanagerv1 "github.com/kubescape/node-agent/pkg/malwaremanager/v1"
	"github.com/kubescape/node-agent/pkg/metricsmanager"
	metricprometheus "github.com/kubescape/node-agent/pkg/metricsmanager/prometheus"
	"github.com/kubescape/node-agent/pkg/networkstream"
	networkstreamv1 "github.com/kubescape/node-agent/pkg/networkstream/v1"
	"github.com/kubescape/node-agent/pkg/nodeprofilemanager"
	nodeprofilemanagerv1 "github.com/kubescape/node-agent/pkg/nodeprofilemanager/v1"
	"github.com/kubescape/node-agent/pkg/objectcache"
	"github.com/kubescape/node-agent/pkg/objectcache/applicationprofilecache"
	"github.com/kubescape/node-agent/pkg/objectcache/dnscache"
	"github.com/kubescape/node-agent/pkg/objectcache/k8scache"
	"github.com/kubescape/node-agent/pkg/objectcache/networkneighborhoodcache"
	objectcachev1 "github.com/kubescape/node-agent/pkg/objectcache/v1"
	"github.com/kubescape/node-agent/pkg/processtree"
	containerprocesstree "github.com/kubescape/node-agent/pkg/processtree/container"
	processtreecreator "github.com/kubescape/node-agent/pkg/processtree/creator"
	rulebinding "github.com/kubescape/node-agent/pkg/rulebindingmanager"
	rulebindingcachev1 "github.com/kubescape/node-agent/pkg/rulebindingmanager/cache"
	"github.com/kubescape/node-agent/pkg/rulemanager"
	"github.com/kubescape/node-agent/pkg/rulemanager/cel"
	"github.com/kubescape/node-agent/pkg/rulemanager/ruleadapters"
	"github.com/kubescape/node-agent/pkg/rulemanager/rulecooldown"
	"github.com/kubescape/node-agent/pkg/rulemanager/rulecreator"
	"github.com/kubescape/node-agent/pkg/rulemanager/ruleswatcher"
	"github.com/kubescape/node-agent/pkg/sbommanager"
	sbommanagerv1 "github.com/kubescape/node-agent/pkg/sbommanager/v1"
	"github.com/kubescape/node-agent/pkg/seccompmanager"
	seccompmanagerv1 "github.com/kubescape/node-agent/pkg/seccompmanager/v1"
	"github.com/kubescape/node-agent/pkg/storage/v1"
	"github.com/kubescape/node-agent/pkg/utils"
	"github.com/kubescape/node-agent/pkg/validator"
	"github.com/kubescape/node-agent/pkg/watcher/dynamicwatcher"
	"github.com/kubescape/node-agent/pkg/watcher/seccompprofilewatcher"
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

	clusterData, err := utilsmetadata.LoadConfig("/etc/config/clusterData.json")
	if err != nil {
		logger.L().Ctx(ctx).Fatal("load clusterData error", helpers.Error(err))
	}

	if credentials, err := beUtils.LoadCredentialsFromFile("/etc/credentials"); err != nil {
		logger.L().Warning("failed to load credentials", helpers.Error(err))
	} else {
		clusterData.AccountID = credentials.Account
		logger.L().Info("credentials loaded", helpers.Int("accountLength", len(credentials.Account)))
	}

	// to enable otel, set OTEL_COLLECTOR_SVC=otel-collector:4317
	if otelHost, present := os.LookupEnv("OTEL_COLLECTOR_SVC"); present {
		ctx = logger.InitOtel("node-agent",
			os.Getenv("RELEASE"),
			clusterData.AccountID,
			clusterData.ClusterName,
			url.URL{Host: otelHost})
		defer logger.ShutdownOtel(ctx)
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
	logger.L().Info("Kubernetes mode is true")
	k8sClient := k8sinterface.NewKubernetesApi()
	storageClient, err := storage.CreateStorage(ctx, clusterData.Namespace, cfg.UpdateDataPeriod)
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

	// Create watchers
	dWatcher := dynamicwatcher.NewWatchHandler(k8sClient, storageClient.StorageClient, cfg.SkipNamespace)
	k8sObjectCache, err := k8scache.NewK8sObjectCache(cfg.NodeName, k8sClient)
	if err != nil {
		logger.L().Ctx(ctx).Fatal("error creating K8sObjectCache", helpers.Error(err))
	}
	dWatcher.AddAdaptor(k8sObjectCache)

	// Create the seccomp manager
	var seccompManager seccompmanager.SeccompManagerClient
	if cfg.EnableSeccomp {
		seccompManager, err = seccompmanagerv1.NewSeccompManager()
		if err != nil {
			logger.L().Ctx(ctx).Fatal("error creating SeccompManager", helpers.Error(err))
		}
		seccompWatcher := seccompprofilewatcher.NewSeccompProfileWatcher(storageClient.StorageClient, seccompManager)
		dWatcher.AddAdaptor(seccompWatcher)
	} else {
		seccompManager = seccompmanager.NewSeccompManagerMock()
	}

	var ruleBindingCache *rulebindingcachev1.RBCache
	if cfg.EnableRuntimeDetection {
		ruleCreator := rulecreator.NewRuleCreator()
		ruleBindingCache = rulebindingcachev1.NewCache(cfg, k8sClient, ruleCreator)
		rulesWatcher := ruleswatcher.NewRulesWatcher(k8sClient, ruleCreator, func() {
			ruleBindingCache.RefreshRuleBindingsRules()
		})
		dWatcher.AddAdaptor(rulesWatcher)
	}

	// Create and DNS managers
	var dnsManagerClient dnsmanager.DNSManagerClient
	var dnsResolver dnsmanager.DNSResolver
	if cfg.EnableNetworkTracing || cfg.EnableRuntimeDetection {
		dnsManager := dnsmanager.CreateDNSManager(cfg.DNSCacheSize)
		dnsManagerClient = dnsManager
		// NOTE: dnsResolver is set for threat detection.
		dnsResolver = dnsManager
	} else {
		if cfg.EnableRuntimeDetection {
			logger.L().Ctx(ctx).Fatal("Network tracing is disabled, but runtime detection is enabled. Network tracing is required for runtime detection.")
		}
		dnsManagerClient = dnsmanager.CreateDNSManagerMock()
		dnsResolver = dnsmanager.CreateDNSManagerMock()
	}

	var containerProfileManager containerprofilemanager.ContainerProfileManagerClient
	if cfg.EnableApplicationProfile {
		containerProfileManager, err = containerprofilemanagerv1.NewContainerProfileManager(ctx, cfg, k8sClient, k8sObjectCache, storageClient, dnsResolver, seccompManager, nil, ruleBindingCache)
		if err != nil {
			logger.L().Ctx(ctx).Fatal("error creating the container profile manager", helpers.Error(err))
		}
	} else {
		containerProfileManager = containerprofilemanager.CreateContainerProfileManagerMock()
	}

	var ruleManager rulemanager.RuleManagerClient
	var processTreeManager processtree.ProcessTreeManager
	var objCache objectcache.ObjectCache
	var ruleBindingNotify chan rulebinding.RuleBindingNotify
	var cloudMetadata *apitypes.CloudMetadata

	// Create the container process tree
	containerProcessTree := containerprocesstree.NewContainerProcessTree()

	// Create the process tree creator
	processTreeCreator := processtreecreator.NewProcessTreeCreator(containerProcessTree, cfg)

	// Create the process tree manager
	processTreeManager = processtree.NewProcessTreeManager(
		processTreeCreator,
		containerProcessTree,
		cfg,
	)

	// Start the process tree manager to activate the exit cleanup manager
	processTreeManager.Start()

	if cfg.EnableRuntimeDetection || cfg.EnableMalwareDetection {
		cloudMetadata, err = cloudmetadata.GetCloudMetadata(ctx, k8sClient, cfg.NodeName)
		if err != nil {
			logger.L().Ctx(ctx).Error("error getting cloud metadata", helpers.Error(err))
		}
	}

	if cfg.EnableRuntimeDetection {
		// create exporter
		exporter := exporters.InitExporters(cfg.Exporters, clusterData.ClusterName, cfg.NodeName, cloudMetadata)
		dWatcher.AddAdaptor(ruleBindingCache)

		ruleBindingNotify = make(chan rulebinding.RuleBindingNotify, 100)
		ruleBindingCache.AddNotifier(&ruleBindingNotify)

		apc := applicationprofilecache.NewApplicationProfileCache(cfg, storageClient.StorageClient, k8sObjectCache)
		apc.Start(ctx)

		nnc := networkneighborhoodcache.NewNetworkNeighborhoodCache(cfg, storageClient.StorageClient, k8sObjectCache)
		nnc.Start(ctx)

		dc := dnscache.NewDnsCache(dnsResolver)

		// create object cache
		objCache = objectcachev1.NewObjectCache(k8sObjectCache, apc, nnc, dc)

		ruleCooldown := rulecooldown.NewRuleCooldown(cfg.RuleCoolDown)

		adapterFactory := ruleadapters.NewEventRuleAdapterFactory()

		celEvaluator, err := cel.NewCEL(objCache, cfg)
		if err != nil {
			logger.L().Ctx(ctx).Fatal("error creating CEL evaluator", helpers.Error(err))
		}

		// create runtimeDetection managers
		ruleManager, err = rulemanager.CreateRuleManager(ctx, cfg, k8sClient, ruleBindingCache, objCache, exporter, prometheusExporter, processTreeManager, dnsResolver, nil, ruleCooldown, adapterFactory, celEvaluator)
		if err != nil {
			logger.L().Ctx(ctx).Fatal("error creating RuleManager", helpers.Error(err))
		}

	} else {
		ruleManager = rulemanager.CreateRuleManagerMock()
		apc := &objectcache.ApplicationProfileCacheMock{}
		nnc := &objectcache.NetworkNeighborhoodCacheMock{}
		dc := &objectcache.DnsCacheMock{}
		objCache = objectcachev1.NewObjectCache(k8sObjectCache, apc, nnc, dc)
		ruleBindingNotify = make(chan rulebinding.RuleBindingNotify, 1)
	}

	// Create the node profile manager
	var profileManager nodeprofilemanager.NodeProfileManagerClient
	if cfg.EnableNodeProfile {
		// FIXME validate the HTTPExporterConfig before we use it ?
		profileManager = nodeprofilemanagerv1.NewNodeProfileManager(cfg, *clusterData, cfg.NodeName, k8sObjectCache, ruleManager, cloudMetadata)
	} else {
		profileManager = nodeprofilemanager.NewNodeProfileManagerMock()
	}

	// Create the network streaming manager
	var networkStreamClient networkstream.NetworkStreamClient
	if cfg.EnableNetworkStreaming {
		networkStreamClient, err = networkstreamv1.NewNetworkStream(ctx, cfg, k8sObjectCache, dnsResolver, cfg.NodeName, nil, false, processTreeManager)
		if err != nil {
			logger.L().Ctx(ctx).Fatal("error creating NetworkManager", helpers.Error(err))
		}
	} else {
		networkStreamClient = networkstream.CreateNetworkStreamMock()
	}

	// Create the malware manager
	var malwareManager malwaremanager.MalwareManagerClient
	if cfg.EnableMalwareDetection {
		// create exporter
		exporter := exporters.InitExporters(cfg.Exporters, clusterData.ClusterName, cfg.NodeName, cloudMetadata)
		malwareManager, err = malwaremanagerv1.CreateMalwareManager(cfg, k8sClient, cfg.NodeName, clusterData.ClusterName, exporter, prometheusExporter, k8sObjectCache)
		if err != nil {
			logger.L().Ctx(ctx).Fatal("error creating MalwareManager", helpers.Error(err))
		}
	} else {
		malwareManager = malwaremanager.CreateMalwareManagerMock()
	}

	// Create the IG k8sClient
	if err := igconfig.Config.ReadInConfig(); err != nil {
		logger.L().Warning("reading IG config", helpers.Error(err))
	}
	igK8sClient, err := containercollection.NewK8sClient(cfg.NodeName, "", "")
	if err != nil {
		logger.L().Fatal("error creating IG Kubernetes client", helpers.Error(err))
	}
	defer igK8sClient.Close()
	logger.L().Info("IG Kubernetes client created", helpers.Interface("client", igK8sClient))
	logger.L().Info("detected container runtime", helpers.String("containerRuntime", igK8sClient.RuntimeConfig.Name.String()))

	// Create the SBOM manager
	var sbomManager sbommanager.SbomManagerClient
	if cfg.EnableSbomGeneration {
		sbomManager, err = sbommanagerv1.CreateSbomManager(ctx, cfg, igK8sClient.RuntimeConfig.SocketPath, storageClient, k8sObjectCache)
		if err != nil {
			logger.L().Ctx(ctx).Fatal("error creating SbomManager", helpers.Error(err))
		}
	} else {
		sbomManager = sbommanager.CreateSbomManagerMock()
	}

	thirdPartyTracers := containerwatcher.ThirdPartyTracers{
		ThirdPartyTracersInitializers: mapset.NewSet[containerwatcher.CustomTracerInitializer](),
		ThirdPartyEventReceivers:      maps.NewSafeMap[utils.EventType, mapset.Set[containerwatcher.GenericEventReceiver]](),
	}

	// Create the container handler
	mainHandler, err := containerwatcherv2.CreateIGContainerWatcher(cfg, containerProfileManager, k8sClient,
		igK8sClient, dnsManagerClient, prometheusExporter, ruleManager,
		malwareManager, sbomManager, &ruleBindingNotify, igK8sClient.RuntimeConfig, nil,
		processTreeManager, clusterData.ClusterName, objCache, networkStreamClient, containerProcessTree, thirdPartyTracers)
	if err != nil {
		logger.L().Ctx(ctx).Fatal("error creating the container watcher", helpers.Error(err))
	}
	healthManager.SetContainerWatcher(mainHandler)

	// Start the profileManager
	profileManager.Start(ctx)

	// Start the networkStream
	networkStreamClient.Start()

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
