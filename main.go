package main

import (
	"context"
	"net/http"
	"net/url"
	"node-agent/internal/validator"
	"node-agent/pkg/applicationprofilemanager"
	applicationprofilemanagerv1 "node-agent/pkg/applicationprofilemanager/v1"
	"node-agent/pkg/config"
	"node-agent/pkg/containerwatcher/v1"
	"node-agent/pkg/dnsmanager"
	"node-agent/pkg/filehandler/v1"
	"node-agent/pkg/networkmanager"
	"node-agent/pkg/relevancymanager"
	relevancymanagerv1 "node-agent/pkg/relevancymanager/v1"
	"node-agent/pkg/sbomhandler/v1"
	"node-agent/pkg/storage/v1"
	"os"
	"os/signal"
	"syscall"

	utilsmetadata "github.com/armosec/utils-k8s-go/armometadata"

	"github.com/kubescape/backend/pkg/utils"
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
		if credentials, err := utils.LoadCredentialsFromFile("/etc/credentials"); err != nil {
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
		logger.L().Ctx(ctx).Fatal("error during validation", helpers.Error(err))
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
		sbomHandler := sbomhandler.CreateSBOMHandler(storageClient)
		relevancyManager, err = relevancymanagerv1.CreateRelevancyManager(ctx, cfg, clusterData.ClusterName, fileHandler, k8sClient, sbomHandler)
		if err != nil {
			logger.L().Ctx(ctx).Fatal("error creating the relevancy manager", helpers.Error(err))
		}
	} else {
		relevancyManager = relevancymanager.CreateRelevancyManagerMock()
	}

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
	mainHandler, err := containerwatcher.CreateIGContainerWatcher(cfg, applicationProfileManager, k8sClient, relevancyManager, networkManagerClient, dnsManagerClient)
	if err != nil {
		logger.L().Ctx(ctx).Fatal("error creating the container watcher", helpers.Error(err))
	}

	// Start the container handler
	err = mainHandler.Start(ctx)
	if err != nil {
		logger.L().Ctx(ctx).Fatal("error starting the container watcher", helpers.Error(err))
	}
	defer mainHandler.Stop()

	// Wait for shutdown signal
	shutdown := make(chan os.Signal, 1)
	signal.Notify(shutdown, os.Interrupt, syscall.SIGTERM)
	<-shutdown

	// Exit with success
	os.Exit(0)
}
