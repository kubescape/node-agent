package main

import (
	"context"
	"net/http"
	"net/url"
	"node-agent/pkg/config"
	"node-agent/pkg/containerwatcher/v1"
	"node-agent/pkg/filehandler/v1"
	"node-agent/pkg/relevancymanager/v1"
	"node-agent/pkg/storageclient"
	"os"
	"os/signal"
	"syscall"

	"github.com/kubescape/go-logger"
	"github.com/kubescape/go-logger/helpers"
	"github.com/kubescape/k8s-interface/k8sinterface"
	"github.com/spf13/afero"

	_ "net/http/pprof"
)

func main() {
	ctx := context.Background()

	cfg, err := config.LoadConfig("/etc/config")
	if err != nil {
		logger.L().Fatal("load config error", helpers.Error(err))
	}

	// port := rand.Intn(9090-6060+1) + 6060
	// logger.L().Info("Port for profiler", helpers.Int("port", port))
	go http.ListenAndServe("localhost:6060", nil)

	clusterData, err := config.LoadClusterData("/etc/config")
	if err != nil {
		logger.L().Fatal("load clusterData error", helpers.Error(err))
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

	// err = validator.CheckPrerequisites()
	// if err != nil {
	// 	logger.L().Ctx(ctx).Fatal("error during validation", helpers.Error(err))
	// }

	// Create the relevancy manager
	fileHandler, err := filehandler.CreateSimpleFileHandler()
	if err != nil {
		logger.L().Fatal("failed to create fileDB", helpers.Error(err))
	}
	defer fileHandler.Close()
	k8sClient := k8sinterface.NewKubernetesApi()
	storageClient, err := storageclient.CreateSBOMStorageK8SAggregatedAPIClient(ctx)
	if err != nil {
		logger.L().Fatal("error creating the storage client", helpers.Error(err))
	}
	relevancyManager, err := relevancymanager.CreateRelevancyManager(cfg, clusterData.ClusterName, fileHandler, k8sClient, afero.NewOsFs(), storageClient)
	if err != nil {
		logger.L().Fatal("error creating the relevancy manager", helpers.Error(err))
	}

	// Create the container handler
	mainHandler, err := containerwatcher.CreateIGContainerWatcher(k8sClient, relevancyManager)
	if err != nil {
		logger.L().Fatal("error creating the container watcher", helpers.Error(err))
	}

	// Start the container handler
	err = mainHandler.Start(ctx)
	if err != nil {
		logger.L().Fatal("error starting the container watcher", helpers.Error(err))
	}
	defer mainHandler.Stop()

	// Wait for shutdown signal
	shutdown := make(chan os.Signal, 1)
	signal.Notify(shutdown, os.Interrupt, syscall.SIGTERM)
	<-shutdown

	// Exit with success
	os.Exit(0)
}
