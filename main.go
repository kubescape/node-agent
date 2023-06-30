package main

import (
	"context"
	"log"
	"net/url"
	"node-agent/internal/validator"
	"node-agent/pkg/config"
	"node-agent/pkg/conthandler"
	"node-agent/pkg/storageclient"
	"os"
	"os/signal"
	"syscall"

	"github.com/kubescape/go-logger"
	"github.com/kubescape/go-logger/helpers"
)

func main() {
	ctx := context.Background()

	cfg, err := config.LoadConfig("/etc/config")
	if err != nil {
		logger.L().Ctx(ctx).Fatal("load config error", helpers.Error(err))
	}

	clusterData, err := config.LoadClusterData("/etc/config")
	if err != nil {
		logger.L().Ctx(ctx).Fatal("load clusterData error", helpers.Error(err))
	}

	// to enable otel, set OTEL_COLLECTOR_SVC=otel-collector:4317
	if otelHost, present := os.LookupEnv("OTEL_COLLECTOR_SVC"); present {
		ctx = logger.InitOtel("kubevuln",
			os.Getenv("RELEASE"),
			clusterData.AccountID,
			clusterData.ClusterName,
			url.URL{Host: otelHost})
		defer logger.ShutdownOtel(ctx)
	}

	err = validator.CheckPrerequisites()
	if err != nil {
		logger.L().Ctx(ctx).Fatal("error during validation", helpers.Error(err))
	}

	// Create the container handler
	k8sAPIServerClient, err := conthandler.CreateContainerClientK8SAPIServer()
	if err != nil {
		logger.L().Ctx(ctx).Fatal("error during create the container client", helpers.Error(err))
	}
	storageClient, err := storageclient.CreateSBOMStorageK8SAggregatedAPIClient(ctx)
	if err != nil {
		logger.L().Ctx(ctx).Fatal("error during create the storage client", helpers.Error(err))
	}
	mainHandler, err := conthandler.CreateContainerHandler(cfg, clusterData.ClusterName, k8sAPIServerClient, storageClient)
	if err != nil {
		logger.L().Ctx(ctx).Fatal("error during create the main container handler", helpers.Error(err))
	}

	// Start the container handler
	err = mainHandler.StartMainHandler(ctx)
	if err != nil {
		logger.L().Ctx(ctx).Fatal("error during start the main container handler", helpers.Error(err))
	}
	defer mainHandler.StopMainHandler()

	// Wait for shutdown signal
	shutdown := make(chan os.Signal, 1)
	signal.Notify(shutdown, os.Interrupt, syscall.SIGTERM)
	<-shutdown
	log.Println("Shutting down...")

	// Exit with success
	os.Exit(0)
}
