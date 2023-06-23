package main

import (
	"log"
	"node-agent/internal/validator"
	"node-agent/pkg/config"
	v1 "node-agent/pkg/config/v1"
	"node-agent/pkg/context"
	"node-agent/pkg/conthandler"
	"node-agent/pkg/storageclient"
	"os"
	"os/signal"
	"syscall"

	"github.com/kubescape/go-logger"
	"github.com/kubescape/go-logger/helpers"
)

func main() {
	// Init
	cfg := config.GetConfigurationConfigContext()
	configData, err := cfg.GetConfigurationReader()
	if err != nil {
		logger.L().Fatal("error during getting configuration data", helpers.Error(err))
	}
	err = cfg.ParseConfiguration(v1.CreateConfigData(), configData)
	if err != nil {
		logger.L().Fatal("error during parsing configuration", helpers.Error(err))
	}
	err = validator.CheckPrerequisites()
	if err != nil {
		logger.L().Fatal("error during validation", helpers.Error(err))
	}
	context.SetBackgroundContext()

	// Create the container handler
	k8sAPIServerClient, err := conthandler.CreateContainerClientK8SAPIServer()
	if err != nil {
		logger.L().Ctx(context.GetBackgroundContext()).Fatal("error during create the container client", helpers.Error(err))
	}
	storageClient, err := storageclient.CreateSBOMStorageK8SAggregatedAPIClient()
	if err != nil {
		logger.L().Ctx(context.GetBackgroundContext()).Fatal("error during create the storage client", helpers.Error(err))
	}
	mainHandler, err := conthandler.CreateContainerHandler(k8sAPIServerClient, storageClient)
	if err != nil {
		logger.L().Ctx(context.GetBackgroundContext()).Fatal("error during create the main container handler", helpers.Error(err))
	}

	// Start the container handler
	err = mainHandler.StartMainHandler()
	if err != nil {
		logger.L().Ctx(context.GetBackgroundContext()).Fatal("error during start the main container handler", helpers.Error(err))
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
