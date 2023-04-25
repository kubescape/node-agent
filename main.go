package main

import (
	"sniffer/internal/validator"
	"sniffer/pkg/config"
	v1 "sniffer/pkg/config/v1"
	"sniffer/pkg/context"
	"sniffer/pkg/conthandler"
	accumulator "sniffer/pkg/event_data_storage"
	"sniffer/pkg/storageclient"

	"github.com/kubescape/go-logger"
	"github.com/kubescape/go-logger/helpers"
)

func main() {
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
	// after this line we can use logger.L().Ctx() to attach events to spans

	accumulatorChannelError := make(chan error, 10)
	acc := accumulator.GetAccumulator()
	err = acc.StartAccumulator(accumulatorChannelError)
	if err != nil {
		logger.L().Ctx(context.GetBackgroundContext()).Fatal("error during start accumulator", helpers.Error(err))
	}

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

	err = mainHandler.StartMainHandler()
	if err != nil {
		logger.L().Ctx(context.GetBackgroundContext()).Fatal("error during start the main container handler", helpers.Error(err))
	}
}
