package main

import (
	"fmt"
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
		logger.L().Ctx(context.GetBackgroundContext()).Fatal("", helpers.String("error during getting configuration data: ", fmt.Sprintf("%v", err)))
	}
	err = cfg.ParseConfiguration(v1.CreateConfigData(), configData)
	if err != nil {
		logger.L().Ctx(context.GetBackgroundContext()).Fatal("", helpers.String("error during parsing configuration: ", fmt.Sprintf("%v", err)))
	}
	err = validator.CheckPrerequisites()
	if err != nil {
		logger.L().Ctx(context.GetBackgroundContext()).Fatal("", helpers.String("error during validation: ", fmt.Sprintf("%v", err)))
	}

	context.SetBackgroundContext()

	accumulatorChannelError := make(chan error, 10)
	acc := accumulator.GetAccumulator()
	err = acc.StartAccumulator(accumulatorChannelError)
	if err != nil {
		logger.L().Ctx(context.GetBackgroundContext()).Fatal("", helpers.String("error during start accumulator: ", fmt.Sprintf("%v", err)))
	}

	k8sAPIServerClient, err := conthandler.CreateContainerClientK8SAPIServer()
	if err != nil {
		logger.L().Ctx(context.GetBackgroundContext()).Fatal("", helpers.String("error during create the container client: ", fmt.Sprintf("%v", err)))
	}
	storageClient, err := storageclient.CreateSBOMStorageK8SAggregatedAPIClient()
	if err != nil {
		logger.L().Ctx(context.GetBackgroundContext()).Fatal("", helpers.Error(err))
	}
	mainHandler, err := conthandler.CreateContainerHandler(k8sAPIServerClient, storageClient)
	mainHandler.StartMainHandler()
}
