package main

import (
	"fmt"
	"sniffer/internal/validator"
	"sniffer/pkg/config"
	v1 "sniffer/pkg/config/v1"
	"sniffer/pkg/conthandler"
	accumulator "sniffer/pkg/event_data_storage"
	"sniffer/pkg/storageclient"

	"github.com/kubescape/go-logger"
	"github.com/kubescape/go-logger/helpers"
)

func waitOnCacheAccumulatorProccessErrorCode(cacheAccumulatorErrorChan chan error) {
	err := <-cacheAccumulatorErrorChan
	if err != nil {
		logger.L().Fatal("EBPF engine failed on error", helpers.Error(err))
	}
}

func main() {
	cfg := config.GetConfigurationConfigContext()
	configData, err := cfg.GetConfigurationReader()
	if err != nil {
		logger.L().Fatal("", helpers.String("error during getting configuration data: ", fmt.Sprintf("%v", err)))
	}
	err = cfg.ParseConfiguration(v1.CreateConfigData(), configData)
	if err != nil {
		logger.L().Fatal("", helpers.String("error during parsing configuration: ", fmt.Sprintf("%v", err)))
	}
	err = validator.CheckPrerequisites()
	if err != nil {
		logger.L().Fatal("", helpers.String("error during validation: ", fmt.Sprintf("%v", err)))
	}

	accumulatorChanError := make(chan error, 10)
	acc := accumulator.GetAccumulator()
	err = acc.StartAccumulator(accumulatorChanError)
	if err != nil {
		logger.L().Fatal("", helpers.String("error during starting accumulator: ", fmt.Sprintf("%v", err)))
	}

	contClient, err := conthandler.CreateContainerClientK8SAPIServer()
	if err != nil {
		logger.L().Fatal("", helpers.String("error create client to k8s api server: ", fmt.Sprintf("%v", err)))
	}
	storageClient := storageclient.CreateSBOMStorageHttpClient()
	contMainHandler, err := conthandler.CreateContainerHandler(contClient, storageClient)
	if err != nil {
		logger.L().Fatal("", helpers.String("error create container main handler: ", fmt.Sprintf("%v", err)))
	}
	err = contMainHandler.StartMainHandler()
	if err != nil {
		logger.L().Fatal("", helpers.String("error starting container main handler: ", fmt.Sprintf("%v", err)))
	}
}
