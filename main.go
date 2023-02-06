package cmd

import (
	"fmt"
	"sniffer/internal/config"
	"sniffer/internal/validator"
	"sniffer/internal/version"
	"sniffer/pkg/accumulator"
	"sniffer/pkg/conthandler"

	logger "github.com/kubescape/go-logger"
	helpers "github.com/kubescape/go-logger/helpers"
)

func waitOnCacheAccumulatorErrorCode(cacheAccumulatorErrorChan chan error) {
	err := <-cacheAccumulatorErrorChan
	if err != nil {
		logger.L().Fatal("", helpers.String("ebpf engine failed on error ", fmt.Sprintf("%v", err)))
	}
}

func startingOperations() error {
	return nil
}

func main() {
	configData, err := config.GetConfigurutionData()
	if err != nil {
		logger.L().Fatal("", helpers.String("error during getting configuration data: ", fmt.Sprintf("%v", err)))
	}

	err = config.ParseConfiguration(configData)
	if err != nil {
		logger.L().Fatal("", helpers.String("error during parsing configuration: ", fmt.Sprintf("%v", err)))
	}

	err = validator.CheckPrerequsits()
	if err != nil {
		logger.L().Fatal("", helpers.String("error during check prerequisites: ", fmt.Sprintf("%v", err)))
	}

	err = version.GetVersion()
	if err != nil {
		logger.L().Fatal("", helpers.String("error during check prerequisites: ", fmt.Sprintf("%v", err)))
	}
	logger.L().Info("", helpers.String("sniffer version is: ", fmt.Sprintf("%v", err)))

	err = startingOperations()
	if err != nil {
		logger.L().Fatal("", helpers.String("error during starting operations: ", fmt.Sprintf("%v", err)))
	}

	cacheAccumulatorErrorChan := make(chan error)
	cachAccumulator := accumulator.CreateCacheAccumulator()
	err = cachAccumulator.StartCacheAccumulator()
	if err != nil {
		logger.L().Fatal("", helpers.String("fail to create cache watcher ", fmt.Sprintf("%v", err)))
	}
	go waitOnCacheAccumulatorErrorCode(cacheAccumulatorErrorChan)

	mainHandler := conthandler.CreateMainHandler()
	if err != nil {
		logger.L().Fatal("", helpers.String("fail to create cache watcher ", fmt.Sprintf("%v", err)))
	}

	mainHandler.StartMainHandler()
}
