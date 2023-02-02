package main

import (
	"fmt"
	"os"

	"sniffer/core/accumulator"
	"sniffer/core/config"
	"sniffer/core/validator"

	logger "github.com/kubescape/go-logger"
	"github.com/kubescape/go-logger/helpers"
)

func waitOnCacheAccumulatorProccessErrorCode(cacheAccumulatorErrorChan chan error) {
	err := <-cacheAccumulatorErrorChan
	if err != nil {
		logger.L().Error("", helpers.String("Global Sniffer failed on error ", fmt.Sprintf("%v", err)))
		os.Exit(1)
	}
}

func startingOperations() error {
	// if config.IsRelaventCVEServiceEnabled() {
	// 	err := vuln.DownloadVulnDB()
	// 	if err != nil {
	// 		return err
	// 	}
	// }
	// err := DB.CreateCRDs()
	// if err != nil {
	// 	return err
	// }
	return nil
}

func main() {

	err := config.ParseConfiguration()
	if err != nil {
		logger.L().Fatal("", helpers.String("error during parsing configuration: ", fmt.Sprintf("%v", err)))
	}

	err = validator.CheckPrerequsits()
	if err != nil {
		logger.L().Fatal("", helpers.String("error during check prerequisites: ", fmt.Sprintf("%v", err)))
	}

	err = startingOperations()
	if err != nil {
		logger.L().Fatal("", helpers.String("error during starting operations: ", fmt.Sprintf("%v", err)))
	}

	cacheAccumulatorErrorChan := make(chan error)
	cachAccumulator := accumulator.CreateCacheAccumulator(10)
	err = cachAccumulator.StartCacheAccumalator(cacheAccumulatorErrorChan, config.GetSyscallFilter(), false, false)
	if err != nil {
		logger.L().Fatal("", helpers.String("fail to create cache watcher ", fmt.Sprintf("%v", err)))
	}
	go waitOnCacheAccumulatorProccessErrorCode(cacheAccumulatorErrorChan)

	fmt.Scanln()
	// containerWatcher, err := k8s_watcher.CreateContainerWatcher()
	// if err != nil {
	// 	log.Fatalf("fail to create container watcher %v", err)
	// }
	// err = containerWatcher.StartWatchingOnNewContainers()
	// if err != nil {
	// 	log.Fatalf("StartWatchingOnNewContainers fail on error %v", err)
	// }
}
