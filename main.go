package main

import (
	"fmt"
	"sniffer/internal/config"
	"sniffer/internal/validator"

	"github.com/kubescape/go-logger"
	"github.com/kubescape/go-logger/helpers"
)

func main() {
	cfg := config.Config{}
	configData, err := cfg.GetConfigurationData()
	if err != nil {
		logger.L().Fatal("", helpers.String("error during getting configuration data: ", fmt.Sprintf("%v", err)))
	}
	err = cfg.ParseConfiguration(configData)
	if err != nil {
		logger.L().Fatal("", helpers.String("error during parsing configuration: ", fmt.Sprintf("%v", err)))
	}
	err = validator.CheckPrerequisites()
	if err != nil {
		logger.L().Fatal("", helpers.String("error during validation: ", fmt.Sprintf("%v", err)))
	}

}
