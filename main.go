package main

import (
	"fmt"
	"sniffer/internal/validator"
	"sniffer/pkg/config"
	v1 "sniffer/pkg/config/v1"

	"github.com/kubescape/go-logger"
	"github.com/kubescape/go-logger/helpers"
)

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

}
