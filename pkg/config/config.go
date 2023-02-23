package config

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"os"
)

const (
	EBPFEngineFalco        = "falco"
	EBPFEngineCilium       = "cilium"
	SNIFFER_CONFIG_ENV_VAR = "SNIFFER_CONFIG_ENV_VAR"
)

type Config struct {
	data ConfigDataInterface
}

func (cfg *Config) getConfigFilePath() (string, bool) {
	return os.LookupEnv(SNIFFER_CONFIG_ENV_VAR)
}

func (cfg *Config) GetConfigurationReader() (io.Reader, error) {
	cfgPath, exist := cfg.getConfigFilePath()
	if !exist {
		return nil, fmt.Errorf("failed to find configuration file path")
	}
	data, err := os.ReadFile(cfgPath)
	if err != nil {
		return nil, fmt.Errorf("failed to read configuration file with error %v", err.Error())
	}

	return bytes.NewReader(data), nil
}

func (cfg *Config) ParseConfiguration(configData ConfigDataInterface, data io.Reader) error {

	buf := new(bytes.Buffer)
	_, err := buf.ReadFrom(data)
	if err != nil {
		return err
	}
	b := buf.Bytes()
	err = json.Unmarshal(b, &configData)
	if err != nil {
		return err
	}
	cfg.data = configData

	return nil
}

func (cfg *Config) IsFalcoEbpfEngine() bool {
	return cfg.data.IsFalcoEbpfEngine()
}

func (cfg *Config) GetSyscallFilter() []string {
	return cfg.data.GetFalcoSyscallFilter()
}

func (cfg *Config) GetFalcoKernelObjPath() string {
	return cfg.data.GetFalcoKernelObjPath()
}

func (cfg *Config) GetEbpfEngineLoaderPath() string {
	return cfg.data.GetEbpfEngineLoaderPath()
}
