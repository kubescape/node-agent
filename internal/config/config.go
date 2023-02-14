package config

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"os"
	v1 "sniffer/internal/config/v1"
)

const (
	FALCO_EBPF_ENGINE  = "falco"
	CILIUM_EBPF_ENGINE = "cilium"
)

var c *Config

type Config struct {
	data v1.ConfigData
}

func (cfg *Config) getConfigFilePath() (string, bool) {
	return os.LookupEnv("SNIFFER_CONFIG")
}

func (cfg *Config) GetConfigurationData() (io.Reader, error) {
	config := Config{}
	c = &config
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

func (cfg *Config) ParseConfiguration(data io.Reader) error {
	configData := v1.ConfigData{}

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

func IsFalcoEbpfEngine() bool {
	return c.data.IsFalcoEbpfEngine()
}

func GetSyscallFilter() []string {
	return c.data.GetFalcoSyscallFilter()
}

func GetFalcoKernelObjPath() string {
	return c.data.GetFalcoKernelObjPath()
}

func GetEbpfEngineLoaderPath() string {
	return c.data.GetFalcoKernelObjPath()
}
