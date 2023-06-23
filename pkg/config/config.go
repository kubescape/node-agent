package config

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	v1 "node-agent/pkg/config/v1"
	"os"
	"time"
)

const (
	ConfigEnvVar   = "CONFIG_ENV_VAR"
	NodeNameEnvVar = "NODE_NAME"
)

const (
	// error message if configuration file is not exist
	ErrConfigurationFileNotExist = "configuration file does not exist"

	// error message if configuration file is not valid
	ErrConfigurationFileNotValid = "configuration file is not valid"

	// error message if failed to parse configuration file
	ErrFailedToUnmarshalConfigurationData = "failed to unmarshal the configuration json data"
)

var _ ConfigDataInterface = &v1.ConfigData{}

type Config struct {
	data ConfigDataInterface
}

var _ ConfigClient = (*Config)(nil)

func (cfg *Config) getConfigFilePath() (string, bool) {
	return os.LookupEnv(ConfigEnvVar)
}

func (cfg *Config) GetConfigurationReader() (io.Reader, error) {
	cfgPath, exist := cfg.getConfigFilePath()
	if !exist {
		return nil, fmt.Errorf(ErrConfigurationFileNotExist)
	}
	data, err := os.ReadFile(cfgPath)
	if err != nil {
		return nil, fmt.Errorf("%s, error: %w", ErrConfigurationFileNotValid, err)
	}

	return bytes.NewReader(data), nil
}

func (cfg *Config) ParseConfiguration(configData ConfigDataInterface, data io.Reader) error {

	buf := new(bytes.Buffer)

	if _, err := buf.ReadFrom(data); err != nil {
		return fmt.Errorf("%s, error: %w", ErrFailedToUnmarshalConfigurationData, err)
	}

	b := buf.Bytes()
	if err := json.Unmarshal(b, &configData); err != nil {
		return fmt.Errorf("%s, error: %w", ErrFailedToUnmarshalConfigurationData, err)
	}
	cfg.data = configData
	cfg.data.SetNodeName()
	cfg.data.SetNamespace()
	cfg.data.SetContainerName()
	cfg.data.SetBackgroundContextURL()

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

func (cfg *Config) GetUpdateDataPeriod() time.Duration {
	return cfg.data.GetUpdateDataPeriod()
}

func (cfg *Config) GetSniffingMaxTimes() time.Duration {
	return cfg.data.GetSniffingMaxTimes()
}

func (cfg *Config) IsRelevantCVEServiceEnabled() bool {
	return cfg.data.IsRelevantCVEServiceEnabled()
}

func (cfg *Config) GetNodeName() string {
	return cfg.data.GetNodeName()
}

func (cfg *Config) GetClusterName() string {
	return cfg.data.GetClusterName()
}

func (cfg *Config) GetNamespace() string {
	return cfg.data.GetNamespace()
}

func (cfg *Config) GetContainerName() string {
	return cfg.data.GetContainerName()
}

func (cfg *Config) GetBackgroundContextURL() string {
	return cfg.data.GetBackgroundContextURL()
}

func (cfg *Config) GetAccountID() string {
	return cfg.data.GetAccountID()
}
