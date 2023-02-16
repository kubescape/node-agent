package config

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"os"
)

const (
	FALCO_EBPF_ENGINE  = "falco"
	CILIUM_EBPF_ENGINE = "cilium"
)

var c *Config
var myContainerID string

func init() {
	myContainerID = "1111111"
}

type Config struct {
	data ConfigDataInterface
}

func (cfg *Config) getConfigFilePath() (string, bool) {
	return os.LookupEnv("SNIFFER_CONFIG")
}

func (cfg *Config) GetConfigurationData() (io.Reader, error) {
	c = cfg
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
	return c.data.GetEbpfEngineLoaderPath()
}

func SetMyContainerID(mycid string) {
	myContainerID = mycid
}

func GetMyContainerID() string {
	return myContainerID
}
