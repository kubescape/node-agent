package config

import (
	"path"
	"sniffer/pkg/utils"
	"time"
)

type ConfigDataFalcoMock struct {
}

func CreateFalcoMockConfigData() *ConfigDataFalcoMock {
	return &ConfigDataFalcoMock{}
}

func (c *ConfigDataFalcoMock) IsFalcoEbpfEngine() bool {
	return true
}

func (c *ConfigDataFalcoMock) GetFalcoSyscallFilter() []string {
	return []string{"open", "openat", "execve", "execveat"}
}

func (c *ConfigDataFalcoMock) GetFalcoKernelObjPath() string {
	return path.Join(utils.CurrentDir(), "..", "testdata", "mock_falco_ebpf_engine", "kernel_obj_mock.o")
}

func (c *ConfigDataFalcoMock) GetEbpfEngineLoaderPath() string {
	return path.Join(utils.CurrentDir(), "..", "testdata", "mock_falco_ebpf_engine", "userspace_app_mock")
}

func (c *ConfigDataFalcoMock) GetUpdateDataPeriod() time.Duration {
	return time.Duration(120) * time.Second
}

func (c *ConfigDataFalcoMock) GetSniffingMaxTimes() time.Duration {
	return time.Duration(60*60) * time.Second
}

func (c *ConfigDataFalcoMock) IsRelevantCVEServiceEnabled() bool {
	return true
}

func (c *ConfigDataFalcoMock) GetNodeName() string {
	return "minikube"
}

func (c *ConfigDataFalcoMock) GetClusterName() string {
	return "test"
}

func (c *ConfigDataFalcoMock) GetStorageURL() string {
	return "blabla"
}
