package config

import (
	"node-agent/pkg/utils"
	"path"
	"time"
)

type ConfigDataTimesMock struct {
}

func CreateTimesMockConfigData() *ConfigDataTimesMock {
	return &ConfigDataTimesMock{}
}

func (c *ConfigDataTimesMock) IsFalcoEbpfEngine() bool {
	return true
}

func (c *ConfigDataTimesMock) GetFalcoSyscallFilter() []string {
	return []string{"open", "openat", "execve", "execveat"}
}

func (c *ConfigDataTimesMock) GetFalcoKernelObjPath() string {
	return path.Join(utils.CurrentDir(), "..", "testdata", "mock_falco_ebpf_engine", "kernel_obj_mock.o")
}

func (c *ConfigDataTimesMock) GetEbpfEngineLoaderPath() string {
	return path.Join(utils.CurrentDir(), "..", "testdata", "mock_falco_ebpf_engine", "userspace_app_mock")
}

func (c *ConfigDataTimesMock) GetUpdateDataPeriod() time.Duration {
	return time.Duration(5) * time.Second
}

func (c *ConfigDataTimesMock) GetSniffingMaxTimes() time.Duration {
	return time.Duration(10) * time.Second
}

func (c *ConfigDataTimesMock) IsRelevantCVEServiceEnabled() bool {
	return true
}

func (c *ConfigDataTimesMock) GetNodeName() string {
	return "minikube"
}

func (c *ConfigDataTimesMock) GetClusterName() string {
	return "test"
}

func (c *ConfigDataTimesMock) SetNodeName() {
}

func (c *ConfigDataTimesMock) SetNamespace() {
}

func (c *ConfigDataTimesMock) SetContainerName() {
}

func (c *ConfigDataTimesMock) GetNamespace() string {
	return "Namespace"
}

func (c *ConfigDataTimesMock) GetContainerName() string {
	return "ContName"
}

func (c *ConfigDataTimesMock) SetBackgroundContextURL() {
}

func (c *ConfigDataTimesMock) GetBackgroundContextURL() string {
	return "URLcontext"
}

func (c *ConfigDataTimesMock) GetAccountID() string {
	return "AccountID"
}
