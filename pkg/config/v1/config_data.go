package config

import (
	"os"
	"time"
)

var falcoSyscallFilter []string

const (
	SnifferServiceRelevantCVEs = "relevantCVEs"
	nodeNameEnvVar             = "NODE_NAME"
	myNamespaceEnvVar          = "MY_NAMESPCAE"
	myContainerNameEnvVar      = "MY_CONTAINER_NAME"
)

// all the struct and arguments names must be visible outside from the package since the json parser package need to parse them

type FalcoEbpfEngineData struct {
	KernelObjPath        string `json:"kernelObjPath"`
	EbpfEngineLoaderPath string `json:"ebpfEngineLoaderPath"`
}

type NodeData struct {
	Name string `json:"name"`
}

type SnifferServices struct {
	Name string `json:"name"`
}

type DB struct {
	UpdateDataPeriod int `json:"updateDataPeriod"`
}

type SnifferData struct {
	FeatureList     []SnifferServices `json:"services"`
	SniffingMaxTime int               `json:"maxSniffingTimePerContainer"`
}

type ConfigData struct {
	SnifferData         `json:"sniffer"`
	FalcoEbpfEngineData `json:"falcoEbpfEngine"`
	NodeData            `json:"node"`
	DB                  `json:"db"`
	ClusterName         string `json:"clusterName"`
	myNamespace         string `json:"namespace"`
	myContainerName     string `json:"clusterName"`
}

func CreateConfigData() *ConfigData {
	return &ConfigData{}
}

func (c *ConfigData) IsFalcoEbpfEngine() bool {
	return c.FalcoEbpfEngineData.EbpfEngineLoaderPath != "" && c.FalcoEbpfEngineData.KernelObjPath != ""
}

func (c *ConfigData) setFalcoSyscallFilter() {
	if c.IsFalcoEbpfEngine() {
		for i := range c.FeatureList {
			if c.FeatureList[i].Name == SnifferServiceRelevantCVEs {
				falcoSyscallFilter = append(falcoSyscallFilter, []string{"open", "openat", "execve", "execveat"}...)
			}
		}
	}
}

func (c *ConfigData) GetFalcoSyscallFilter() []string {
	if len(falcoSyscallFilter) == 0 {
		c.setFalcoSyscallFilter()
	}
	return falcoSyscallFilter
}

func (c *ConfigData) GetFalcoKernelObjPath() string {
	return c.FalcoEbpfEngineData.KernelObjPath
}

func (c *ConfigData) GetEbpfEngineLoaderPath() string {
	return c.FalcoEbpfEngineData.EbpfEngineLoaderPath
}

func (c *ConfigData) GetUpdateDataPeriod() time.Duration {
	return time.Duration(c.DB.UpdateDataPeriod) * time.Second
}

func (c *ConfigData) GetSniffingMaxTimes() time.Duration {
	return time.Duration(c.SnifferData.SniffingMaxTime) * time.Minute
}

func (c *ConfigData) IsRelevantCVEServiceEnabled() bool {
	for i := range c.FeatureList {
		if c.FeatureList[i].Name == SnifferServiceRelevantCVEs {
			return true
		}
	}
	return false
}

func (c *ConfigData) GetNodeName() string {
	return c.NodeData.Name
}

func (c *ConfigData) GetClusterName() string {
	return c.ClusterName
}

func (c *ConfigData) SetNodeName() {
	nodeName, exist := os.LookupEnv(nodeNameEnvVar)
	if exist {
		c.NodeData.Name = nodeName
	}
}

func (c *ConfigData) SetMyNamespace() {
	myNamespace, exist := os.LookupEnv(myNamespaceEnvVar)
	if exist {
		c.myNamespace = myNamespace
	}
}

func (c *ConfigData) SetMyContainerName() {
	myContainerName, exist := os.LookupEnv(myContainerNameEnvVar)
	if exist {
		c.myContainerName = myContainerName
	}
}

func (c *ConfigData) GetMyNamespace() string {
	return c.myNamespace
}

func (c *ConfigData) GetMyContainerName() string {
	return c.myContainerName
}
