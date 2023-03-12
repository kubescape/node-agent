package config

import "time"

var falcoSyscallFilter []string

const (
	SnifferServiceRelevantCVEs = "relevantCVEs"
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

type Server struct {
	URL string `json:"URL"`
}

type DB struct {
	Server           `json:"server"`
	FileSystem       bool `json:"fileSystem"`
	UpdateDataPeriod int  `json:"updateDataPeriod"`
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

func (c *ConfigData) GetStorageURL() string {
	return c.DB.Server.URL
}

func (c *ConfigData) GetNodeName() string {
	return c.NodeData.Name
}

func (c *ConfigData) GetClusterName() string {
	return c.ClusterName
}
