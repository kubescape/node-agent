package config

import (
	"context"
	"net/url"
	"os"
	"time"

	"github.com/kubescape/go-logger"
)

var falcoSyscallFilter []string

const (
	SnifferServiceRelevantCVEs         = "relevantCVEs"
	nodeNameEnvVar                     = "NODE_NAME"
	myNamespaceEnvVar                  = "MY_NAMESPCAE"
	myContainerNameEnvVar              = "MY_CONTAINER_NAME"
	releaseBuildTagEnvironmentVariable = "RELEASE"
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
	FalcoEbpfEngineData `json:"falcoEbpfEngine"`
	NodeData            `json:"node"`
	ClusterName         string `json:"clusterName"`
	AccountID           string `json:"accountID"`
	SnifferData         `json:"sniffer"`
	DB                  `json:"db"`
	MyNamespace         string `json:"namespace"`
	MyContainerName     string `json:"containerName"`
	BackgroundContext   context.Context
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
		c.MyNamespace = myNamespace
	}
}

func (c *ConfigData) SetMyContainerName() {
	myContainerName, exist := os.LookupEnv(myContainerNameEnvVar)
	if exist {
		c.MyContainerName = myContainerName
	}
}

func (c *ConfigData) GetMyNamespace() string {
	return c.MyNamespace
}

func (c *ConfigData) GetMyContainerName() string {
	return c.MyContainerName
}

func (c *ConfigData) SetBackgroundContext() {
	ctx := context.Background()
	if otelHost, present := os.LookupEnv("OTEL_COLLECTOR_SVC"); present {
		ctx = logger.InitOtel("node agent",
			os.Getenv(releaseBuildTagEnvironmentVariable),
			c.AccountID,
			c.ClusterName,
			url.URL{Host: otelHost})
		defer logger.ShutdownOtel(ctx)
	}
	c.BackgroundContext = ctx
}

func (c *ConfigData) GetBackgroundContext() context.Context {
	return c.BackgroundContext
}
