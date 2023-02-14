package config

var falcoSyscallFilter []string

const (
	FALCO_EBPF_ENGINE_TYPE     = "falco"
	KUBESCAPE_EBPF_ENGINE_TYPE = "kubescape"
)

const (
	SNIFFER_SERVICE_RELEVANT_CVES = "relevantCVEs"
)

// all the struct and arguments names must be visible outside from the package since the json parser package need to parse them

type FalcoEbpfEngineData struct {
	KernelObjPath        string `json:"kernelObjPath"`
	EbpfEngineLoaderPath string `json:"ebpfEngineLoaderPath"`
}

type EbpfEngine struct {
	EbpfEngineType string      `json:"type"`
	Data           interface{} `json:"data"`
}

type NodeData struct {
	Name string `json:"name"`
}

type Features struct {
	Name string `json:"name"`
}

type ContainerSniffing struct {
	SniffingMaxTime string `json:"sniffingMaxTime"`
}

type DataStorage struct {
	URL string `json:"URL"`
}

type OutputDataStorageData struct {
	DataStorage `json:"dataStorage"`
}

type OutputDataStorage struct {
	OutputDataStorageType string      `json:"type"`
	Data                  interface{} `json:"data"`
	UpdateDataPeriod      string      `json:"updateDataPeriod"`
}

type SnifferData struct {
	EbpfEngine        `json:"ebpfEngine"`
	NodeData          `json:"node"`
	FeatureList       []Features `json:"features"`
	ContainerSniffing `json:"containerSniffing"`
	OutputDataStorage `json:"outputDataStorage"`
}

type Services struct {
	ServiceType string      `json:"type"`
	Data        interface{} `json:"data"`
}

type ConfigData struct {
	ServicesList []Services `json:"services"`
}

func (c *ConfigData) IsFalcoEbpfEngine() bool {
	for i := range c.ServicesList {
		switch v := c.ServicesList[i].Data.(type) {
		case map[string]interface{}:
			return v["ebpfEngine"].(map[string]interface{})["type"] == FALCO_EBPF_ENGINE_TYPE
		default:
			return false
		}
	}
	return false
}

func (c *ConfigData) setFalcoSyscallFilter() {
	if c.IsFalcoEbpfEngine() {
		for i := range c.ServicesList {
			features := c.ServicesList[i].Data.(map[string]interface{})["features"]
			feature := features.([]interface{})
			if feature[0].(map[string]interface{})["Name"] == SNIFFER_SERVICE_RELEVANT_CVES {
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
	for i := range c.ServicesList {
		if c.ServicesList[i].ServiceType == "sniffer" {
			return c.ServicesList[i].Data.(map[string]interface{})["ebpfEngine"].(map[string]interface{})["data"].(map[string]interface{})["kernelObjPath"].(string)
		}
	}
	return ""
}

func (c *ConfigData) GetEbpfEngineLoaderPath() string {
	for i := range c.ServicesList {
		if c.ServicesList[i].ServiceType == "sniffer" {
			return c.ServicesList[i].Data.(map[string]interface{})["ebpfEngine"].(map[string]interface{})["data"].(map[string]interface{})["ebpfEngineLoaderPath"].(string)
		}
	}
	return ""
}
