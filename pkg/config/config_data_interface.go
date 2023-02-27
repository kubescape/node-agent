package config

type ConfigDataInterface interface {
	IsFalcoEbpfEngine() bool
	GetFalcoSyscallFilter() []string
	GetFalcoKernelObjPath() string
	GetEbpfEngineLoaderPath() string
	GetUpdateDataPeriod() int
	GetSniffingMaxTimes() int
	IsRelevantCVEServiceEnabled() bool
	GetNodeName() string
	GetClusterName() string
	GetStorageURL() string
}
