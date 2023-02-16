package config

type ConfigDataInterface interface {
	IsFalcoEbpfEngine() bool
	GetFalcoSyscallFilter() []string
	GetFalcoKernelObjPath() string
	GetEbpfEngineLoaderPath() string
}
