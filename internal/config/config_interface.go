package config

type configClient interface {
	// global configuration
	GetConfigurutionData() ([]byte, error)
	ParseConfiguration() error

	//ebpf engine based on falco configuration
	GetFalcoEngineBinaryPath() string
	GetFalcoEngineKernelObjPath() string
	GetFalcoSyscallFilter() []string
	IsFalcoEbpfEngineMonitorHostMachine() []string
	IsFalcoEbpfEngine() bool

	// services configuration
	IsRelaventCVEServiceEnabled() bool
}
