package config

import (
	"time"
)

type ConfigDataInterface interface {
	IsFalcoEbpfEngine() bool
	GetFalcoSyscallFilter() []string
	GetFalcoKernelObjPath() string
	GetEbpfEngineLoaderPath() string
	GetUpdateDataPeriod() time.Duration
	GetSniffingMaxTimes() time.Duration
	IsRelevantCVEServiceEnabled() bool
	GetNodeName() string
	GetClusterName() string
	SetNodeName()
	SetNamespace()
	GetNamespace() string
	SetContainerName()
	GetContainerName() string
	SetBackgroundContextURL()
	GetBackgroundContextURL() string
	GetAccountID() string
}
