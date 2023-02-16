package config

import (
	"os"
	v1 "sniffer/pkg/config/v1"
	"testing"
)

func TestConfig(t *testing.T) {
	err := os.Setenv(SNIFFER_CONFIG, "../../configuration/ConfigurationFile.json")
	if err != nil {
		t.Fatalf("failed to set env SNIFFER_CONFIG with err %v", err)
	}

	cfg := GetConfigurationConfigContext()
	configData, err := cfg.GetConfigurationReader()
	if err != nil {
		t.Fatalf("GetConfigurationReader failed with err %v", err)
	}
	err = cfg.ParseConfiguration(v1.CreateConfigData(), configData)
	if err != nil {
		t.Fatalf("ParseConfiguration failed with err %v", err)
	}

	if cfg.data.IsFalcoEbpfEngine() == false {
		t.Fatalf("IsFalcoEbpfEngine need to be falco")
	}

	syscallFilters := cfg.GetSyscallFilter()
	if !(syscallFilters[0] == "open" && syscallFilters[1] == "openat" && syscallFilters[2] == "execve" && syscallFilters[3] == "execveat") {
		t.Fatalf("GetFalcoSyscallFilter need to be matched to relevantCVEs feature")
	}

	falcoKernelObj := cfg.GetFalcoKernelObjPath()
	if falcoKernelObj != "./resources/ebpf/falco/kernel_obj.o" {
		t.Fatalf("GetFalcoKernelObjPath failed")
	}

	falcoEbpfEngineLoaderPath := cfg.GetEbpfEngineLoaderPath()
	if falcoEbpfEngineLoaderPath != "./resources/ebpf/falco/userspace_app" {
		t.Fatalf("GetEbpfEngineLoaderPath failed")
	}
}
