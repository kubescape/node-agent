package config

import (
	"bytes"
	"encoding/json"
	"os"
	"path"
	v1 "sniffer/pkg/config/v1"
	"sniffer/pkg/utils"
	"strings"
	"testing"
	"time"
)

func TestConfig(t *testing.T) {
	{
		cfg := GetConfigurationConfigContext()
		_, err := cfg.GetConfigurationReader()
		if err == nil || !strings.Contains(err.Error(), ErrConfigurationFileNotExist) {
			t.Errorf("missing error message/incomplete error message, expected error message: '%s', got: '%v'", ErrConfigurationFileNotExist, err)
		}
	}
	{
		configPath := path.Join(utils.CurrentDir(), "..", "..", "configuration", "ConfigurationFile.json")
		err := os.Setenv(ConfigEnvVar, configPath)
		if err != nil {
			t.Fatalf("failed to set env %s with err %v", ConfigEnvVar, err)
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
			t.Errorf("missing error message/incomplete error message, expected error message: '%s', got: '%v'", ErrConfigurationFileNotExist, err)
		}
	}
	{
		os.Setenv(ConfigEnvVar, "kuku")
		cfg := GetConfigurationConfigContext()
		_, err := cfg.GetConfigurationReader()
		if err == nil || !strings.Contains(err.Error(), ErrConfigurationFileNotValid) {
			t.Fatalf("missing error message/incomplete error message")
		}
	}
}

type TestConfigData struct {
	FalcoKernelObjPath       string
	EbpfEngineLoaderPath     string
	NodeName                 string
	ClusterName              string
	FalcoSyscallFilter       []string
	UpdateDataPeriod         time.Duration
	SniffingMaxTimes         time.Duration
	FalcoEbpfEngine          bool
	RelevantCVEServiceEnable bool
}

func TestGetConfigurationReader(t *testing.T) {
	cfg := Config{}
	reader, err := cfg.GetConfigurationReader()
	if err == nil {
		t.Errorf("expected an error but got nil")
	}
	if reader != nil {
		t.Errorf("expected nil reader but got %v", reader)
	}

	testConfigData := TestConfigData{
		FalcoEbpfEngine:    true,
		FalcoSyscallFilter: []string{"open", "openat", "execve", "execveat"},
	}

	testData, err := json.Marshal(testConfigData)
	if err != nil {
		t.Errorf("unexpected error while creating test data: %v", err)
	}

	cfgFilePath := "test_config.json"
	err = os.WriteFile(cfgFilePath, testData, 0644)
	if err != nil {
		t.Errorf("unexpected error while creating test file: %v", err)
	}
	defer os.Remove(cfgFilePath)

	os.Setenv(ConfigEnvVar, cfgFilePath)
	reader, err = cfg.GetConfigurationReader()
	if err != nil {
		t.Errorf("unexpected error while getting reader: %v", err)
	}
	if reader == nil {
		t.Errorf("expected non-nil reader but got nil")
	}
}

func TestParseConfiguration(t *testing.T) {

	configPath := path.Join(utils.CurrentDir(), "..", "..", "configuration", "ConfigurationFile.json")
	err := os.Setenv(ConfigEnvVar, configPath)
	if err != nil {
		t.Fatalf("failed to set env %s with err %v", ConfigEnvVar, err)
	}

	cfg := GetConfigurationConfigContext()
	configData, err := cfg.GetConfigurationReader()
	if err != nil {
		t.Errorf("GetConfigurationReader failed with err %v", err)
	}

	c := v1.CreateConfigData()
	if err = cfg.ParseConfiguration(c, bytes.NewReader([]byte{})); err == nil || !strings.Contains(err.Error(), ErrFailedToUnmarshalConfigurationData) {
		t.Errorf("missing error message/incomplete error message, expected error message: '%s', got: '%v'", ErrFailedToUnmarshalConfigurationData, err)
	}

	if err = cfg.ParseConfiguration(c, configData); err != nil {
		t.Errorf("unexpected error while parsing configuration: %v", err)
	}
	if cfg.IsFalcoEbpfEngine() != true {
		t.Errorf("expected IsFalcoEbpfEngine() to be true but got false")
	}
	if len(cfg.GetSyscallFilter()) != len(c.GetFalcoSyscallFilter()) {
		t.Errorf("expected %v syscall filters but got %v", len(c.GetFalcoSyscallFilter()), len(cfg.GetSyscallFilter()))
	}
	if cfg.GetFalcoKernelObjPath() == "" {
		t.Errorf("expected empty kernel obj path but got %v", cfg.GetFalcoKernelObjPath())
	}
	if cfg.GetEbpfEngineLoaderPath() == "" {
		t.Errorf("expected empty ebpf engine loader path but got %v", cfg.GetEbpfEngineLoaderPath())
	}
	if cfg.GetUpdateDataPeriod() != 30*time.Second {
		t.Errorf("expected update data period to be 0 but got %v", cfg.GetUpdateDataPeriod())
	}
	if cfg.GetSniffingMaxTimes() != 6*time.Hour {
		t.Errorf("expected sniffing max times to be 0 but got %v", cfg.GetSniffingMaxTimes())
	}
	if !cfg.IsRelevantCVEServiceEnabled() {
		t.Errorf("expected Is Relevant CVE Service Enabled to be false but got true")
	}
	if cfg.GetNodeName() != "minikube" {
		t.Errorf("expected empty node name but got %v", cfg.GetNodeName())
	}
	if cfg.GetClusterName() != "myCluster" {
		t.Errorf("expected empty cluster name but got %v", cfg.GetClusterName())
	}
}
