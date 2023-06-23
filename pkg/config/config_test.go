package config

import (
	"bytes"
	"encoding/json"
	v1 "node-agent/pkg/config/v1"
	"node-agent/pkg/utils"
	"os"
	"path"
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
		t.Setenv(ConfigEnvVar, configPath)

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
		t.Setenv(ConfigEnvVar, "kuku")
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
	defer func(name string) {
		_ = os.Remove(name)
	}(cfgFilePath)

	t.Setenv(ConfigEnvVar, cfgFilePath)
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
	t.Setenv(ConfigEnvVar, configPath)

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
	if cfg.GetUpdateDataPeriod() != 1*time.Minute {
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

func TestIsFalcoEbpfEngineMock(t *testing.T) {
	configPath := path.Join(utils.CurrentDir(), "..", "..", "configuration", "ConfigurationFile.json")
	t.Setenv(ConfigEnvVar, configPath)

	config := GetConfigurationConfigContext()
	configData, err := config.GetConfigurationReader()
	if err != nil {
		t.Errorf("GetConfigurationReader failed with err %v", err)
	}
	err = config.ParseConfiguration(v1.CreateConfigData(), configData)
	if err != nil {
		t.Fatalf("ParseConfiguration failed with err %v", err)
	}

	expected := true
	actual := config.IsFalcoEbpfEngine()

	if actual != expected {
		t.Errorf("IsFalcoEbpfEngine() returned %v, expected %v", actual, expected)
	}
}

// func TestGetFalcoSyscallFilterMockv(t *testing.T) {
// 	configPath := path.Join(utils.CurrentDir(), "..", "..", "configuration", "ConfigurationFile.json")
// 	err := os.Setenv(ConfigEnvVar, configPath)
// 	if err != nil {
// 		t.Fatalf("failed to set env %s with err %v", ConfigEnvVar, err)
// 	}

// 	config := GetConfigurationConfigContext()
// 	configData, err := config.GetConfigurationReader()
// 	if err != nil {
// 		t.Errorf("GetConfigurationReader failed with err %v", err)
// 	}
// 	err = config.ParseConfiguration(v1.CreateConfigData(), configData)
// 	if err != nil {
// 		t.Fatalf("ParseConfiguration failed with err %v", err)
// 	}

// 	expected := []string{"open", "openat", "execve", "execveat"}
// 	actual := config.GetFalcoSyscallFilter()

// 	if !equalStringSlices(actual, expected) {
// 		t.Errorf("GetFalcoSyscallFilter() returned %v, expected %v", actual, expected)
// 	}
// }

func TestGetFalcoKernelObjPath(t *testing.T) {
	configPath := path.Join(utils.CurrentDir(), "..", "..", "configuration", "ConfigurationFile.json")
	t.Setenv(ConfigEnvVar, configPath)

	config := GetConfigurationConfigContext()
	configData, err := config.GetConfigurationReader()
	if err != nil {
		t.Errorf("GetConfigurationReader failed with err %v", err)
	}
	err = config.ParseConfiguration(v1.CreateConfigData(), configData)
	if err != nil {
		t.Fatalf("ParseConfiguration failed with err %v", err)
	}

	expected := "./resources/ebpf/falco/kernel_obj.o"
	actual := config.GetFalcoKernelObjPath()

	if actual != expected {
		t.Errorf("GetFalcoKernelObjPath() returned %v, expected %v", actual, expected)
	}
}

func TestGetEbpfEngineLoaderPath(t *testing.T) {
	configPath := path.Join(utils.CurrentDir(), "..", "..", "configuration", "ConfigurationFile.json")
	t.Setenv(ConfigEnvVar, configPath)

	config := GetConfigurationConfigContext()
	configData, err := config.GetConfigurationReader()
	if err != nil {
		t.Errorf("GetConfigurationReader failed with err %v", err)
	}
	err = config.ParseConfiguration(v1.CreateConfigData(), configData)
	if err != nil {
		t.Fatalf("ParseConfiguration failed with err %v", err)
	}

	expected := "./resources/ebpf/falco/userspace_app"
	actual := config.GetEbpfEngineLoaderPath()

	if actual != expected {
		t.Errorf("GetEbpfEngineLoaderPath() returned %v, expected %v", actual, expected)
	}
}

func TestGetUpdateDataPeriodMock(t *testing.T) {
	configPath := path.Join(utils.CurrentDir(), "..", "..", "configuration", "ConfigurationFile.json")
	t.Setenv(ConfigEnvVar, configPath)

	config := GetConfigurationConfigContext()
	configData, err := config.GetConfigurationReader()
	if err != nil {
		t.Errorf("GetConfigurationReader failed with err %v", err)
	}
	err = config.ParseConfiguration(v1.CreateConfigData(), configData)
	if err != nil {
		t.Fatalf("ParseConfiguration failed with err %v", err)
	}

	expected := time.Duration(1) * time.Minute
	actual := config.GetUpdateDataPeriod()

	if actual != expected {
		t.Errorf("GetUpdateDataPeriod() returned %v, expected %v", actual, expected)
	}
}

func TestGetSniffingMaxTimesMock(t *testing.T) {
	configPath := path.Join(utils.CurrentDir(), "..", "..", "configuration", "ConfigurationFile.json")
	t.Setenv(ConfigEnvVar, configPath)

	config := GetConfigurationConfigContext()
	configData, err := config.GetConfigurationReader()
	if err != nil {
		t.Errorf("GetConfigurationReader failed with err %v", err)
	}
	err = config.ParseConfiguration(v1.CreateConfigData(), configData)
	if err != nil {
		t.Fatalf("ParseConfiguration failed with err %v", err)
	}

	expected := time.Duration(6*60*60) * time.Second
	actual := config.GetSniffingMaxTimes()

	if actual != expected {
		t.Errorf("GetSniffingMaxTimes() returned %v, expected %v", actual, expected)
	}
}

func TestIsRelevantCVEServiceEnabledMock(t *testing.T) {
	configPath := path.Join(utils.CurrentDir(), "..", "..", "configuration", "ConfigurationFile.json")
	t.Setenv(ConfigEnvVar, configPath)

	config := GetConfigurationConfigContext()
	configData, err := config.GetConfigurationReader()
	if err != nil {
		t.Errorf("GetConfigurationReader failed with err %v", err)
	}
	err = config.ParseConfiguration(v1.CreateConfigData(), configData)
	if err != nil {
		t.Fatalf("ParseConfiguration failed with err %v", err)
	}

	expected := true
	actual := config.IsRelevantCVEServiceEnabled()

	if actual != expected {
		t.Errorf("IsRelevantCVEServiceEnabled() returned %v, expected %v", actual, expected)
	}
}

func TestGetNodeName(t *testing.T) {
	configPath := path.Join(utils.CurrentDir(), "..", "..", "configuration", "ConfigurationFile.json")
	t.Setenv(ConfigEnvVar, configPath)

	config := GetConfigurationConfigContext()
	configData, err := config.GetConfigurationReader()
	if err != nil {
		t.Errorf("GetConfigurationReader failed with err %v", err)
	}
	err = config.ParseConfiguration(v1.CreateConfigData(), configData)
	if err != nil {
		t.Fatalf("ParseConfiguration failed with err %v", err)
	}

	expected := "minikube"
	actual := config.GetNodeName()

	if actual != expected {
		t.Errorf("GetNodeName() returned %v, expected %v", actual, expected)
	}
}

func TestGetClusterName(t *testing.T) {
	configPath := path.Join(utils.CurrentDir(), "..", "..", "configuration", "ConfigurationFile.json")
	t.Setenv(ConfigEnvVar, configPath)

	config := GetConfigurationConfigContext()
	configData, err := config.GetConfigurationReader()
	if err != nil {
		t.Errorf("GetConfigurationReader failed with err %v", err)
	}
	err = config.ParseConfiguration(v1.CreateConfigData(), configData)
	if err != nil {
		t.Fatalf("ParseConfiguration failed with err %v", err)
	}

	expected := "myCluster"
	actual := config.GetClusterName()

	if actual != expected {
		t.Errorf("GetClusterName() returned %v, expected %v", actual, expected)
	}
}

func TestGetNamespace(t *testing.T) {
	configPath := path.Join(utils.CurrentDir(), "..", "..", "configuration", "ConfigurationFile.json")
	t.Setenv(ConfigEnvVar, configPath)

	config := GetConfigurationConfigContext()
	configData, err := config.GetConfigurationReader()
	if err != nil {
		t.Errorf("GetConfigurationReader failed with err %v", err)
	}
	err = config.ParseConfiguration(v1.CreateConfigData(), configData)
	if err != nil {
		t.Fatalf("ParseConfiguration failed with err %v", err)
	}

	expected := "kubescape"
	actual := config.GetNamespace()

	if actual != expected {
		t.Errorf("GetNamespace() returned %v, expected %v", actual, expected)
	}
}

func TestGetContainerName(t *testing.T) {
	configPath := path.Join(utils.CurrentDir(), "..", "..", "configuration", "ConfigurationFile.json")
	t.Setenv(ConfigEnvVar, configPath)

	config := GetConfigurationConfigContext()
	configData, err := config.GetConfigurationReader()
	if err != nil {
		t.Errorf("GetConfigurationReader failed with err %v", err)
	}
	err = config.ParseConfiguration(v1.CreateConfigData(), configData)
	if err != nil {
		t.Fatalf("ParseConfiguration failed with err %v", err)
	}

	expected := "contName"
	actual := config.GetContainerName()

	if actual != expected {
		t.Errorf("GetContainerName() returned %v, expected %v", actual, expected)
	}
}

func TestGetBackgroundContextURL(t *testing.T) {
	configPath := path.Join(utils.CurrentDir(), "..", "..", "configuration", "ConfigurationFile.json")
	t.Setenv(ConfigEnvVar, configPath)

	config := GetConfigurationConfigContext()
	configData, err := config.GetConfigurationReader()
	if err != nil {
		t.Errorf("GetConfigurationReader failed with err %v", err)
	}
	err = config.ParseConfiguration(v1.CreateConfigData(), configData)
	if err != nil {
		t.Fatalf("ParseConfiguration failed with err %v", err)
	}
	t.Setenv("OTEL_COLLECTOR_SVC", "URLcontext")

	expected := "URLcontext"
	config.data.SetBackgroundContextURL()
	actual := config.GetBackgroundContextURL()

	if actual != expected {
		t.Errorf("GetBackgroundContextURL() returned %v, expected %v", actual, expected)
	}
}

func TestGetAccountID(t *testing.T) {
	configPath := path.Join(utils.CurrentDir(), "..", "..", "configuration", "ConfigurationFile.json")
	t.Setenv(ConfigEnvVar, configPath)

	config := GetConfigurationConfigContext()
	configData, err := config.GetConfigurationReader()
	if err != nil {
		t.Errorf("GetConfigurationReader failed with err %v", err)
	}
	err = config.ParseConfiguration(v1.CreateConfigData(), configData)
	if err != nil {
		t.Fatalf("ParseConfiguration failed with err %v", err)
	}

	expected := "myAccountID"
	actual := config.GetAccountID()

	if actual != expected {
		t.Errorf("GetAccountID() returned %v, expected %v", actual, expected)
	}
}
