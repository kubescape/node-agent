package validator

import (
	"os"
	"path"
	"sniffer/pkg/config"
	v1 "sniffer/pkg/config/v1"
	"sniffer/pkg/utils"
	"testing"
)

func TestValidator(t *testing.T) {
	minKernelVersion = "0.1"
	err := checkKernelVersion()
	if err != nil {
		t.Fatalf("checkKernelVersion failed withh error %v", err)
	}
}

func TestInt8ToStr(t *testing.T) {
	// Test with valid input
	input1 := []int8{72, 101, 108, 108, 111, 32, 87, 111, 114, 108, 100, 0}
	expected1 := "Hello World"
	output1 := int8ToStr(input1)
	if output1 != expected1 {
		t.Errorf("int8ToStr(%v) = %v; want %v", input1, output1, expected1)
	}

	// Test with empty input
	var input2 []int8
	expected2 := ""
	output2 := int8ToStr(input2)
	if output2 != expected2 {
		t.Errorf("int8ToStr(%v) = %v; want %v", input2, output2, expected2)
	}

	// Test with input containing only null byte
	input3 := []int8{0}
	expected3 := ""
	output3 := int8ToStr(input3)
	if output3 != expected3 {
		t.Errorf("int8ToStr(%v) = %v; want %v", input3, output3, expected3)
	}

	// Test with input containing multiple null bytes
	input4 := []int8{72, 101, 108, 108, 111, 0, 87, 111, 114, 108, 100, 0}
	expected4 := "Hello"
	output4 := int8ToStr(input4)
	if output4 != expected4 {
		t.Errorf("int8ToStr(%v) = %v; want %v", input4, output4, expected4)
	}
}

func TestCheckPrerequisites(t *testing.T) {
	configPath := path.Join(utils.CurrentDir(), "..", "..", "configuration", "ConfigurationFile.json")
	err := os.Setenv(config.ConfigEnvVar, configPath)
	if err != nil {
		t.Fatalf("failed to set env %s with err %v", config.ConfigEnvVar, err)
	}

	cfg := config.GetConfigurationConfigContext()
	configData, err := cfg.GetConfigurationReader()
	if err != nil {
		t.Errorf("GetConfigurationReader failed with err %v", err)
	}
	err = cfg.ParseConfiguration(v1.CreateConfigData(), configData)
	if err != nil {
		t.Fatalf("ParseConfiguration failed with err %v", err)
	}

	minKernelVersion = "0.1"
	err = CheckPrerequisites()
	if err != nil {
		t.Fatalf("checkNodePrerequisites failed with err %v", err)
	}

}
