package config

import (
	"os"
	"testing"
)

func TestGetMyContainerID(test *testing.T) {
	if GetMyContainerID() != "111111111111111111" {
		test.Errorf("TestGetMyContainerID")
	}
}

func TestConfigurationFile(test *testing.T) {
	wd, err := os.Getwd()
	if err != nil {
		test.Errorf("ParseConfigurationFile os.Getwd() %v", err)
	}
	if err := parseConfigurationFile(wd + "/../../configuration/SneefferConfigurationFile.txt"); err != nil {
		test.Errorf("ParseConfigurationFile err %v", err)
	}
	if err := validateMandatoryConfigurationn(); err != nil {
		test.Errorf("ParseConfigurationFile err %v", err)
	}
}

func TestFullTestConfigurationFile(test *testing.T) {
	wd, err := os.Getwd()
	if err != nil {
		test.Errorf("TestFullTestConfigurationFile os.Getwd() %v", err)
	}
	err = os.Setenv("SNEEFFER_CONF_FILE_PATH", wd+"/../../configuration/SneefferConfigurationFile.txt")
	if err != nil {
		test.Errorf("TestFullTestConfigurationFile os.Setenv() %v", err)
	}
	err = ParseConfiguration()
	if err != nil {
		test.Errorf("TestFullTestConfigurationFile ParseConfiguration %v", err)
	}
}
