package config

import (
	"os"
	"testing"
)

func TestConfig(t *testing.T) {
	err := os.Setenv("SNIFFER_CONFIG", "../../configuration/ConfigurationFile.json")
	if err != nil {
		t.Fatalf("failed to set env SNIFFER_CONFIG with err %v", err)
	}

	cfg := Config{}
	configData, err := cfg.GetConfigurationData()
	if err != nil {
		t.Fatalf("GetConfigurationData failed with err %v", err)
	}
	err = cfg.ParseConfiguration(configData)
	if err != nil {
		t.Fatalf("ParseConfiguration failed with err %v", err)
	}

	if cfg.data.IsFalcoEbpfEngine() == false {
		t.Fatalf("IsFalcoEbpfEngine need to be falco")
	}
}
