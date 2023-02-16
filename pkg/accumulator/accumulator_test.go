package accumulator

import (
	"os"
	"sniffer/pkg/config"
	v1 "sniffer/pkg/config/v1"
	"testing"
	"time"
)

func TestAccumulatorFlow(t *testing.T) {
	err := os.Setenv("SNIFFER_CONFIG", "../../configuration/ConfigurationFile.json")
	if err != nil {
		t.Fatalf("failed to set env SNIFFER_CONFIG with err %v", err)
	}

	cfg := config.GetConfigurationConfigContext()
	configData, err := cfg.GetConfigurationReader()
	if err != nil {
		t.Fatalf("GetConfigurationReader failed with err %v", err)
	}
	err = cfg.ParseConfiguration(v1.CreateFalcoMockConfigData(), configData)
	if err != nil {
		t.Fatalf("ParseConfiguration failed with err %v", err)
	}

	cacheAccumulatorErrorChan := make(chan error)
	acc := CreateAccumulator()
	err = acc.StartAccumulator(cacheAccumulatorErrorChan)
	if err != nil {
		t.Fatalf("StartAccumulator failed with err %v", err)
	}
	time.Sleep(5 * time.Second)
}
