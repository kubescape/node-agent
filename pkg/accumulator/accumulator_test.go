package accumulator

import (
	"os"
	"sniffer/pkg/config"
	v1 "sniffer/pkg/config/v1"
	evData "sniffer/pkg/ebpfev/v1"
	"testing"
	"time"
)

const (
	REDIS_CONTAINERID                 = "16248df36c67"
	NUMBER_OF_REDIS_EVENT_IN_THE_MOCK = 703
)

func TestAccumulatorFlow(t *testing.T) {
	err := os.Setenv(config.SNIFFER_CONFIG, "../../configuration/ConfigurationFile.json")
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
	acc := GetAccumulator()
	err = acc.StartAccumulator(cacheAccumulatorErrorChan)
	if err != nil {
		t.Fatalf("StartAccumulator failed with err %v", err)
	}
	time.Sleep(5 * time.Second)

	var data []evData.EventData
	acc.AccumulatorByContainerID(&data, REDIS_CONTAINERID)
	if len(data) < NUMBER_OF_REDIS_EVENT_IN_THE_MOCK {
		t.Fatalf("failed to get redis server events %d < 703", len(data))
	}
}
