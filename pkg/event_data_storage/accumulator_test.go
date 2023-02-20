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
	NUMBER_OF_REDIS_EVENT_IN_THE_MOCK = 402
)

func TestFullAccumulatorFlow(t *testing.T) {
	err := os.Setenv(config.SNIFFER_CONFIG_ENV_VAR, "../../configuration/ConfigurationFile.json")
	if err != nil {
		t.Fatalf("failed to set env SNIFFER_CONFIG_ENV_VAR with err %v", err)
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

// func TestFullAccumulatorFlowAndAllOtherSmallFunctions(t *testing.T) {
// 	err := os.Setenv(config.SNIFFER_CONFIG_ENV_VAR, "../../configuration/ConfigurationFile.json")
// 	if err != nil {
// 		t.Fatalf("failed to set env SNIFFER_CONFIG_ENV_VAR with err %v", err)
// 	}

// 	cfg := config.GetConfigurationConfigContext()
// 	configData, err := cfg.GetConfigurationReader()
// 	if err != nil {
// 		t.Fatalf("GetConfigurationReader failed with err %v", err)
// 	}
// 	err = cfg.ParseConfiguration(v1.CreateFalcoMockConfigData(), configData)
// 	if err != nil {
// 		t.Fatalf("ParseConfiguration failed with err %v", err)
// 	}

// 	cacheAccumulatorErrorChan := make(chan error)
// 	acc := GetAccumulator()
// 	err = acc.StartAccumulator(cacheAccumulatorErrorChan)
// 	if err != nil {
// 		t.Fatalf("StartAccumulator failed with err %v", err)
// 	}
// 	time.Sleep(5 * time.Second)

// 	time, err := acc.getFirstTimestamp()
// 	if err != nil {
// 		t.Fatalf("getFirstTimestamp failed with err %v", err)
// 	}
// 	if !time.Equal(acc.accumulatorData[0][acc.firstMapKeysOfAccumulatorData[0]][0].GetEventTimestamp()) {
// 		t.Fatalf("getFirstTimestamp not equal to known timestamp")
// 	}
// }
