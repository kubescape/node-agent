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

func TestFullAccumulatorFlowAndAllOtherSmallFunctions(t *testing.T) {
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

	acc := GetAccumulator()

	now := time.Now()
	event := evData.CreateKernelEvent(&now, "1234", "111", "1111", "open", "(dirfd: AT_FDCWD, name: /sys/fs/cgroup/perf_event/docker/0002f88945ecff75cf837f29f0378a686c830e8474028f6b913abdcc3be5ecd2/kubepods/besteffort/poda254d032-c044-4760-98d6-2d50aed26492/16248df36c67852de0e421767ef72e89fc0996d734210fbcdb824bcbcce1f57e, flags: O_RDONLY|O_CLOEXEC, mode: 0)", "blabla", "blublu")

	index, newSlotIsNeeded, err := acc.findIndexByTimestamp(event)
	if err != nil {
		t.Fatalf("findIndexByTimestamp failed with error %v", err)
	}
	if newSlotIsNeeded == false {
		t.Fatalf("newSlotIsNeeded need to true")
	}

	acc.createNewSlotInIndex(event, index)
	acc.addEventToCache(event, index)

	if acc.data[index]["1234"][0] != *event {
		t.Fatalf("event %v not exist", event)
	}

}
