package conthandler

import (
	"os"
	"path"
	"sniffer/pkg/config"
	configV1 "sniffer/pkg/config/v1"
	conthadlerV1 "sniffer/pkg/conthandler/v1"
	"testing"
	"time"

	accumulator "sniffer/pkg/event_data_storage"
)

const (
	REDIS_POD_NAME                                            = "redis-64bd97b5fc-kvh7r"
	REDIS_IMAGE_ID                                            = "docker-pullable://redis@sha256:6a59f1cbb8d28ac484176d52c473494859a512ddba3ea62a547258cf16c9b3ae"
	REDIS_CONTAINER_ID                                        = "16248df36c67"
	REDIS_WLID                                                = "wlid://cluster-test/namespace-any/deployment/redis"
	REDIS_INSTANCE_ID                                         = "any"
	NUMBER_OF_REDIS_EVENT_IN_THE_MOCK_AFTER_FILTER_DUPLICATED = 73
)

func TestContAggregator(t *testing.T) {
	configPath := path.Join(currentDir(), "..", "..", "configuration", "ConfigurationFile.json")
	err := os.Setenv(config.SNIFFER_CONFIG_ENV_VAR, configPath)
	if err != nil {
		t.Fatalf("failed to set env SNIFFER_CONFIG_ENV_VAR with err %v", err)
	}

	cfg := config.GetConfigurationConfigContext()
	configData, err := cfg.GetConfigurationReader()
	if err != nil {
		t.Fatalf("GetConfigurationReader failed with err %v", err)
	}
	err = cfg.ParseConfiguration(configV1.CreateFalcoMockConfigData(), configData)
	if err != nil {
		t.Fatalf("ParseConfiguration failed with err %v", err)
	}

	cacheAccumulatorErrorChan := make(chan error)
	acc := accumulator.GetAccumulator()
	err = acc.StartAccumulator(cacheAccumulatorErrorChan)
	if err != nil {
		t.Fatalf("StartAccumulator failed with err %v", err)
	}

	containersEventChan := make(chan conthadlerV1.ContainerEventData, 50)
	go func() {
		containersEventChan <- *conthadlerV1.CreateNewContainerEvent(REDIS_IMAGE_ID, REDIS_CONTAINER_ID, REDIS_POD_NAME, REDIS_WLID, REDIS_INSTANCE_ID, conthadlerV1.CONTAINER_RUNNING)
	}()

	event := <-containersEventChan
	if event.GetContainerEventType() != conthadlerV1.CONTAINER_RUNNING {
		t.Fatalf("event container type is wrong, get: %s expected: %s", event.GetContainerEventType(), conthadlerV1.CONTAINER_RUNNING)
	}
	if event.GetContainerID() != REDIS_CONTAINER_ID {
		t.Fatalf("container ID is wrong,  get: %s expected: %s", event.GetContainerID(), REDIS_CONTAINER_ID)
	}

	redisAggregator := CreateAggregator(event.GetContainerID())
	aggregatorChannel := make(chan error)
	err = redisAggregator.StartAggregate(aggregatorChannel)
	if err != nil {
		t.Fatalf("StartAggregate: err %v", err)
	}
	time.Sleep(12 * time.Second)
	fileList := redisAggregator.GetContainerRealtimeFileList()
	if len(fileList) < NUMBER_OF_REDIS_EVENT_IN_THE_MOCK_AFTER_FILTER_DUPLICATED {
		t.Fatalf("file list of redis container is not as expected,  get: %d expected: %d", len(fileList), NUMBER_OF_REDIS_EVENT_IN_THE_MOCK_AFTER_FILTER_DUPLICATED)
	}
}
