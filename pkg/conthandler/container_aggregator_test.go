package conthandler

import (
	"os"
	"path"
	"sniffer/pkg/config"
	configV1 "sniffer/pkg/config/v1"
	conthadlerV1 "sniffer/pkg/conthandler/v1"
	"sniffer/pkg/utils"
	"testing"
	"time"

	accumulator "sniffer/pkg/event_data_storage"

	"github.com/kubescape/k8s-interface/instanceidhandler/v1"
)

const (
	RedisPodName     = "redis-64bd97b5fc-kvh7r"
	RedisImageID     = "docker-pullable://redis@sha256:6a59f1cbb8d28ac484176d52c473494859a512ddba3ea62a547258cf16c9b3ae"
	RedisContainerID = "16248df36c67"
	RedisWLID        = "wlid://cluster-test/namespace-any/deployment/redis"

	NumberOfRedisEventInTheMockAfterFilterDuplicated = 73
)

func TestContAggregator(t *testing.T) {
	configPath := path.Join(utils.CurrentDir(), "..", "..", "configuration", "ConfigurationFile.json")
	err := os.Setenv(config.ConfigEnvVar, configPath)
	if err != nil {
		t.Fatalf("failed to set env ConfigEnvVar with err %v", err)
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

	RedisInstanceID := instanceidhandler.InstanceID{}
	RedisInstanceID.SetAPIVersion("apps/v1")
	RedisInstanceID.SetNamespace("any")
	RedisInstanceID.SetKind("deployment")
	RedisInstanceID.SetName("redis")
	RedisInstanceID.SetContainerName("redis")
	containersEventChan := make(chan conthadlerV1.ContainerEventData, 50)
	go func() {
		containersEventChan <- *conthadlerV1.CreateNewContainerEvent(RedisImageID, RedisContainerID, RedisPodName, RedisWLID, &RedisInstanceID, conthadlerV1.ContainerRunning)
	}()

	event := <-containersEventChan
	if event.GetContainerEventType() != conthadlerV1.ContainerRunning {
		t.Fatalf("event container type is wrong, get: %s expected: %s", event.GetContainerEventType(), conthadlerV1.ContainerRunning)
	}
	if event.GetContainerID() != RedisContainerID {
		t.Fatalf("container ID is wrong,  get: %s expected: %s", event.GetContainerID(), RedisContainerID)
	}

	redisAggregator := CreateAggregator(event.GetContainerID())
	aggregatorChannel := make(chan error)
	err = redisAggregator.StartAggregate(aggregatorChannel)
	if err != nil {
		t.Fatalf("StartAggregate: err %v", err)
	}
	time.Sleep(12 * time.Second)
	fileList := redisAggregator.GetContainerRealtimeFileList()
	if len(fileList) < NumberOfRedisEventInTheMockAfterFilterDuplicated {
		t.Fatalf("file list of redis container is not as expected,  get: %d expected: %d", len(fileList), NumberOfRedisEventInTheMockAfterFilterDuplicated)
	}
}
