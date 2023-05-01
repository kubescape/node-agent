package conthandler

import (
	"path"
	"sniffer/pkg/config"
	configV1 "sniffer/pkg/config/v1"
	conthadlerV1 "sniffer/pkg/conthandler/v1"
	accumulator "sniffer/pkg/event_data_storage"
	"sniffer/pkg/storageclient"
	"sniffer/pkg/utils"
	"testing"
	"time"

	"github.com/kubescape/k8s-interface/instanceidhandler/v1"
)

const (
	RedisContainerIDContHandler = "docker://16248df36c67807ca5c429e6f021fe092e14a27aab89cbde00ba801de0f05266"
)

func TestContMainHandler(t *testing.T) {
	configPath := path.Join(utils.CurrentDir(), "..", "..", "configuration", "ConfigurationFile.json")
	t.Setenv(config.ConfigEnvVar, configPath)

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

	contHandler, err := CreateContainerHandler(nil, storageclient.CreateSBOMStorageHttpClientMock())
	if err != nil {
		t.Fatalf("CreateContainerHandler failed with err %v", err)
	}
	go func() {
		_ = contHandler.afterTimerActions()
	}()
	go func() {
		RedisInstanceID := instanceidhandler.InstanceID{}
		RedisInstanceID.SetAPIVersion("apps/v1")
		RedisInstanceID.SetNamespace("any")
		RedisInstanceID.SetKind("deployment")
		RedisInstanceID.SetName("redis")
		RedisInstanceID.SetContainerName("redis")
		contHandler.containersEventChan <- *conthadlerV1.CreateNewContainerEvent(RedisImageID, RedisContainerIDContHandler, RedisPodName, RedisWLID, &RedisInstanceID, conthadlerV1.ContainerRunning)
	}()

	event := <-contHandler.containersEventChan
	if event.GetContainerEventType() != conthadlerV1.ContainerRunning {
		t.Fatalf("event container type is wrong, get: %s expected: %s", event.GetContainerEventType(), conthadlerV1.ContainerRunning)
	}
	if event.GetContainerID() != RedisContainerIDContHandler {
		t.Fatalf("container ID is wrong,  get: %s expected: %s", event.GetContainerID(), RedisContainerIDContHandler)
	}
	time.Sleep(12 * time.Second)
	err = contHandler.handleNewContainerEvent(event)
	if err != nil {
		t.Fatalf("handleNewContainerEvent failed with error %v", err)
	}
}
