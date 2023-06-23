package conthandler

import (
	"node-agent/pkg/config"
	configV1 "node-agent/pkg/config/v1"
	conthandlerV1 "node-agent/pkg/conthandler/v1"
	"node-agent/pkg/sbom"
	"node-agent/pkg/storageclient"
	"node-agent/pkg/utils"
	"path"
	"testing"
	"time"

	containercollection "github.com/inspektor-gadget/inspektor-gadget/pkg/container-collection"
	"github.com/kubescape/k8s-interface/instanceidhandler/v1"
	"k8s.io/client-go/kubernetes/fake"
)

const (
	RedisContainerIDContHandler = "16248df36c67807ca5c429e6f021fe092e14a27aab89cbde00ba801de0f05266"
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

	client := &k8sFakeClient{}
	client.Clientset = fake.NewSimpleClientset()
	contHandler, err := CreateContainerHandler(client, storageclient.CreateSBOMStorageHttpClientMock())
	if err != nil {
		t.Fatalf("CreateContainerHandler failed with err %v", err)
	}
	go func() {
		_ = contHandler.afterTimerActions()
	}()

	RedisInstanceID := instanceidhandler.InstanceID{}
	RedisInstanceID.SetAPIVersion("apps/v1")
	RedisInstanceID.SetNamespace("any")
	RedisInstanceID.SetKind("deployment")
	RedisInstanceID.SetName("redis")
	RedisInstanceID.SetContainerName("redis")
	cont := &containercollection.Container{
		ID:        RedisContainerIDContHandler,
		Name:      "redis",
		Namespace: "any",
		Podname:   "redis",
	}
	event := conthandlerV1.CreateNewContainerEvent("docker.io/library/redis/latest", cont, "any/redis/redis", "wlid://cluster-foo/namespace-any/deployment-redis", &RedisInstanceID)
	err = contHandler.handleContainerRunningEvent(*event)
	if err != nil {
		t.Fatalf("handleNewContainerEvent failed with error %v", err)
	}
}

func TestContMainHandlerStopMonitorAfterXMinutes(t *testing.T) {
	configPath := path.Join(utils.CurrentDir(), "..", "..", "configuration", "ConfigurationFile.json")
	t.Setenv(config.ConfigEnvVar, configPath)

	cfg := config.GetConfigurationConfigContext()
	configData, err := cfg.GetConfigurationReader()
	if err != nil {
		t.Fatalf("GetConfigurationReader failed with err %v", err)
	}
	err = cfg.ParseConfiguration(configV1.CreateTimesMockConfigData(), configData)
	if err != nil {
		t.Fatalf("ParseConfiguration failed with err %v", err)
	}

	client := &k8sFakeClient{}
	client.Clientset = fake.NewSimpleClientset()
	contHandler, err := CreateContainerHandler(client, storageclient.CreateSBOMStorageHttpClientMock())
	if err != nil {
		t.Fatalf("CreateContainerHandler failed with err %v", err)
	}
	RedisInstanceID := instanceidhandler.InstanceID{}
	RedisInstanceID.SetAPIVersion("apps/v1")
	RedisInstanceID.SetNamespace("any")
	RedisInstanceID.SetKind("deployment")
	RedisInstanceID.SetName("redis")
	RedisInstanceID.SetContainerName("redis")
	cont := &containercollection.Container{
		ID:        RedisContainerIDContHandler,
		Name:      "redis",
		Namespace: "any",
		Podname:   "redis",
	}
	contEvent := conthandlerV1.CreateNewContainerEvent("docker.io/library/redis/latest", cont, "any/redis/redis", "wlid://cluster-foo/namespace-any/deployment-redis", &RedisInstanceID)

	newWatchedContainer := watchedContainerData{
		snifferTicker: createTicker(),
		sbomClient:    sbom.CreateSBOMStorageClient(storageclient.CreateSBOMStorageHttpClientMock(), "", &instanceidhandler.InstanceID{}),
	}
	contHandler.watchedContainers.Store(contEvent.GetContainerID(), newWatchedContainer)
	now := time.Now()
	contHandler.startRelevancyProcess(*contEvent)
	stopTime := time.Now()
	elapsedTime := stopTime.Sub(now)
	if elapsedTime.Minutes() < config.GetConfigurationConfigContext().GetSniffingMaxTimes().Minutes() {
		t.Fatalf("elapsedTime is too little, should be %f < %f", elapsedTime.Minutes(), config.GetConfigurationConfigContext().GetSniffingMaxTimes().Minutes())
	}
	if elapsedTime.Minutes() > (config.GetConfigurationConfigContext().GetSniffingMaxTimes().Minutes() + float64(time.Minute)) {
		t.Fatalf("elapsedTime is too High, should be %f > %f", elapsedTime.Minutes(), config.GetConfigurationConfigContext().GetSniffingMaxTimes().Minutes())
	}
}
