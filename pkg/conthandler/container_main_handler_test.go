package conthandler

import (
	"os"
	"path"
	"path/filepath"
	"runtime"
	"sniffer/pkg/config"
	configV1 "sniffer/pkg/config/v1"
	conthadlerV1 "sniffer/pkg/conthandler/v1"
	accumulator "sniffer/pkg/event_data_storage"
	"testing"
	"time"

	"k8s.io/apimachinery/pkg/watch"
	"k8s.io/client-go/kubernetes/fake"
)

const (
	REDIS_CONTAINER_ID_CONT_HANDLER = "docker://16248df36c67807ca5c429e6f021fe092e14a27aab89cbde00ba801de0f05266"
)

var watcherMainHandler *watch.FakeWatcher

type k8sFakeClientMainHandler struct {
	Clientset *fake.Clientset
}

func (client *k8sFakeClientMainHandler) GetWatcher() (watch.Interface, error) {
	watcherMainHandler = watch.NewFake()
	return watcherMainHandler, nil
}

func TestContMainHandler(t *testing.T) {
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

	contHandler, err := CreateContainerHandler(nil)
	if err != nil {
		t.Fatalf("CreateContainerHandler failed with err %v", err)
	}
	go contHandler.afterTimerActions()
	go func() {
		contHandler.containersEventChan <- *conthadlerV1.CreateNewContainerEvent(REDIS_IMAGE_ID, REDIS_CONTAINER_ID_CONT_HANDLER, REDIS_POD_NAME, REDIS_WLID, REDIS_INSTANCE_ID, conthadlerV1.CONTAINER_RUNNING)
	}()

	event := <-contHandler.containersEventChan
	if event.GetContainerEventType() != conthadlerV1.CONTAINER_RUNNING {
		t.Fatalf("event container type is wrong, get: %s expected: %s", event.GetContainerEventType(), conthadlerV1.CONTAINER_RUNNING)
	}
	if event.GetContainerID() != REDIS_CONTAINER_ID_CONT_HANDLER {
		t.Fatalf("container ID is wrong,  get: %s expected: %s", event.GetContainerID(), REDIS_CONTAINER_ID_CONT_HANDLER)
	}
	time.Sleep(12 * time.Second)
	err = contHandler.handleNewContainerEvent(event)
	if err != nil {
		t.Fatalf("handleNewContainerEvent failed with error %v", err)
	}

}

func currentDir() string {
	_, filename, _, _ := runtime.Caller(1)

	return filepath.Dir(filename)
}
