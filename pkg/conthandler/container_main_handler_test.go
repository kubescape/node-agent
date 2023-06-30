package conthandler

import (
	"context"
	"node-agent/pkg/config"
	conthandlerV1 "node-agent/pkg/conthandler/v1"
	"node-agent/pkg/storageclient"
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
	cfg := config.Config{
		EnableRelevancy:  false,
		MaxSniffingTime:  6 * time.Hour,
		UpdateDataPeriod: 1 * time.Minute,
	}
	ctx := context.TODO()
	client := &k8sFakeClient{}
	client.Clientset = fake.NewSimpleClientset()
	contHandler, err := CreateContainerHandler(cfg, "clusterName", client, storageclient.CreateSBOMStorageHttpClientMock())
	if err != nil {
		t.Fatalf("CreateContainerHandler failed with err %v", err)
	}
	go func() {
		_ = contHandler.afterTimerActions(ctx)
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
	err = contHandler.handleContainerRunningEvent(ctx, *event)
	if err != nil {
		t.Fatalf("handleNewContainerEvent failed with error %v", err)
	}
}
