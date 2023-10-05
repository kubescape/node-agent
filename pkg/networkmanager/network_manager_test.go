package networkmanager

import (
	"context"
	"node-agent/pkg/config"
	"node-agent/pkg/k8sclient"
	"node-agent/pkg/storage"
	"testing"
	"time"

	containercollection "github.com/inspektor-gadget/inspektor-gadget/pkg/container-collection"
	"github.com/inspektor-gadget/inspektor-gadget/pkg/types"
	"github.com/stretchr/testify/assert"
)

func TestNetworkManager(t *testing.T) {
	cfg := config.Config{
		InitialDelay:     1 * time.Second,
		MaxSniffingTime:  5 * time.Minute,
		UpdateDataPeriod: 20 * time.Second,
	}
	ctx := context.TODO()
	k8sClient := &k8sclient.K8sClientMock{}
	storageClient := &storage.StorageHttpClientMock{}
	am, err := CreateNetworkManager(ctx, cfg, k8sClient, storageClient, "test-cluster")
	assert.NoError(t, err)
	// report container started
	container := &containercollection.Container{
		K8s: containercollection.K8sMetadata{
			BasicK8sMetadata: types.BasicK8sMetadata{
				Namespace:     "ns",
				PodName:       "pod",
				ContainerName: "cont",
			},
		},
		Runtime: containercollection.RuntimeMetadata{
			BasicRuntimeMetadata: types.BasicRuntimeMetadata{
				ContainerID: "5fff6a395ce4e6984a9447cc6cfb09f473eaf278498243963fcc944889bc8400",
			},
		},
	}
	am.ContainerCallback(containercollection.PubSubEvent{
		Type:      containercollection.EventTypeAddContainer,
		Container: container,
	})
}
