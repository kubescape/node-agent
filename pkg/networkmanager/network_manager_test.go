package networkmanager

import (
	"context"
	"fmt"
	"node-agent/pkg/config"
	"node-agent/pkg/storage"
	"testing"
	"time"

	containercollection "github.com/inspektor-gadget/inspektor-gadget/pkg/container-collection"
	"github.com/inspektor-gadget/inspektor-gadget/pkg/types"
	"github.com/kubescape/k8s-interface/k8sinterface"
	"github.com/stretchr/testify/assert"
)

func TestNetworkManager(t *testing.T) {
	cfg := config.Config{
		InitialDelay:     1 * time.Second,
		MaxSniffingTime:  5 * time.Minute,
		UpdateDataPeriod: 10 * time.Second,
	}
	ctx := context.TODO()
	k8sClient := k8sinterface.NewKubernetesApi()
	storageClient := &storage.StorageHttpClientMock{}

	am, err := CreateNetworkManager(ctx, cfg, k8sClient, storageClient, "test-cluster")
	assert.NoError(t, err)
	// report container started
	container := &containercollection.Container{
		K8s: containercollection.K8sMetadata{
			BasicK8sMetadata: types.BasicK8sMetadata{
				Namespace:     "default",
				PodName:       "nginx-deployment-cbdccf466-csh9c",
				ContainerName: "nginx",
			},
		},
		Runtime: containercollection.RuntimeMetadata{
			BasicRuntimeMetadata: types.BasicRuntimeMetadata{
				ContainerID: "docker://802c6c322d264557779fe785013a0dfa84eb658e7791aa36396da809fcb3329c",
			},
		},
	}

	am.ContainerCallback(containercollection.PubSubEvent{
		Type:      containercollection.EventTypeAddContainer,
		Container: container,
	})

	networkEvents := []*NetworkEvent{
		{
			Port:     80,
			PktType:  "HOST",
			Protocol: "tcp",
			PodLabels: map[string]string{
				"app": "nginx",
			},
			Destination: Destination{
				Namespace: "default",
				Name:      "nginx-deployment-cbdccf466-csh9c",
				Kind:      EndpointKindPod,
				PodLabels: map[string]string{
					"app": "nginx",
				},
				IPAddress: "19.64.52.4",
			},
		},
	}

	time.Sleep(10 * time.Second)
	for i := range networkEvents {
		am.SaveNetworkEvent(container.Runtime.ContainerID, container.K8s.PodName, networkEvents[i])
	}
	time.Sleep(150 * time.Second)

	fmt.Println("bla")

}
