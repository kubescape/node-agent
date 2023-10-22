package networkmanager

import (
	"context"
	"node-agent/pkg/config"
	storagev1 "node-agent/pkg/storage/v1"
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
	storageClient, err := storagev1.CreateStorageNoCache()

	am, err := CreateNetworkManager(ctx, cfg, k8sClient, storageClient, "test-cluster")
	assert.NoError(t, err)

	containers := []containercollection.Container{
		{
			K8s: containercollection.K8sMetadata{
				BasicK8sMetadata: types.BasicK8sMetadata{
					Namespace:     "default",
					PodName:       "nginx-deployment-fcc867f7-dgjrg",
					ContainerName: "nginx",
				},
			},
			Runtime: containercollection.RuntimeMetadata{
				BasicRuntimeMetadata: types.BasicRuntimeMetadata{
					ContainerID: "docker://802c6c322d264557779fe785013a0dfa84eb658e7791aa36396da809fcb3329c",
				},
			},
		},
		{
			K8s: containercollection.K8sMetadata{
				BasicK8sMetadata: types.BasicK8sMetadata{
					Namespace:     "kube-system",
					PodName:       "fluentd-elasticsearch-hlsbx",
					ContainerName: "fluentd-elasticsearch",
				},
			},
			Runtime: containercollection.RuntimeMetadata{
				BasicRuntimeMetadata: types.BasicRuntimeMetadata{
					ContainerID: "docker://50b40cad5db4165b712909453e1927d8baada94cdefa7c11b90cb775024d041d",
				},
			},
		},
	}

	for i := range containers {
		am.ContainerCallback(containercollection.PubSubEvent{
			Type:      containercollection.EventTypeAddContainer,
			Container: &containers[i],
		})
	}

	networkEvents := []*NetworkEvent{
		{
			Port:      80,
			PktType:   "HOST",
			Protocol:  "tcp",
			PodLabels: "app=nginx2",
			Destination: Destination{
				Namespace: "default",
				Name:      "nginx-deployment-cbdccf466-csh9c",
				Kind:      EndpointKindPod,
				PodLabels: "app=nginx2",
				IPAddress: "19.64.52.5",
			},
		},
		// {
		// 	Port:      8000,
		// 	PktType:   "HOST",
		// 	Protocol:  "tcp",
		// 	PodLabels: "app=nginx2",
		// 	Destination: Destination{
		// 		Namespace: "default",
		// 		Name:      "nginx-deployment-cbdccf466-csh9c",
		// 		Kind:      EndpointKindPod,
		// 		PodLabels: "app=nginx2",
		// 		IPAddress: "19.64.52.5",
		// 	},
		// },
		// {
		// 	Port:      80,
		// 	PktType:   "HOST",
		// 	Protocol:  "tcp",
		// 	PodLabels: "app=nginx",
		// 	Destination: Destination{
		// 		Namespace: "default",
		// 		Name:      "nginx-deployment-cbdccf466-csh9c",
		// 		Kind:      EndpointKindService,
		// 		PodLabels: "SERVICE=nginx2",
		// 		IPAddress: "19.64.52.4",
		// 	},
		// },
		// {
		// 	Port:      80,
		// 	PktType:   "HOST",
		// 	Protocol:  "tcp",
		// 	PodLabels: "app=nginx2",
		// 	Destination: Destination{
		// 		Namespace: "default",
		// 		Name:      "nginx-deployment-cbdccf466-csh9c",
		// 		Kind:      EndpointKindPod,
		// 		PodLabels: "app=nginx2",
		// 		IPAddress: "19.64.52.4",
		// 	},
		// },
		{
			Port:      3333,
			PktType:   "OUTGOING",
			Protocol:  "tcp",
			PodLabels: "",
			Destination: Destination{
				Namespace: "",
				Name:      "nginx-deployment-cbdccf466-csh9c",
				Kind:      EndpointKindRaw,
				PodLabels: "",
				IPAddress: "19.64.52.4",
			},
		}, {
			Port:      4444,
			PktType:   "OUTGOING",
			Protocol:  "tcp",
			PodLabels: "",
			Destination: Destination{
				Namespace: "",
				Name:      "nginx-deployment-cbdccf466-csh9c",
				Kind:      EndpointKindRaw,
				PodLabels: "",
				IPAddress: "19.64.52.4",
			},
		}, {
			Port:      4444,
			PktType:   "OUTGOING",
			Protocol:  "tcp",
			PodLabels: "",
			Destination: Destination{
				Namespace: "",
				Name:      "nginx-deployment-cbdccf466-csh9c",
				Kind:      EndpointKindRaw,
				PodLabels: "",
				IPAddress: "19.64.52.5",
			},
		},
	}

	time.Sleep(10 * time.Second)
	for i := range networkEvents {
		am.SaveNetworkEvent(containers[0].Runtime.ContainerID, containers[0].K8s.PodName, networkEvents[i])
	}
	time.Sleep(150 * time.Second)

}
