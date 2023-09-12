package applicationprofilemanager

import (
	"context"
	"node-agent/pkg/config"
	"node-agent/pkg/k8sclient"
	"node-agent/pkg/storage"
	"testing"
	"time"

	mapset "github.com/deckarep/golang-set/v2"
	containercollection "github.com/inspektor-gadget/inspektor-gadget/pkg/container-collection"
	"github.com/inspektor-gadget/inspektor-gadget/pkg/types"
	"github.com/stretchr/testify/assert"
)

func TestApplicationProfileManager_ReportCapability(t *testing.T) {
	cfg := config.Config{
		InitialDelay:     1 * time.Second,
		MaxSniffingTime:  5 * time.Minute,
		UpdateDataPeriod: 20 * time.Second,
	}
	type fields struct {
		k8sClient     k8sclient.K8sClientInterface
		storageClient storage.StorageClient
	}
	type args struct {
		capability string
	}
	tests := []struct {
		name   string
		fields fields
		args   args
	}{
		{
			name: "Test1",
			args: args{
				capability: "NET_BIND_SERVICE",
			},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			am := &ApplicationProfileManager{
				cfg:           cfg,
				ctx:           context.TODO(),
				k8sClient:     tt.fields.k8sClient,
				storageClient: tt.fields.storageClient,
			}
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
			am.ReportCapability("ns/pod/cont", tt.args.capability)
			value, ok := am.capabilitiesSets.Load("ns/pod/cont")
			assert.True(t, ok)
			set := value.(*mapset.Set[string])
			assert.Equal(t, []string{tt.args.capability}, (*set).ToSlice())
		})
	}
}
