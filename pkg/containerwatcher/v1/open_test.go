package containerwatcher

import (
	"context"
	"testing"

	traceropentype "github.com/inspektor-gadget/inspektor-gadget/pkg/gadgets/trace/open/types"
	"github.com/inspektor-gadget/inspektor-gadget/pkg/types"
	"github.com/kubescape/node-agent/pkg/applicationprofilemanager/v1"
	"github.com/kubescape/node-agent/pkg/config"
	"github.com/kubescape/node-agent/pkg/metricsmanager"
	"github.com/stretchr/testify/assert"
)

func BenchmarkIGContainerWatcher_openEventCallback(b *testing.B) {
	cfg := config.Config{}
	ctx := context.TODO()
	applicationProfileManager, err := applicationprofilemanager.CreateApplicationProfileManager(ctx, cfg, "cluster", nil, nil, nil, nil, nil)
	assert.NoError(b, err)
	mockExporter := metricsmanager.NewMetricsMock()

	mainHandler, err := CreateIGContainerWatcher(cfg, applicationProfileManager, nil, nil, nil, mockExporter, nil, nil, nil, nil, nil, nil)
	assert.NoError(b, err)
	event := &traceropentype.Event{
		Event: types.Event{
			CommonData: types.CommonData{
				K8s: types.K8sMetadata{
					BasicK8sMetadata: types.BasicK8sMetadata{
						Namespace:     "ns",
						PodName:       "pod",
						ContainerName: "cont",
					},
				},
			},
			Type: types.NORMAL,
		},
		Path: "file",
	}
	for i := 0; i < b.N; i++ {
		mainHandler.openEventCallback(event)
	}
	b.ReportAllocs()
}
