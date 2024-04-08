package containerwatcher

import (
	"context"
	"github.com/kubescape/node-agent/pkg/config"
	"github.com/kubescape/node-agent/pkg/filehandler/v1"
	metricsmanager "github.com/kubescape/node-agent/pkg/metricsmanager"
	"github.com/kubescape/node-agent/pkg/relevancymanager/v1"
	"testing"

	traceropentype "github.com/inspektor-gadget/inspektor-gadget/pkg/gadgets/trace/open/types"
	"github.com/inspektor-gadget/inspektor-gadget/pkg/types"
	"github.com/stretchr/testify/assert"
)

func BenchmarkIGContainerWatcher_openEventCallback(b *testing.B) {
	cfg := config.Config{}
	ctx := context.TODO()
	fileHandler, err := filehandler.CreateInMemoryFileHandler()
	assert.NoError(b, err)
	relevancyManager, err := relevancymanager.CreateRelevancyManager(ctx, cfg, "cluster", fileHandler, nil, nil, nil)
	assert.NoError(b, err)
	mockExporter := metricsmanager.NewMetricsMock()

	mainHandler, err := CreateIGContainerWatcher(cfg, nil, nil, relevancyManager, nil, nil, mockExporter, nil, nil, nil, nil)
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
