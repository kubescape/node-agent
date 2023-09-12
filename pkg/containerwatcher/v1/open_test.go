package containerwatcher

import (
	"context"
	"node-agent/pkg/config"
	"node-agent/pkg/filehandler/v1"
	"node-agent/pkg/relevancymanager/v1"
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
	relevancyManager, err := relevancymanager.CreateRelevancyManager(ctx, cfg, "cluster", fileHandler, nil, nil)
	assert.NoError(b, err)
	mainHandler, err := CreateIGContainerWatcher(cfg, nil, nil, relevancyManager)
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
