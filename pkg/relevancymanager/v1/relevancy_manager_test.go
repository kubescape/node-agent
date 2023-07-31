package relevancymanager

import (
	"context"
	"node-agent/pkg/config"
	"node-agent/pkg/filehandler/v1"
	"testing"

	"github.com/spf13/afero"
	"github.com/stretchr/testify/assert"
)

func BenchmarkRelevancyManager_ReportFileAccess(b *testing.B) {
	cfg := config.Config{}
	ctx := context.TODO()
	fileHandler, err := filehandler.CreateInMemoryFileHandler()
	assert.NoError(b, err)
	relevancyManager, err := CreateRelevancyManager(cfg, "cluster", fileHandler, nil, afero.NewMemMapFs(), nil)
	assert.NoError(b, err)
	for i := 0; i < b.N; i++ {
		relevancyManager.ReportFileAccess(ctx, "ns", "pod", "cont", "file")
	}
	b.ReportAllocs()
}
