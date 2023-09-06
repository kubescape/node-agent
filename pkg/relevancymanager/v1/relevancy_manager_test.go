package relevancymanager

import (
	"context"
	"encoding/json"
	"node-agent/pkg/config"
	"node-agent/pkg/containerwatcher"
	"node-agent/pkg/filehandler/v1"
	"node-agent/pkg/k8sclient"
	"node-agent/pkg/sbomhandler/v1"
	"node-agent/pkg/storage"
	"node-agent/pkg/utils"
	"os"
	"path"
	"testing"
	"time"

	containercollection "github.com/inspektor-gadget/inspektor-gadget/pkg/container-collection"
	"github.com/inspektor-gadget/inspektor-gadget/pkg/types"
	"github.com/kinbiko/jsonassert"
	"github.com/stretchr/testify/assert"
)

func BenchmarkRelevancyManager_ReportFileAccess(b *testing.B) {
	cfg := config.Config{}
	ctx := context.TODO()
	fileHandler, err := filehandler.CreateInMemoryFileHandler()
	assert.NoError(b, err)
	relevancyManager, err := CreateRelevancyManager(cfg, "cluster", fileHandler, nil, nil)
	assert.NoError(b, err)
	for i := 0; i < b.N; i++ {
		relevancyManager.ReportFileAccess(ctx, "ns", "pod", "cont", "file")
	}
	b.ReportAllocs()
}

func TestRelevancyManager(t *testing.T) {
	// create a new relevancy manager
	cfg := config.Config{
		EnableRelevancy:  true,
		InitialDelay:     1 * time.Second,
		MaxSniffingTime:  5 * time.Minute,
		UpdateDataPeriod: 20 * time.Second,
	}
	ctx := context.TODO()
	fileHandler, err := filehandler.CreateInMemoryFileHandler()
	assert.NoError(t, err)
	k8sClient := &k8sclient.K8sClientMock{}
	storageClient := storage.CreateSBOMStorageHttpClientMock("nginx-spdx-format-mock.json")
	sbomHandler := sbomhandler.CreateSBOMHandler(storageClient)
	relevancyManager, err := CreateRelevancyManager(cfg, "cluster", fileHandler, k8sClient, sbomHandler)
	assert.NoError(t, err)
	relevancyManager.SetContainerHandler(containerwatcher.ContainerWatcherMock{})
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
	relevancyManager.ReportContainerStarted(ctx, container)
	// report file access
	files := []string{
		"/path/to/file",
		"/path/to/file2",
		"/usr/sbin/deluser",
	}
	for _, file := range files {
		relevancyManager.ReportFileAccess(ctx, "ns", "pod", "cont", file)
	}
	// let it run for a while
	time.Sleep(10 * time.Second)
	// verify files are reported
	assert.NotNil(t, storageClient.FilteredSBOMs)
	assert.Equal(t, 1, len(storageClient.FilteredSBOMs))
	assert.Equal(t, 1, len(storageClient.FilteredSBOMs[0].Spec.SPDX.Files))
	assert.Equal(t, "/usr/sbin/deluser", storageClient.FilteredSBOMs[0].Spec.SPDX.Files[0].FileName)
	// add one more vulnerable file
	relevancyManager.ReportFileAccess(ctx, "ns", "pod", "cont", "/etc/deluser.conf")
	time.Sleep(1 * time.Second)
	// report container stopped
	relevancyManager.ReportContainerTerminated(ctx, container)
	// let it stop
	time.Sleep(1 * time.Second)
	// verify files are reported (old and new ones)
	assert.Equal(t, 2, len(storageClient.FilteredSBOMs[1].Spec.SPDX.Files))
	assert.Equal(t, "/usr/sbin/deluser", storageClient.FilteredSBOMs[1].Spec.SPDX.Files[0].FileName)
	assert.Equal(t, "/etc/deluser.conf", storageClient.FilteredSBOMs[1].Spec.SPDX.Files[1].FileName)
	// check full content
	gotBytes, err := json.Marshal(storageClient.FilteredSBOMs[0])
	assert.NoError(t, err)
	wantBytes, err := os.ReadFile(path.Join(utils.CurrentDir(), "testdata", "nginx-spdx-filtered.json"))
	assert.NoError(t, err)
	ja := jsonassert.New(t)
	ja.Assertf(string(gotBytes), string(wantBytes))
	// verify cleanup
	time.Sleep(1 * time.Second)
	_, err = fileHandler.GetAndDeleteFiles("ns/pod/cont")
	assert.ErrorContains(t, err, "bucket does not exist for container ns/pod/cont")
}

func TestRelevancyManagerIncompleteSBOM(t *testing.T) {
	// create a new relevancy manager
	cfg := config.Config{
		EnableRelevancy:  true,
		InitialDelay:     1 * time.Second,
		MaxSniffingTime:  5 * time.Minute,
		UpdateDataPeriod: 20 * time.Second,
	}
	ctx := context.TODO()
	fileHandler, err := filehandler.CreateInMemoryFileHandler()
	assert.NoError(t, err)
	k8sClient := &k8sclient.K8sClientMock{}
	storageClient := storage.CreateSBOMStorageHttpClientMock("sbom-incomplete-mock.json")
	sbomHandler := sbomhandler.CreateSBOMHandler(storageClient)
	relevancyManager, err := CreateRelevancyManager(cfg, "cluster", fileHandler, k8sClient, sbomHandler)
	assert.NoError(t, err)
	relevancyManager.SetContainerHandler(containerwatcher.ContainerWatcherMock{})
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
	relevancyManager.ReportContainerStarted(ctx, container)
	// report file access
	relevancyManager.ReportFileAccess(ctx, "ns", "pod", "cont", "/usr/sbin/deluser")
	// let it run for a while
	time.Sleep(10 * time.Second)
	// report container stopped
	relevancyManager.ReportContainerTerminated(ctx, container)
	// let it stop
	time.Sleep(1 * time.Second)
	// verify filtered SBOM is created
	assert.NotNil(t, storageClient.FilteredSBOMs)
	assert.Equal(t, 1, len(storageClient.FilteredSBOMs))
}
