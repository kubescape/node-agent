package relevancymanager

import (
	"context"
	_ "embed"
	"encoding/json"
	"os"
	"path"
	"testing"
	"time"

	mapset "github.com/deckarep/golang-set/v2"
	containercollection "github.com/inspektor-gadget/inspektor-gadget/pkg/container-collection"
	"github.com/inspektor-gadget/inspektor-gadget/pkg/types"
	"github.com/kinbiko/jsonassert"
	helpersv1 "github.com/kubescape/k8s-interface/instanceidhandler/v1/helpers"
	"github.com/kubescape/node-agent/pkg/config"
	"github.com/kubescape/node-agent/pkg/filehandler/v1"
	"github.com/kubescape/node-agent/pkg/k8sclient"
	"github.com/kubescape/node-agent/pkg/sbomhandler/syfthandler"
	"github.com/kubescape/node-agent/pkg/storage"
	"github.com/kubescape/node-agent/pkg/utils"
	"github.com/kubescape/storage/pkg/apis/softwarecomposition/v1beta1"
	"github.com/stretchr/testify/assert"
)

func BenchmarkRelevancyManager_ReportFileExec(b *testing.B) {
	cfg := config.Config{}
	ctx := context.TODO()
	fileHandler, err := filehandler.CreateInMemoryFileHandler()
	assert.NoError(b, err)
	relevancyManager, err := CreateRelevancyManager(ctx, cfg, "cluster", fileHandler, nil, nil, mapset.NewSet[string]())
	assert.NoError(b, err)
	for i := 0; i < b.N; i++ {
		relevancyManager.ReportFileExec("ns", "ns", "file")
	}
	b.ReportAllocs()
}

//go:embed testdata/nginx-syft-crd.json
var nginxSyftCRD []byte

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
	var syftDoc v1beta1.SBOMSyft
	err = json.Unmarshal(nginxSyftCRD, &syftDoc)
	assert.NoError(t, err)

	storageClient := storage.CreateSyftSBOMStorageHttpClientMock(syftDoc)
	sbomHandler := syfthandler.CreateSyftSBOMHandler(storageClient)

	relevancyManager, err := CreateRelevancyManager(ctx, cfg, "cluster", fileHandler, k8sClient, sbomHandler, mapset.NewSet[string]())
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
				ContainerID:          "5fff6a395ce4e6984a9447cc6cfb09f473eaf278498243963fcc944889bc8400",
				ContainerImageDigest: "nginx@sha256:6a59f1cbb8d28ac484176d52c473494859a512ddba3ea62a547258cf16c9b3ae",
				ContainerImageName:   "nginx",
			},
		},
	}
	relevancyManager.ContainerCallback(containercollection.PubSubEvent{
		Type:      containercollection.EventTypeAddContainer,
		Container: container,
	})

	// report file access
	files := []string{
		"/path/to/file",
		"/path/to/file2",
		"/usr/sbin/deluser",
	}

	for _, file := range files {
		relevancyManager.ReportFileExec("ns/pod/cont", "ns/pod/cont", file)
	}

	// let it run for a while
	time.Sleep(5 * time.Second)
	// report a same file again, should do noop
	relevancyManager.ReportFileExec("ns/pod/cont", "ns/pod/cont", "/usr/sbin/deluser")
	// let it run for a while
	time.Sleep(5 * time.Second)
	// verify files are reported and we have only 1 filtered SBOM
	assert.NotNil(t, storageClient.FilteredSyftSBOMs)
	assert.Equal(t, 1, len(storageClient.FilteredSyftSBOMs))
	assert.Equal(t, 1, len(storageClient.FilteredSyftSBOMs[0].Spec.Syft.Files))
	assert.Equal(t, "/usr/sbin/deluser", storageClient.FilteredSyftSBOMs[0].Spec.Syft.Files[0].Location.RealPath)

	// add one more vulnerable file
	relevancyManager.ReportFileExec("ns/pod/cont", "ns/pod/cont", "/etc/deluser.conf")
	time.Sleep(1 * time.Second)
	// report container stopped
	relevancyManager.ContainerCallback(containercollection.PubSubEvent{
		Type:      containercollection.EventTypeRemoveContainer,
		Container: container,
	})

	// let it stop
	time.Sleep(1 * time.Second)

	// verify files are reported (old and new ones)
	assert.Equal(t, 2, len(storageClient.FilteredSyftSBOMs[1].Spec.Syft.Files))
	foundFiles := 0
	for _, file := range storageClient.FilteredSyftSBOMs[1].Spec.Syft.Files {
		if file.Location.RealPath == "/usr/sbin/deluser" || file.Location.RealPath == "/etc/deluser.conf" {
			foundFiles++
		}
	}

	assert.Equal(t, foundFiles, 2)

	// write filtered sbom to json file
	gotBytes, err := json.Marshal(storageClient.FilteredSyftSBOMs[0])
	assert.NoError(t, err)

	wantBytes, err := os.ReadFile(path.Join(utils.CurrentDir(), "testdata", "nginx-syft-filtered.json"))
	assert.NoError(t, err)
	ja := jsonassert.New(t)
	ja.Assertf(string(gotBytes), string(wantBytes))
	// verify cleanup
	time.Sleep(1 * time.Second)
	_, err = fileHandler.GetAndDeleteFiles("ns/pod/cont")
	assert.ErrorContains(t, err, "bucket does not exist for container ns/pod/cont")
}

func TestRelevancyManagerIncompleteSBOM(t *testing.T) {
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
	var syftDoc v1beta1.SBOMSyft
	err = json.Unmarshal(nginxSyftCRD, &syftDoc)
	assert.NoError(t, err)
	syftDoc.Annotations = map[string]string{
		helpersv1.StatusMetadataKey: helpersv1.Incomplete}

	storageClient := storage.CreateSyftSBOMStorageHttpClientMock(syftDoc)
	sbomHandler := syfthandler.CreateSyftSBOMHandler(storageClient)
	relevancyManager, err := CreateRelevancyManager(ctx, cfg, "cluster", fileHandler, k8sClient, sbomHandler, mapset.NewSet[string]())
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
				ContainerID:          "5fff6a395ce4e6984a9447cc6cfb09f473eaf278498243963fcc944889bc8400",
				ContainerImageName:   "docker.io/library/nginx:latest",
				ContainerImageDigest: "sha256:0c86dddac19f2ce4fd716ac58c0fd87bf69bfd4edabfd6971fb885bafd12a00b",
			},
		},
	}
	relevancyManager.ContainerCallback(containercollection.PubSubEvent{
		Type:      containercollection.EventTypeAddContainer,
		Container: container,
	})
	// report file access
	relevancyManager.ReportFileExec("ns/pod/cont", "ns/pod/cont", "/usr/sbin/deluser")
	// let it run for a while
	time.Sleep(10 * time.Second)
	// report container stopped
	relevancyManager.ContainerCallback(containercollection.PubSubEvent{
		Type:      containercollection.EventTypeRemoveContainer,
		Container: container,
	})
	// let it stop
	time.Sleep(1 * time.Second)
	// verify filtered SBOM is created
	assert.NotNil(t, storageClient.FilteredSyftSBOMs)
	assert.Equal(t, 1, len(storageClient.FilteredSyftSBOMs))
}
