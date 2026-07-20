package v1

import (
	"context"
	"errors"
	"sync"
	"testing"

	mapset "github.com/deckarep/golang-set/v2"
	containercollection "github.com/inspektor-gadget/inspektor-gadget/pkg/container-collection"
	"github.com/inspektor-gadget/inspektor-gadget/pkg/types"
	helpersv1 "github.com/kubescape/k8s-interface/instanceidhandler/v1/helpers"
	"github.com/kubescape/k8s-interface/names"
	"github.com/kubescape/node-agent/pkg/config"
	"github.com/kubescape/node-agent/pkg/metricsmanager"
	sbomscanner "github.com/kubescape/node-agent/pkg/sbomscanner/v1"
	"github.com/kubescape/storage/pkg/apis/softwarecomposition/v1beta1"
	"github.com/stretchr/testify/assert"
	k8serrors "k8s.io/apimachinery/pkg/api/errors"
	"k8s.io/apimachinery/pkg/runtime/schema"
	runtime "k8s.io/cri-api/pkg/apis/runtime/v1"
)

// fakeSbomClient is an in-memory storage.SbomClient used to observe how
// processContainerWithMetadata persists SBOM state across repeated calls.
type fakeSbomClient struct {
	mu           sync.Mutex
	sboms        map[string]*v1beta1.SBOMSyft
	replaceCalls int
}

func newFakeSbomClient() *fakeSbomClient {
	return &fakeSbomClient{sboms: map[string]*v1beta1.SBOMSyft{}}
}

func (f *fakeSbomClient) CreateSBOM(sbom *v1beta1.SBOMSyft) (*v1beta1.SBOMSyft, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	if _, ok := f.sboms[sbom.Name]; ok {
		return nil, k8serrors.NewAlreadyExists(schema.GroupResource{Resource: "sbomsyfts"}, sbom.Name)
	}
	f.sboms[sbom.Name] = sbom.DeepCopy()
	return sbom, nil
}

func (f *fakeSbomClient) GetSBOMMeta(name string) (*v1beta1.SBOMSyft, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	if s, ok := f.sboms[name]; ok {
		return s.DeepCopy(), nil
	}
	return nil, k8serrors.NewNotFound(schema.GroupResource{Resource: "sbomsyfts"}, name)
}

func (f *fakeSbomClient) ReplaceSBOM(sbom *v1beta1.SBOMSyft) (*v1beta1.SBOMSyft, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.replaceCalls++
	f.sboms[sbom.Name] = sbom.DeepCopy()
	return sbom, nil
}

// fakeScannerClient is a sbomscanner.SBOMScannerClient that always fails, used to
// deterministically drive processContainerWithMetadata into its generic
// SBOM-generation-failure branch without depending on real image/digest parsing.
type fakeScannerClient struct{ err error }

func (f *fakeScannerClient) CreateSBOM(_ context.Context, _ sbomscanner.ScanRequest) (*sbomscanner.ScanResult, error) {
	return nil, f.err
}
func (f *fakeScannerClient) Ready() bool  { return true }
func (f *fakeScannerClient) Close() error { return nil }

func newTestManager(fake *fakeSbomClient, version string) *SbomManager {
	return &SbomManager{
		cfg:           config.Config{NodeName: "node-1"},
		ctx:           context.Background(),
		processing:    mapset.NewSet[string](),
		storageClient: fake,
		scannerClient: &fakeScannerClient{err: errors.New("scan failed")},
		metrics:       metricsmanager.NewMetricsNoop(),
		version:       version,
	}
}

func testNotifAndImageStatus() (containercollection.PubSubEvent, *runtime.ImageStatusResponse, string, string) {
	imageTag := "quay.io/kubescape/kubevuln:v0.3.2"
	imageID := "sha256:94cbbb94f8d6bdf2529d5f9c5279ac4c7411182f4e8e5a3d0b5e8f10a465f73a"
	notif := containercollection.PubSubEvent{
		Container: &containercollection.Container{
			Runtime: containercollection.RuntimeMetadata{
				BasicRuntimeMetadata: types.BasicRuntimeMetadata{
					ContainerID:        "container-1",
					ContainerImageName: imageTag,
				},
			},
			K8s: containercollection.K8sMetadata{
				BasicK8sMetadata: types.BasicK8sMetadata{
					Namespace:     "default",
					PodName:       "pod-1",
					ContainerName: "container-1",
				},
			},
		},
	}
	imageStatus := &runtime.ImageStatusResponse{
		Image: &runtime.Image{
			Id:       "img-id",
			RepoTags: []string{imageTag},
		},
		Info: map[string]string{"info": `{"imageSpec":{}}`},
	}
	return notif, imageStatus, imageTag, imageID
}

// Test_processContainerWithMetadata_IncompleteReprocessing guards against the
// SBOM-generation-failure reprocessing loop: a generic failure must persist the SBOM
// as Incomplete so a later container start for the same image skips reprocessing at
// the same tool version, instead of retrying and re-failing indefinitely.
func Test_processContainerWithMetadata_IncompleteReprocessing(t *testing.T) {
	fake := newFakeSbomClient()
	mgr := newTestManager(fake, "v1.0.0")
	notif, imageStatus, imageTag, imageID := testNotifAndImageStatus()

	sbomName, err := names.ImageInfoToSlug(imageTag, imageID)
	assert.NoError(t, err)

	// First attempt: SBOM generation fails, must persist as Incomplete instead of
	// being left dangling in Initializing.
	mgr.processContainerWithMetadata(notif, nil, imageStatus, imageTag, imageID)

	stored, err := fake.GetSBOMMeta(sbomName)
	assert.NoError(t, err)
	assert.Equal(t, helpersv1.Incomplete, stored.Annotations[helpersv1.StatusMetadataKey])
	assert.Equal(t, "v1.0.0", stored.Annotations[helpersv1.ToolVersionMetadataKey])
	assert.Equal(t, 1, fake.replaceCalls)

	// Second attempt at the same tool version: this is the exact bug being fixed --
	// previously the SBOM stayed in Initializing/no-terminal-status and fell through
	// to the "processing was interrupted, retrying" default case on every container
	// start. It must now be skipped without touching storage again.
	mgr.processContainerWithMetadata(notif, nil, imageStatus, imageTag, imageID)
	assert.Equal(t, 1, fake.replaceCalls, "second attempt at the same tool version must not reprocess")

	// Third attempt with a different tool version: a fixed/updated node-agent build
	// must still retry previously-failed images, not pin them to Incomplete forever.
	mgr.version = "v2.0.0"
	mgr.processContainerWithMetadata(notif, nil, imageStatus, imageTag, imageID)
	assert.Equal(t, 2, fake.replaceCalls, "a different tool version must retry")

	stored, err = fake.GetSBOMMeta(sbomName)
	assert.NoError(t, err)
	assert.Equal(t, helpersv1.Incomplete, stored.Annotations[helpersv1.StatusMetadataKey])
	assert.Equal(t, "v2.0.0", stored.Annotations[helpersv1.ToolVersionMetadataKey])
}
