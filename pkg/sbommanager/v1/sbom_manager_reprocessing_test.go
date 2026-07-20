package v1

import (
	"context"
	"errors"
	"os"
	"path/filepath"
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
//
// GetSBOMMeta mirrors the real Storage.GetSBOMMeta contract (pkg/storage/v1/storage.go),
// which fetches with metav1.GetOptions{ResourceVersion: softwarecomposition.ResourceVersionMetadata}
// and therefore returns the object's metadata WITHOUT its Spec. Tests that rely on Spec
// being present on a GetSBOMMeta result would hide the exact bug this fake is meant to catch.
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
	s, ok := f.sboms[name]
	if !ok {
		return nil, k8serrors.NewNotFound(schema.GroupResource{Resource: "sbomsyfts"}, name)
	}
	meta := s.DeepCopy()
	meta.Spec = v1beta1.SBOMSyftSpec{} // metadata-only fetch: mirrors the real API server
	return meta, nil
}

func (f *fakeSbomClient) ReplaceSBOM(sbom *v1beta1.SBOMSyft) (*v1beta1.SBOMSyft, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.replaceCalls++
	f.sboms[sbom.Name] = sbom.DeepCopy()
	return sbom, nil
}

func (f *fakeSbomClient) get(name string) *v1beta1.SBOMSyft {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.sboms[name].DeepCopy()
}

// fakeScannerClient is a sbomscanner.SBOMScannerClient that always fails with a fixed error,
// used to deterministically drive processContainerWithMetadata into a specific failure branch
// without depending on real image/digest parsing.
type fakeScannerClient struct{ err error }

func (f *fakeScannerClient) CreateSBOM(_ context.Context, _ sbomscanner.ScanRequest) (*sbomscanner.ScanResult, error) {
	return nil, f.err
}
func (f *fakeScannerClient) Ready() bool  { return true }
func (f *fakeScannerClient) Close() error { return nil }

func newTestManager(fake *fakeSbomClient, version string) *SbomManager {
	return newTestManagerWithScannerErr(fake, version, errors.New("scan failed"))
}

func newTestManagerWithScannerErr(fake *fakeSbomClient, version string, scannerErr error) *SbomManager {
	return &SbomManager{
		cfg:            config.Config{NodeName: "node-1"},
		ctx:            context.Background(),
		processing:     mapset.NewSet[string](),
		storageClient:  fake,
		scannerClient:  &fakeScannerClient{err: scannerErr},
		metrics:        metricsmanager.NewMetricsNoop(),
		version:        version,
		scanRetries:    make(map[string]int),
		failureRetries: make(map[string]int),
	}
}

// newTestManagerInProcess builds a manager with no scanner sidecar configured, so
// processContainerWithMetadata takes the in-process (syftutil.NewSource) fallback path.
func newTestManagerInProcess(fake *fakeSbomClient, version string, maxImageSize int64) *SbomManager {
	return &SbomManager{
		cfg:            config.Config{NodeName: "node-1", MaxImageSize: maxImageSize},
		ctx:            context.Background(),
		processing:     mapset.NewSet[string](),
		storageClient:  fake,
		version:        version,
		scanRetries:    make(map[string]int),
		failureRetries: make(map[string]int),
	}
}

// testImageStatusWithLayer builds an ImageStatusResponse with one valid diff-id and a mount
// pointing to a real temp directory containing a file, so syftutil.toLayers computes a
// non-zero totalSize and NewSource can be driven into ErrImageTooLarge via a small MaxImageSize.
func testImageStatusWithLayer(t *testing.T, imageTag string) (*runtime.ImageStatusResponse, []string) {
	t.Helper()
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "layer.tar"), make([]byte, 1024), 0o644); err != nil {
		t.Fatalf("failed to write test layer file: %v", err)
	}
	imageStatus := &runtime.ImageStatusResponse{
		Image: &runtime.Image{
			Id:       "img-id",
			RepoTags: []string{imageTag},
		},
		Info: map[string]string{"info": `{"imageSpec":{"rootfs":{"type":"layers","diff_ids":["sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"]}}}`},
	}
	return imageStatus, []string{dir}
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
// SBOM-generation-failure reprocessing loop: a fresh reservation that keeps failing must
// only be pinned Incomplete after maxScanRetries consecutive failures (so a single transient
// error doesn't permanently lose SBOM coverage), after which a later container start at the
// same tool version must skip reprocessing instead of retrying and re-failing indefinitely.
func Test_processContainerWithMetadata_IncompleteReprocessing(t *testing.T) {
	fake := newFakeSbomClient()
	mgr := newTestManager(fake, "v1.0.0")
	notif, imageStatus, imageTag, imageID := testNotifAndImageStatus()

	sbomName, err := names.ImageInfoToSlug(imageTag, imageID)
	assert.NoError(t, err)

	// Failures below the retry threshold must not touch storage -- this is what makes
	// transient errors (a brief sidecar blip, a registry hiccup) self-healing.
	for range maxScanRetries - 1 {
		mgr.processContainerWithMetadata(notif, nil, imageStatus, imageTag, imageID)
	}
	assert.Equal(t, 0, fake.replaceCalls, "failures below the retry threshold must not mark Incomplete")
	assert.Equal(t, helpersv1.Initializing, fake.get(sbomName).Annotations[helpersv1.StatusMetadataKey])

	// The maxScanRetries-th consecutive failure must persist Incomplete.
	mgr.processContainerWithMetadata(notif, nil, imageStatus, imageTag, imageID)
	stored := fake.get(sbomName)
	assert.Equal(t, helpersv1.Incomplete, stored.Annotations[helpersv1.StatusMetadataKey])
	assert.Equal(t, "v1.0.0", stored.Annotations[helpersv1.ToolVersionMetadataKey])
	assert.Equal(t, 1, fake.replaceCalls)

	// A later attempt at the same tool version must be skipped without touching storage
	// again -- this is the exact bug being fixed: previously the SBOM stayed dangling with
	// no terminal status and was reprocessed on every container start forever.
	mgr.processContainerWithMetadata(notif, nil, imageStatus, imageTag, imageID)
	assert.Equal(t, 1, fake.replaceCalls, "the same tool version must not reprocess")

	// A different tool version must retry -- a fixed/updated node-agent build gets a fresh
	// maxScanRetries budget instead of being pinned to Incomplete forever.
	mgr.version = "v2.0.0"
	for range maxScanRetries - 1 {
		mgr.processContainerWithMetadata(notif, nil, imageStatus, imageTag, imageID)
	}
	assert.Equal(t, 1, fake.replaceCalls, "a version bump must not immediately re-pin Incomplete")
	mgr.processContainerWithMetadata(notif, nil, imageStatus, imageTag, imageID)
	assert.Equal(t, 2, fake.replaceCalls)

	stored = fake.get(sbomName)
	assert.Equal(t, helpersv1.Incomplete, stored.Annotations[helpersv1.StatusMetadataKey])
	assert.Equal(t, "v2.0.0", stored.Annotations[helpersv1.ToolVersionMetadataKey])
}

// Test_processContainerWithMetadata_PreservesContentOnReprocessFailure guards against
// silently wiping a previously-successful SBOM. GetSBOMMeta (used to fetch the SBOM on the
// reprocessing path, e.g. after a tool-version bump) returns metadata only, with no Spec --
// persisting that stripped object on a failed reprocess would destroy the existing, real SBOM
// content and permanently lose vulnerability-scan coverage for the image.
func Test_processContainerWithMetadata_PreservesContentOnReprocessFailure(t *testing.T) {
	fake := newFakeSbomClient()
	mgr := newTestManager(fake, "v2.0.0")
	notif, imageStatus, imageTag, imageID := testNotifAndImageStatus()

	sbomName, err := names.ImageInfoToSlug(imageTag, imageID)
	assert.NoError(t, err)

	// Seed a previously-successful SBOM, created by an older tool version, with real content.
	good := &v1beta1.SBOMSyft{}
	good.Name = sbomName
	good.Annotations = map[string]string{
		helpersv1.StatusMetadataKey:      helpersv1.Learning,
		helpersv1.ToolVersionMetadataKey: "v1.0.0",
	}
	good.Spec.Syft.Artifacts = make([]v1beta1.SyftPackage, 2)
	fake.sboms[sbomName] = good

	// A container start at the new version triggers reprocessing (version mismatch); the
	// scan then fails (mgr's scanner always errors). The stored SBOM's real content and
	// status must survive untouched -- reprocessing a content-bearing SBOM must never call
	// ReplaceSBOM on failure, regardless of the retry budget.
	for range maxScanRetries + 2 {
		mgr.processContainerWithMetadata(notif, nil, imageStatus, imageTag, imageID)
	}

	raw := fake.get(sbomName)
	assert.Len(t, raw.Spec.Syft.Artifacts, 2, "existing SBOM content must not be wiped by a failed reprocess")
	assert.Equal(t, helpersv1.Learning, raw.Annotations[helpersv1.StatusMetadataKey], "status must be left untouched on failure")
	// The stored object is never persisted on this path (see handleGenericFailure), so even
	// the tool-version bump that triggered the retry is not recorded -- only a successful
	// reprocess would update it. The image keeps retrying on every container start until
	// then, which is the accepted trade-off for never risking existing content.
	assert.Equal(t, "v1.0.0", raw.Annotations[helpersv1.ToolVersionMetadataKey], "storage is untouched, so the original recorded version is unchanged")
	assert.Equal(t, 0, fake.replaceCalls, "a failed reprocess of a content-bearing SBOM must never touch storage")
}

// Test_processContainerWithMetadata_PreservesContentOnScannerCrash is the handleScannerCrash
// counterpart to Test_processContainerWithMetadata_PreservesContentOnReprocessFailure: repeated
// sidecar OOM crashes while reprocessing a content-bearing SBOM must not clear its Spec and
// pin it to TooLarge, the same class of data loss as a generic scan/source/syft error.
func Test_processContainerWithMetadata_PreservesContentOnScannerCrash(t *testing.T) {
	fake := newFakeSbomClient()
	mgr := newTestManagerWithScannerErr(fake, "v2.0.0", sbomscanner.ErrScannerCrashed)
	notif, imageStatus, imageTag, imageID := testNotifAndImageStatus()

	sbomName, err := names.ImageInfoToSlug(imageTag, imageID)
	assert.NoError(t, err)

	good := &v1beta1.SBOMSyft{}
	good.Name = sbomName
	good.Annotations = map[string]string{
		helpersv1.StatusMetadataKey:      helpersv1.Learning,
		helpersv1.ToolVersionMetadataKey: "v1.0.0",
	}
	good.Spec.Syft.Artifacts = make([]v1beta1.SyftPackage, 2)
	fake.sboms[sbomName] = good

	// Each container start triggers reprocessing (version mismatch) and the sidecar
	// "crashes" (ErrScannerCrashed); handleScannerCrash's own maxScanRetries threshold would
	// normally pin the SBOM to TooLarge with an empty Spec after this many crashes.
	for range maxScanRetries + 2 {
		mgr.processContainerWithMetadata(notif, nil, imageStatus, imageTag, imageID)
	}

	raw := fake.get(sbomName)
	assert.Len(t, raw.Spec.Syft.Artifacts, 2, "existing SBOM content must not be wiped by a scanner crash loop")
	assert.Equal(t, helpersv1.Learning, raw.Annotations[helpersv1.StatusMetadataKey], "status must be left untouched on failure")
	assert.Equal(t, 0, fake.replaceCalls, "a scanner crash loop on a content-bearing SBOM must never touch storage")
}

// Test_processContainerWithMetadata_PreservesContentOnTooLarge is the ErrImageTooLarge
// counterpart to the other content-preservation tests: totalSize in syftutil.toLayers is
// computed from the currently-mounted layer paths, not a fixed property of the image, so a
// content-bearing SBOM being reprocessed can also hit ErrImageTooLarge and must not have its
// existing content wiped.
func Test_processContainerWithMetadata_PreservesContentOnTooLarge(t *testing.T) {
	fake := newFakeSbomClient()
	imageTag := "quay.io/kubescape/kubevuln:v0.3.2"
	imageID := "sha256:94cbbb94f8d6bdf2529d5f9c5279ac4c7411182f4e8e5a3d0b5e8f10a465f73a"
	imageStatus, mounts := testImageStatusWithLayer(t, imageTag)
	// MaxImageSize (1 byte) smaller than the seeded layer file guarantees NewSource returns
	// ErrImageTooLarge.
	mgr := newTestManagerInProcess(fake, "v2.0.0", 1)
	notif, _, _, _ := testNotifAndImageStatus()

	sbomName, err := names.ImageInfoToSlug(imageTag, imageID)
	assert.NoError(t, err)

	good := &v1beta1.SBOMSyft{}
	good.Name = sbomName
	good.Annotations = map[string]string{
		helpersv1.StatusMetadataKey:      helpersv1.Learning,
		helpersv1.ToolVersionMetadataKey: "v1.0.0",
	}
	good.Spec.Syft.Artifacts = make([]v1beta1.SyftPackage, 2)
	fake.sboms[sbomName] = good

	mgr.processContainerWithMetadata(notif, mounts, imageStatus, imageTag, imageID)

	raw := fake.get(sbomName)
	assert.Len(t, raw.Spec.Syft.Artifacts, 2, "existing SBOM content must not be wiped by an ErrImageTooLarge reprocess")
	assert.Equal(t, helpersv1.Learning, raw.Annotations[helpersv1.StatusMetadataKey], "status must be left untouched on failure")
	assert.Equal(t, 0, fake.replaceCalls, "an ErrImageTooLarge reprocess of a content-bearing SBOM must never touch storage")
}
