package v1

import (
	"context"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"sync"
	"testing"
	"time"

	mapset "github.com/deckarep/golang-set/v2"
	"github.com/hashicorp/golang-lru/v2/expirable"
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
//
// PatchSBOMAnnotations mirrors the real Storage.PatchSBOMAnnotations contract: it only ever
// modifies the stored object's Annotations map (nil value deletes the key), never its Spec.
type fakeSbomClient struct {
	mu           sync.Mutex
	sboms        map[string]*v1beta1.SBOMSyft
	replaceCalls int
	patchCalls   int
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

func (f *fakeSbomClient) PatchSBOMAnnotations(name string, annotations map[string]any) (*v1beta1.SBOMSyft, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.patchCalls++
	s, ok := f.sboms[name]
	if !ok {
		return nil, k8serrors.NewNotFound(schema.GroupResource{Resource: "sbomsyfts"}, name)
	}
	if s.Annotations == nil {
		s.Annotations = map[string]string{}
	}
	for k, v := range annotations {
		if v == nil {
			delete(s.Annotations, k)
			continue
		}
		s.Annotations[k] = fmt.Sprintf("%v", v)
	}
	return s.DeepCopy(), nil
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

func newFailureRetries() *expirable.LRU[string, int] {
	return expirable.NewLRU[string, int](maxFailureRetryEntries, nil, failureRetryTTL)
}

func newCrashLoopRetries() *expirable.LRU[string, int] {
	return expirable.NewLRU[string, int](maxFailureRetryEntries, nil, crashLoopRetryTTL)
}

func newTestManager(fake *fakeSbomClient, version string) *SbomManager {
	return newTestManagerWithScannerErr(fake, version, errors.New("scan failed"))
}

func newTestManagerWithScannerErr(fake *fakeSbomClient, version string, scannerErr error) *SbomManager {
	return &SbomManager{
		cfg:              config.Config{NodeName: "node-1"},
		ctx:              context.Background(),
		processing:       mapset.NewSet[string](),
		storageClient:    fake,
		scannerClient:    &fakeScannerClient{err: scannerErr},
		metrics:          metricsmanager.NewMetricsNoop(),
		version:          version,
		failureRetries:   newFailureRetries(),
		crashLoopRetries: newCrashLoopRetries(),
	}
}

// newTestManagerInProcess builds a manager with no scanner sidecar configured, so
// processContainerWithMetadata takes the in-process (syftutil.NewSource) fallback path.
func newTestManagerInProcess(fake *fakeSbomClient, version string, maxImageSize int64) *SbomManager {
	return &SbomManager{
		cfg:              config.Config{NodeName: "node-1", MaxImageSize: maxImageSize},
		ctx:              context.Background(),
		processing:       mapset.NewSet[string](),
		storageClient:    fake,
		version:          version,
		failureRetries:   newFailureRetries(),
		crashLoopRetries: newCrashLoopRetries(),
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
// Marking must go through PatchSBOMAnnotations (annotations only), never a full ReplaceSBOM.
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
	assert.Equal(t, 0, fake.patchCalls, "failures below the retry threshold must not mark Incomplete")
	assert.Equal(t, helpersv1.Initializing, fake.get(sbomName).Annotations[helpersv1.StatusMetadataKey])

	// The maxScanRetries-th consecutive failure must persist Incomplete via a patch.
	mgr.processContainerWithMetadata(notif, nil, imageStatus, imageTag, imageID)
	stored := fake.get(sbomName)
	assert.Equal(t, helpersv1.Incomplete, stored.Annotations[helpersv1.StatusMetadataKey])
	assert.Equal(t, "v1.0.0", stored.Annotations[helpersv1.ToolVersionMetadataKey])
	assert.Equal(t, 1, fake.patchCalls)
	assert.Equal(t, 0, fake.replaceCalls, "failure marking must never use a full ReplaceSBOM")

	// A later attempt at the same tool version must be skipped without touching storage
	// again -- this is the exact bug being fixed: previously the SBOM stayed dangling with
	// no terminal status and was reprocessed on every container start forever.
	mgr.processContainerWithMetadata(notif, nil, imageStatus, imageTag, imageID)
	assert.Equal(t, 1, fake.patchCalls, "the same tool version must not reprocess")

	// A different tool version must retry -- a fixed/updated node-agent build gets a fresh
	// maxScanRetries budget instead of being pinned to Incomplete forever.
	mgr.version = "v2.0.0"
	for range maxScanRetries - 1 {
		mgr.processContainerWithMetadata(notif, nil, imageStatus, imageTag, imageID)
	}
	assert.Equal(t, 1, fake.patchCalls, "a version bump must not immediately re-pin Incomplete")
	mgr.processContainerWithMetadata(notif, nil, imageStatus, imageTag, imageID)
	assert.Equal(t, 2, fake.patchCalls)

	stored = fake.get(sbomName)
	assert.Equal(t, helpersv1.Incomplete, stored.Annotations[helpersv1.StatusMetadataKey])
	assert.Equal(t, "v2.0.0", stored.Annotations[helpersv1.ToolVersionMetadataKey])
}

// Test_processContainerWithMetadata_PreservesContentOnReprocessFailure guards against
// silently wiping a previously-successful SBOM. GetSBOMMeta (used to fetch the SBOM on the
// reprocessing path, e.g. after a tool-version bump) returns metadata only, with no Spec.
// Marking a repeatedly-failing content-bearing SBOM Incomplete must go through
// PatchSBOMAnnotations, which never sends Spec, so the existing artifacts survive even though
// the status/tool-version annotations do get updated once the retry budget is exhausted.
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

	// A container start at the new version triggers reprocessing (version mismatch); the scan
	// then fails (mgr's scanner always errors) on every subsequent attempt. Once the retry
	// budget is exhausted the SBOM is pinned Incomplete, and further attempts at that recorded
	// version are skipped -- but the artifacts must survive throughout, since marking never
	// uses a full ReplaceSBOM.
	for range maxScanRetries + 2 {
		mgr.processContainerWithMetadata(notif, nil, imageStatus, imageTag, imageID)
	}

	raw := fake.get(sbomName)
	assert.Len(t, raw.Spec.Syft.Artifacts, 2, "existing SBOM content must survive an annotation-only status update")
	assert.Equal(t, helpersv1.Incomplete, raw.Annotations[helpersv1.StatusMetadataKey])
	assert.Equal(t, "v2.0.0", raw.Annotations[helpersv1.ToolVersionMetadataKey])
	assert.Equal(t, 1, fake.patchCalls, "only the maxScanRetries-th consecutive failure marks Incomplete; later attempts must skip")
	assert.Equal(t, 0, fake.replaceCalls, "failure marking must never use a full ReplaceSBOM")
}

// Test_processContainerWithMetadata_PreservesContentOnScannerCrash is the handleScannerCrash
// counterpart to Test_processContainerWithMetadata_PreservesContentOnReprocessFailure. TooLarge
// is a one-way door in the storage layer (all future writes to a TooLarge object are silently
// dropped server-side), so repeated sidecar OOM crashes while reprocessing a content-bearing
// SBOM must pin it to Incomplete (safely retryable) instead of TooLarge, via an annotation-only
// patch that never touches its Spec.
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
	// "crashes" (ErrScannerCrashed); handleScannerCrash's own maxScanRetries threshold pins
	// the SBOM to Incomplete once exhausted, after which further attempts are skipped.
	for range maxScanRetries + 2 {
		mgr.processContainerWithMetadata(notif, nil, imageStatus, imageTag, imageID)
	}

	raw := fake.get(sbomName)
	assert.Len(t, raw.Spec.Syft.Artifacts, 2, "existing SBOM content must survive an annotation-only status update")
	assert.Equal(t, helpersv1.Incomplete, raw.Annotations[helpersv1.StatusMetadataKey], "content-bearing SBOMs must never be pinned TooLarge, a storage-layer one-way door")
	assert.Equal(t, 1, fake.patchCalls, "only the maxScanRetries-th consecutive crash marks Incomplete; later attempts must skip")
	assert.Equal(t, 0, fake.replaceCalls, "scanner-crash marking must never use a full ReplaceSBOM")
}

// alternatingScannerClient is a sbomscanner.SBOMScannerClient that alternates its returned
// error between a generic error and sbomscanner.ErrScannerCrashed on successive CreateSBOM
// calls (even calls -> generic error, odd calls -> scanner crash). It lets a test drive
// processContainerWithMetadata through mixed failure categories in a deterministic order.
type alternatingScannerClient struct {
	calls int
}

func (a *alternatingScannerClient) CreateSBOM(_ context.Context, _ sbomscanner.ScanRequest) (*sbomscanner.ScanResult, error) {
	a.calls++
	if a.calls%2 == 0 {
		return nil, errors.New("scan failed")
	}
	return nil, sbomscanner.ErrScannerCrashed
}
func (a *alternatingScannerClient) Ready() bool  { return true }
func (a *alternatingScannerClient) Close() error { return nil }

// Test_processContainerWithMetadata_MixedFailureCategoriesShareBudget is the regression test for
// issue #856. Before the fix, generic failures and scanner crashes each had an independent
// counter compared against maxScanRetries, so an image alternating between the two categories
// could take up to 5-6 attempts before reaching a terminal status. With the counters unified
// onto a single shared budget (incrementFailureCount), the SBOM must be pinned at exactly the
// 3rd COMBINED attempt across mixed failure categories.
func Test_processContainerWithMetadata_MixedFailureCategoriesShareBudget(t *testing.T) {
	fake := newFakeSbomClient()
	imageTag := "quay.io/kubescape/kubevuln:v0.3.2"
	imageID := "sha256:94cbbb94f8d6bdf2529d5f9c5279ac4c7411182f4e8e5a3d0b5e8f10a465f73a"

	sbomName, err := names.ImageInfoToSlug(imageTag, imageID)
	assert.NoError(t, err)

	// Seed a previously-successful, content-bearing SBOM created by an older tool version so
	// every call triggers reprocessing (version mismatch).
	good := &v1beta1.SBOMSyft{}
	good.Name = sbomName
	good.Annotations = map[string]string{
		helpersv1.StatusMetadataKey:      helpersv1.Learning,
		helpersv1.ToolVersionMetadataKey: "v1.0.0",
	}
	good.Spec.Syft.Artifacts = make([]v1beta1.SyftPackage, 2)
	fake.sboms[sbomName] = good

	mgr := &SbomManager{
		cfg:              config.Config{NodeName: "node-1"},
		ctx:              context.Background(),
		processing:       mapset.NewSet[string](),
		storageClient:    fake,
		scannerClient:    &alternatingScannerClient{},
		metrics:          metricsmanager.NewMetricsNoop(),
		version:          "v2.0.0",
		failureRetries:   newFailureRetries(),
		crashLoopRetries: newCrashLoopRetries(),
	}

	notif, imageStatus, imageTag, imageID := testNotifAndImageStatus()

	// The first two mixed-category failures must stay below the shared threshold and never
	// touch storage.
	mgr.processContainerWithMetadata(notif, nil, imageStatus, imageTag, imageID)
	mgr.processContainerWithMetadata(notif, nil, imageStatus, imageTag, imageID)
	assert.Equal(t, 0, fake.patchCalls, "the first two combined failures must not mark a terminal status")

	// The 3rd combined attempt crosses the shared budget and pins the SBOM Incomplete -- proving
	// the counters are unified, not independent (which would have needed up to 5-6 attempts).
	mgr.processContainerWithMetadata(notif, nil, imageStatus, imageTag, imageID)
	assert.Equal(t, 1, fake.patchCalls, "the 3rd combined failure must pin the SBOM at the shared threshold")
	assert.Equal(t, 0, fake.replaceCalls, "failure marking must never use a full ReplaceSBOM")

	raw := fake.get(sbomName)
	assert.Equal(t, helpersv1.Incomplete, raw.Annotations[helpersv1.StatusMetadataKey])
	assert.Len(t, raw.Spec.Syft.Artifacts, 2, "existing SBOM content must survive an annotation-only status update")
}

// Test_processContainerWithMetadata_PreservesContentOnTooLarge is the ErrImageTooLarge
// counterpart to the other content-preservation tests: totalSize in syftutil.toLayers is
// computed from the currently-mounted layer paths, not a fixed property of the image, so a
// content-bearing SBOM being reprocessed can also hit ErrImageTooLarge. TooLarge is a one-way
// door in the storage layer, so a content-bearing SBOM must never be pinned to it -- instead
// this is treated as a generic (retryable, eventually Incomplete) failure, same as any other
// generic error, and always through PatchSBOMAnnotations so existing content is never wiped.
func Test_processContainerWithMetadata_PreservesContentOnTooLarge(t *testing.T) {
	fake := newFakeSbomClient()
	imageTag := "quay.io/kubescape/kubevuln:v0.3.2"
	imageID := "sha256:94cbbb94f8d6bdf2529d5f9c5279ac4c7411182f4e8e5a3d0b5e8f10a465f73a"
	imageStatus, mounts := testImageStatusWithLayer(t, imageTag)
	// MaxImageSize (1 byte) smaller than the seeded layer file guarantees NewSource returns
	// ErrImageTooLarge on every attempt.
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

	for range maxScanRetries + 2 {
		mgr.processContainerWithMetadata(notif, mounts, imageStatus, imageTag, imageID)
	}

	raw := fake.get(sbomName)
	assert.Len(t, raw.Spec.Syft.Artifacts, 2, "existing SBOM content must survive an annotation-only status update")
	assert.Equal(t, helpersv1.Incomplete, raw.Annotations[helpersv1.StatusMetadataKey], "content-bearing SBOMs must never be pinned TooLarge, a storage-layer one-way door")
	assert.Equal(t, 1, fake.patchCalls, "only the maxScanRetries-th consecutive failure marks Incomplete; later attempts must skip")
	assert.Equal(t, 0, fake.replaceCalls, "ErrImageTooLarge marking must never use a full ReplaceSBOM")
}

// Test_processContainerWithMetadata_MarksFreshImageTooLargeImmediately guards the unchanged
// half of the ErrImageTooLarge behavior: an image with no prior content (a fresh reservation)
// is still marked TooLarge immediately, with no retry budget -- TooLarge's storage-layer
// one-way door is only a problem when it freezes real content, which a content-free SBOM
// never had to begin with.
func Test_processContainerWithMetadata_MarksFreshImageTooLargeImmediately(t *testing.T) {
	fake := newFakeSbomClient()
	imageTag := "quay.io/kubescape/kubevuln:v0.3.2"
	imageStatus, mounts := testImageStatusWithLayer(t, imageTag)
	mgr := newTestManagerInProcess(fake, "v2.0.0", 1)
	notif, _, _, imageID := testNotifAndImageStatus()

	sbomName, err := names.ImageInfoToSlug(imageTag, imageID)
	assert.NoError(t, err)

	mgr.processContainerWithMetadata(notif, mounts, imageStatus, imageTag, imageID)

	stored := fake.get(sbomName)
	assert.Equal(t, helpersv1.TooLarge, stored.Annotations[helpersv1.StatusMetadataKey])
	assert.Equal(t, 1, fake.patchCalls, "a fresh reservation must mark TooLarge on the first occurrence, with no retry budget")
}

// genericThenCrashScannerClient returns a generic error on its first two calls, then
// sbomscanner.ErrScannerCrashed on the third -- used to reproduce the exact mixed-failure
// sequence from the review finding on PR #857 (2 generic failures + 1 crash).
type genericThenCrashScannerClient struct{ calls int }

func (a *genericThenCrashScannerClient) CreateSBOM(_ context.Context, _ sbomscanner.ScanRequest) (*sbomscanner.ScanResult, error) {
	a.calls++
	if a.calls < 3 {
		return nil, errors.New("scan failed")
	}
	return nil, sbomscanner.ErrScannerCrashed
}
func (a *genericThenCrashScannerClient) Ready() bool  { return true }
func (a *genericThenCrashScannerClient) Close() error { return nil }

// Test_processContainerWithMetadata_MixedFailureCategoriesPinIncomplete is the regression test
// for the review blocker on PR #857: a contentless image (hadContent == false, no prior
// successful scan) that reaches the shared threshold via two generic failures plus a single
// scanner crash must be pinned Incomplete, not TooLarge -- TooLarge is only reachable when
// crashLoopRetries' crash-only backstop itself crosses the threshold, which one crash does not.
func Test_processContainerWithMetadata_MixedFailureCategoriesPinIncomplete(t *testing.T) {
	fake := newFakeSbomClient()
	notif, imageStatus, imageTag, imageID := testNotifAndImageStatus()
	sbomName, err := names.ImageInfoToSlug(imageTag, imageID)
	assert.NoError(t, err)

	mgr := &SbomManager{
		cfg:              config.Config{NodeName: "node-1"},
		ctx:              context.Background(),
		processing:       mapset.NewSet[string](),
		storageClient:    fake,
		scannerClient:    &genericThenCrashScannerClient{},
		metrics:          metricsmanager.NewMetricsNoop(),
		version:          "v2.0.0",
		scannerMemLimit:  1024,
		failureRetries:   newFailureRetries(),
		crashLoopRetries: newCrashLoopRetries(),
	}

	for range 3 {
		mgr.processContainerWithMetadata(notif, nil, imageStatus, imageTag, imageID)
	}

	raw := fake.get(sbomName)
	assert.Equal(t, helpersv1.Incomplete, raw.Annotations[helpersv1.StatusMetadataKey], "a mix of generic failures and a single crash must never be classified TooLarge")
	_, hasMemLimitAnnotation := raw.Annotations[ScannerMemoryLimitAnnotation]
	assert.False(t, hasMemLimitAnnotation, "the TooLarge-only memory-limit annotation must not be set on an Incomplete pin")
}

// Test_processContainerWithMetadata_MarksContentlessImageTooLargeOnPureCrashLoop guards the
// still-supported TooLarge path: a contentless image (no prior successful scan) that crashes the
// scanner sidecar 3 consecutive times with no interleaved generic failures must still be pinned
// TooLarge, with the scanner memory limit recorded -- this is the signal crashLoopRetries exists
// to preserve.
func Test_processContainerWithMetadata_MarksContentlessImageTooLargeOnPureCrashLoop(t *testing.T) {
	fake := newFakeSbomClient()
	notif, imageStatus, imageTag, imageID := testNotifAndImageStatus()
	sbomName, err := names.ImageInfoToSlug(imageTag, imageID)
	assert.NoError(t, err)

	mgr := &SbomManager{
		cfg:              config.Config{NodeName: "node-1"},
		ctx:              context.Background(),
		processing:       mapset.NewSet[string](),
		storageClient:    fake,
		scannerClient:    &fakeScannerClient{err: sbomscanner.ErrScannerCrashed},
		metrics:          metricsmanager.NewMetricsNoop(),
		version:          "v2.0.0",
		scannerMemLimit:  2048,
		failureRetries:   newFailureRetries(),
		crashLoopRetries: newCrashLoopRetries(),
	}

	for range 3 {
		mgr.processContainerWithMetadata(notif, nil, imageStatus, imageTag, imageID)
	}

	raw := fake.get(sbomName)
	assert.Equal(t, helpersv1.TooLarge, raw.Annotations[helpersv1.StatusMetadataKey])
	assert.Equal(t, "2048", raw.Annotations[ScannerMemoryLimitAnnotation])
}

// Test_processContainerWithMetadata_CrashLoopBackstopSurvivesSparseCadence is the regression test
// for review finding #2 on PR #857: a chronically-crashing image whose restarts are spaced wider
// apart than failureRetryTTL must still eventually be pinned, via crashLoopRetries' longer TTL,
// even though the shared failureRetries budget keeps expiring and never itself reaches
// maxScanRetries. A short-TTL failureRetries and a longer-but-still-short crashLoopRetries are
// constructed directly (rather than via the production TTL constants) so the test can force real
// expiry with millisecond-scale sleeps instead of waiting on failureRetryTTL/crashLoopRetryTTL.
func Test_processContainerWithMetadata_CrashLoopBackstopSurvivesSparseCadence(t *testing.T) {
	fake := newFakeSbomClient()
	notif, imageStatus, imageTag, imageID := testNotifAndImageStatus()
	sbomName, err := names.ImageInfoToSlug(imageTag, imageID)
	assert.NoError(t, err)

	mgr := &SbomManager{
		cfg:              config.Config{NodeName: "node-1"},
		ctx:              context.Background(),
		processing:       mapset.NewSet[string](),
		storageClient:    fake,
		scannerClient:    &fakeScannerClient{err: sbomscanner.ErrScannerCrashed},
		metrics:          metricsmanager.NewMetricsNoop(),
		version:          "v2.0.0",
		scannerMemLimit:  4096,
		failureRetries:   expirable.NewLRU[string, int](maxFailureRetryEntries, nil, 5*time.Millisecond),
		crashLoopRetries: expirable.NewLRU[string, int](maxFailureRetryEntries, nil, 500*time.Millisecond),
	}

	for i := range 3 {
		mgr.processContainerWithMetadata(notif, nil, imageStatus, imageTag, imageID)
		if i < 2 {
			time.Sleep(20 * time.Millisecond) // exceeds the 5ms failureRetries TTL, well inside the 500ms crashLoopRetries TTL
		}
	}

	raw := fake.get(sbomName)
	assert.Equal(t, helpersv1.TooLarge, raw.Annotations[helpersv1.StatusMetadataKey], "the crash-only backstop must still pin TooLarge even though the shared budget kept expiring between crashes")
	assert.Equal(t, "4096", raw.Annotations[ScannerMemoryLimitAnnotation])
}
