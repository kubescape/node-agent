package v1

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/anchore/syft/syft"
	"github.com/anchore/syft/syft/sbom"
	"github.com/anchore/syft/syft/source"
	"github.com/armosec/armoapi-go/scanfailure"
	mapset "github.com/deckarep/golang-set/v2"
	helpersv1 "github.com/kubescape/k8s-interface/instanceidhandler/v1/helpers"
	"github.com/kubescape/node-agent/pkg/config"
	"github.com/kubescape/node-agent/pkg/metricsmanager"
	"github.com/kubescape/storage/pkg/apis/softwarecomposition/v1beta1"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	_ "modernc.org/sqlite" // required by syft's RPM cataloger, mirrors sbom_manager.go
)

// recordingFailureReporter records every kubevuln failure report submitted.
type recordingFailureReporter struct {
	mu      sync.Mutex
	reports []scanfailure.ScanFailureReport
}

func (r *recordingFailureReporter) ReportSbomFailure(_ context.Context, report scanfailure.ScanFailureReport) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.reports = append(r.reports, report)
	return nil
}

func (r *recordingFailureReporter) count() int {
	r.mu.Lock()
	defer r.mu.Unlock()
	return len(r.reports)
}

// newHostSbomManager builds a manager wired for host-branch tests: real storage
// fake, no scanner sidecar (the sidecar's ScanRequest is image-shaped and the
// host never uses it), and a host filesystem prefix pointing at hostRoot.
func newHostSbomManager(t *testing.T, cfg config.Config, hostRoot string) (*SbomManager, *fakeSbomClient, *recordingFailureReporter) {
	t.Helper()
	store := newFakeSbomClient()
	reporter := &recordingFailureReporter{}
	return &SbomManager{
		ctx:              t.Context(),
		cfg:              cfg,
		storageClient:    store,
		k8sObjectCache:   &sharedDataSpy{},
		processing:       mapset.NewSet[string](),
		waitCancels:      map[string]context.CancelFunc{},
		failureRetries:   newFailureRetries(),
		crashLoopRetries: newFailureRetries(),
		metrics:          &metricsmanager.MetricsNoop{},
		failureReporter:  reporter,
		hostFSPrefix:     hostRoot,
		version:          "v1.0.0",
	}, store, reporter
}

// tinyHostRoot is a minimal but non-empty fake host filesystem, small enough
// that a real Syft scan over it finishes in well under a second.
func tinyHostRoot(t *testing.T) string {
	t.Helper()
	root := t.TempDir()
	distInfo := filepath.Join(root, "usr/lib/python3/dist-packages/hostpkg-1.0.dist-info")
	require.NoError(t, os.MkdirAll(distInfo, 0o755))
	require.NoError(t, os.WriteFile(filepath.Join(distInfo, "METADATA"),
		[]byte("Metadata-Version: 2.1\nName: hostpkg\nVersion: 1.0\n"), 0o644))
	require.NoError(t, os.WriteFile(filepath.Join(distInfo, "RECORD"), nil, 0o644))
	return root
}

func hostCfg(nodeName string) config.Config {
	return config.Config{
		HostMonitoringEnabled: true,
		NodeName:              nodeName,
		MaxSBOMSize:           20 * 1024 * 1024,
	}
}

// Test_ContainerCallback_HostTakesSeparateBranch proves the host early-return
// was replaced by a genuinely separate branch: the host scan starts, while none
// of the image/mount-driven machinery (shared-data wait, image status, mounted
// volumes) is touched. imageServiceClient and appFs are deliberately nil here --
// if the host ever fell through to the container path, this test panics.
func Test_ContainerCallback_HostTakesSeparateBranch(t *testing.T) {
	sm, _, _ := newHostSbomManager(t, hostCfg("node-1"), t.TempDir())
	spy := sm.k8sObjectCache.(*sharedDataSpy)

	scanned := make(chan string, 4)
	sm.hostScanFn = func(hostID string) { scanned <- hostID }

	sm.ContainerCallback(hostAddNotif())

	select {
	case hostID := <-scanned:
		assert.Equal(t, "node-1", hostID, "host scan must be keyed by the host identity")
	case <-time.After(2 * time.Second):
		t.Fatal("host scan was never started")
	}
	assert.Zero(t, spy.reads, "host must never read shared container data")
}

// Test_ContainerCallback_HostSkippedWhenMonitoringDisabled keeps the branch
// gated on the same flag that creates the host pseudo-container in the first
// place.
func Test_ContainerCallback_HostSkippedWhenMonitoringDisabled(t *testing.T) {
	cfg := hostCfg("node-1")
	cfg.HostMonitoringEnabled = false
	sm, _, _ := newHostSbomManager(t, cfg, t.TempDir())

	var calls atomic.Int32
	sm.hostScanFn = func(string) { calls.Add(1) }

	sm.ContainerCallback(hostAddNotif())
	time.Sleep(100 * time.Millisecond)

	assert.Zero(t, calls.Load())
}

// Test_StartHostSbomLifecycle_StartsOnce proves a replayed host add-container
// notification cannot start a second rescan loop.
func Test_StartHostSbomLifecycle_StartsOnce(t *testing.T) {
	cfg := hostCfg("node-1")
	cfg.HostSBOMRescanInterval = time.Hour // no tick within the test window
	sm, _, _ := newHostSbomManager(t, cfg, t.TempDir())

	var calls atomic.Int32
	sm.hostScanFn = func(string) { calls.Add(1) }

	for range 5 {
		sm.ContainerCallback(hostAddNotif())
	}
	time.Sleep(200 * time.Millisecond)

	assert.Equal(t, int32(1), calls.Load(), "the host lifecycle must start exactly once")
}

// Test_HostSbomLoop_RescanTickerFires is the injectable-interval proof:
// with a 10ms interval, the rescan must actually happen repeatedly
// within a bounded test window. A test asserting only that the config field
// exists and is read once would pass even if the ticker were never wired.
func Test_HostSbomLoop_RescanTickerFires(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	cfg := hostCfg("node-1")
	cfg.HostSBOMRescanInterval = 10 * time.Millisecond
	sm, _, _ := newHostSbomManager(t, cfg, t.TempDir())
	sm.ctx = ctx

	var calls atomic.Int32
	sm.hostScanFn = func(string) { calls.Add(1) }

	go sm.hostSbomLoop("node-1")

	assert.Eventually(t, func() bool { return calls.Load() >= 3 }, 2*time.Second, 5*time.Millisecond,
		"the rescan ticker must fire repeatedly (1 initial scan + at least 2 rescans)")

	cancel()
	settled := calls.Load()
	time.Sleep(100 * time.Millisecond)
	assert.LessOrEqual(t, calls.Load(), settled+1, "the rescan loop must stop when the manager context is cancelled")
}

// Test_HostSbomLoop_RescanDisabledStaysOneShot covers the <= 0 interval case.
func Test_HostSbomLoop_RescanDisabledStaysOneShot(t *testing.T) {
	cfg := hostCfg("node-1")
	cfg.HostSBOMRescanInterval = 0
	sm, _, _ := newHostSbomManager(t, cfg, t.TempDir())

	var calls atomic.Int32
	sm.hostScanFn = func(string) { calls.Add(1) }

	sm.hostSbomLoop("node-1") // returns rather than blocking
	time.Sleep(100 * time.Millisecond)

	assert.Equal(t, int32(1), calls.Load())
}

// Test_ProcessHostSbom_ProducesHostNamedCR runs the real host branch end to end
// over a tiny fake host root and asserts the CR is host-identity-named and
// carries no image-derived annotations.
func Test_ProcessHostSbom_ProducesHostNamedCR(t *testing.T) {
	sm, store, reporter := newHostSbomManager(t, hostCfg("node-1"), tinyHostRoot(t))

	sm.processHostSbom("node-1")

	sbom := store.get("host-node-1")
	require.NotNil(t, sbom, "host SBOM must be named from the host identity, not from an image")
	assert.Equal(t, helpersv1.Learning, sbom.Annotations[helpersv1.StatusMetadataKey])
	assert.NotEmpty(t, sbom.Spec.Syft.Artifacts, "the host scan must have catalogued the fixture package")
	assert.NotContains(t, sbom.Annotations, helpersv1.ImageIDMetadataKey)
	assert.NotContains(t, sbom.Annotations, helpersv1.ImageTagMetadataKey)
	assert.Equal(t, "node-1", sbom.Labels[HostSbomNameLabelKey])
	assert.Zero(t, reporter.count(), "the host path must not report to the image-keyed failure endpoint")
	assert.Zero(t, sm.processing.Cardinality(), "the processing slot must be released")
}

// Test_ProcessHostSbom_NeverReportsFailure locks in the explicit decision that
// the kubevuln failure-reporting path -- which is keyed by image tag/digest and
// a pod workload identifier the host does not have -- is omitted for the host.
// The scan is forced to fail by pointing the host prefix at a path that is not
// a directory, which is also the nil-image-reference panic scenario.
func Test_ProcessHostSbom_NeverReportsFailure(t *testing.T) {
	notADir := filepath.Join(t.TempDir(), "file")
	require.NoError(t, os.WriteFile(notADir, []byte("x"), 0o644))

	sm, store, reporter := newHostSbomManager(t, hostCfg("node-1"), notADir)

	assert.NotPanics(t, func() { sm.processHostSbom("node-1") })

	assert.Zero(t, reporter.count(), "host failures must not be sent to the image-keyed endpoint")
	sbom := store.get("host-node-1")
	require.NotNil(t, sbom)
	assert.Equal(t, helpersv1.Initializing, sbom.Annotations[helpersv1.StatusMetadataKey],
		"a single failure must not pin the host SBOM")
}

// Test_HostSbomName_IsIdentityDerived pins the naming scheme.
func Test_HostSbomName_IsIdentityDerived(t *testing.T) {
	assert.Equal(t, "host-node-1", hostSbomName("node-1"))
	assert.Equal(t, "host-ip-10-0-1-5-eu-west-1-compute-internal",
		hostSbomName("ip-10-0-1-5.eu-west-1.compute.internal"))
}

// --- TooLarge interaction -------------------------------------------------

// seedHostSbom puts an existing host SBOM into the fake store with the given
// status/annotations, so prepareHostSbom takes its AlreadyExists path.
func seedHostSbom(t *testing.T, store *fakeSbomClient, annotations map[string]string) {
	t.Helper()
	_, err := store.CreateSBOM(&v1beta1.SBOMSyft{Name: "host-node-1", Annotations: annotations})
	require.NoError(t, err)
}

// Test_PrepareHostSbom_TooLargeBlocksThisRescanOnly is the explicit
// decision test for oversized-SBOM handling.
//
// Decision: a TooLarge trip does NOT permanently stop the rescan ticker, but it
// DOES make each rescan return without scanning while the conditions that
// produced it hold. It is released by a Syft tool-version bump or a scanner
// memory-limit change -- the same two escape hatches the container path honours.
// Rescanning unconditionally would be pointless work: TooLarge is a one-way door
// in the storage layer, so the resulting write would be silently dropped.
func Test_PrepareHostSbom_TooLargeBlocksThisRescanOnly(t *testing.T) {
	t.Run("same version and limit: rescan skipped", func(t *testing.T) {
		sm, store, _ := newHostSbomManager(t, hostCfg("node-1"), t.TempDir())
		seedHostSbom(t, store, map[string]string{
			helpersv1.StatusMetadataKey:      helpersv1.TooLarge,
			helpersv1.ToolVersionMetadataKey: sm.version,
			ScannerMemoryLimitAnnotation:     "0",
		})

		_, _, ok := sm.prepareHostSbom("host-node-1", "node-1")
		assert.False(t, ok, "a TooLarge host SBOM must not be rescanned under unchanged conditions")
	})

	t.Run("tool version bumped: rescan proceeds", func(t *testing.T) {
		sm, store, _ := newHostSbomManager(t, hostCfg("node-1"), t.TempDir())
		seedHostSbom(t, store, map[string]string{
			helpersv1.StatusMetadataKey:      helpersv1.TooLarge,
			helpersv1.ToolVersionMetadataKey: "v0.9.0-old",
		})

		wip, hadContent, ok := sm.prepareHostSbom("host-node-1", "node-1")
		require.True(t, ok, "a tool-version bump must release the TooLarge block")
		assert.False(t, hadContent, "a TooLarge SBOM has had its spec cleared, so it carries no content")
		assert.Equal(t, sm.version, wip.Annotations[helpersv1.ToolVersionMetadataKey])
	})

	t.Run("scanner memory limit changed: rescan proceeds", func(t *testing.T) {
		sm, store, _ := newHostSbomManager(t, hostCfg("node-1"), t.TempDir())
		sm.scannerMemLimit = 2048
		seedHostSbom(t, store, map[string]string{
			helpersv1.StatusMetadataKey:      helpersv1.TooLarge,
			helpersv1.ToolVersionMetadataKey: sm.version,
			ScannerMemoryLimitAnnotation:     "1024",
		})

		_, _, ok := sm.prepareHostSbom("host-node-1", "node-1")
		assert.True(t, ok, "a scanner memory-limit change must release the TooLarge block")
	})
}

// Test_PrepareHostSbom_NilAnnotationsDoNotPanic proves that an existing host
// SBOM fetched with a nil Annotations map (ObjectMeta.Annotations is
// optional) does not panic on the map write that stamps ToolVersionMetadataKey.
// The host scan runs on its own goroutine with no recovery, so this write
// panicking would take down the whole node-agent process.
func Test_PrepareHostSbom_NilAnnotationsDoNotPanic(t *testing.T) {
	sm, store, _ := newHostSbomManager(t, hostCfg("node-1"), t.TempDir())
	seedHostSbom(t, store, nil)

	require.NotPanics(t, func() {
		_, _, ok := sm.prepareHostSbom("host-node-1", "node-1")
		assert.True(t, ok, "a nil-annotation SBOM has no status marker, so it must retry like any Incomplete/Initializing scan")
	})
}

// Test_HostSbomLoop_KeepsTickingAfterTooLarge proves the other half of the
// decision: the ticker itself is never stopped by a TooLarge trip, so the host
// SBOM resumes automatically as soon as the block is released.
func Test_HostSbomLoop_KeepsTickingAfterTooLarge(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	cfg := hostCfg("node-1")
	cfg.HostSBOMRescanInterval = 10 * time.Millisecond
	sm, store, _ := newHostSbomManager(t, cfg, t.TempDir())
	sm.ctx = ctx
	seedHostSbom(t, store, map[string]string{
		helpersv1.StatusMetadataKey:      helpersv1.TooLarge,
		helpersv1.ToolVersionMetadataKey: sm.version,
	})

	var attempts atomic.Int32
	sm.hostScanFn = func(hostID string) {
		attempts.Add(1)
		_, _, ok := sm.prepareHostSbom(hostSbomName(hostID), hostID)
		assert.False(t, ok)
	}

	go sm.hostSbomLoop("node-1")

	assert.Eventually(t, func() bool { return attempts.Load() >= 3 }, 2*time.Second, 5*time.Millisecond,
		"a TooLarge trip must block the scan, not stop the rescan ticker")
}

// Test_PrepareHostSbom_LearningIsRescanned is the behaviour that distinguishes
// host from container: a completed host SBOM is exactly what the ticker exists
// to refresh, whereas a completed container SBOM is left alone.
func Test_PrepareHostSbom_LearningIsRescanned(t *testing.T) {
	sm, store, _ := newHostSbomManager(t, hostCfg("node-1"), t.TempDir())
	seedHostSbom(t, store, map[string]string{
		helpersv1.StatusMetadataKey:      helpersv1.Learning,
		helpersv1.ToolVersionMetadataKey: sm.version,
	})

	_, hadContent, ok := sm.prepareHostSbom("host-node-1", "node-1")
	assert.True(t, ok, "the host rescan must refresh a completed SBOM at the same tool version")
	assert.True(t, hadContent, "a completed SBOM has content, so a later size trip must be Incomplete, not TooLarge")
}

// Test_PrepareHostSbom_IncompleteRetainsContent proves the same invariant as
// Test_PrepareHostSbom_LearningIsRescanned for the Incomplete status: it is
// only ever written when a scan already had content but was still oversized
// (see processHostSbom's hadContent==true write path), so a rescan of it must
// report hadContent==true. Reporting false here would misroute a
// still-too-large rescan into the TooLarge branch, which wipes wipSbom.Spec --
// destroying content that Incomplete specifically exists to preserve.
func Test_PrepareHostSbom_IncompleteRetainsContent(t *testing.T) {
	sm, store, _ := newHostSbomManager(t, hostCfg("node-1"), t.TempDir())
	seedHostSbom(t, store, map[string]string{
		helpersv1.StatusMetadataKey:      helpersv1.Incomplete,
		helpersv1.ToolVersionMetadataKey: sm.version,
	})

	_, hadContent, ok := sm.prepareHostSbom("host-node-1", "node-1")
	assert.True(t, ok, "the host rescan must retry an Incomplete SBOM at the same tool version")
	assert.True(t, hadContent, "Incomplete only ever means content was retained; a rescan must not report hadContent=false")
}

// Test_ProcessHostSbom_RescanReplacesExistingSBOM proves the rescan path
// actually persists a fresh document rather than no-oping.
func Test_ProcessHostSbom_RescanReplacesExistingSBOM(t *testing.T) {
	sm, store, _ := newHostSbomManager(t, hostCfg("node-1"), tinyHostRoot(t))

	sm.processHostSbom("node-1")
	sm.processHostSbom("node-1")

	store.mu.Lock()
	replaces := store.replaceCalls
	store.mu.Unlock()
	assert.Equal(t, 2, replaces, "each host rescan must persist a refreshed SBOM")
}

// --- scan timeout ----------------------------------------------------------

// Test_ProcessHostSbom_ScanTimeoutIsAborted proves a host scan that exceeds
// hostScanTimeout is aborted rather than left to run (or hang) indefinitely:
// with hostScanTimeoutOverride set to a tiny bound and a fake Syft scan that
// blocks until its context is cancelled, processHostSbom must return promptly
// once the timeout fires, and the scan's context must have been cancelled
// with DeadlineExceeded.
func Test_ProcessHostSbom_ScanTimeoutIsAborted(t *testing.T) {
	sm, store, reporter := newHostSbomManager(t, hostCfg("node-1"), tinyHostRoot(t))
	sm.hostScanTimeoutOverride = 20 * time.Millisecond

	var sawDeadline atomic.Bool
	sm.hostSyftScanFn = func(ctx context.Context, _ source.Source, _ *syft.CreateSBOMConfig) (*sbom.SBOM, error) {
		<-ctx.Done()
		sawDeadline.Store(errors.Is(ctx.Err(), context.DeadlineExceeded))
		return nil, ctx.Err()
	}

	done := make(chan struct{})
	go func() {
		sm.processHostSbom("node-1")
		close(done)
	}()

	select {
	case <-done:
	case <-time.After(2 * time.Second):
		t.Fatal("processHostSbom did not return after the scan timed out")
	}

	assert.True(t, sawDeadline.Load(), "the scan's context must have been cancelled with DeadlineExceeded")
	assert.Zero(t, reporter.count(), "host failures must not be sent to the image-keyed endpoint")

	sbomCR := store.get("host-node-1")
	require.NotNil(t, sbomCR)
	assert.Equal(t, helpersv1.Initializing, sbomCR.Annotations[helpersv1.StatusMetadataKey],
		"a single scan timeout must not pin the host SBOM to a terminal status")
}

// Test_ProcessHostSbom_TimeoutDoesNotBlockLaterRescan proves the recoverable
// half of the fix: after a scan times out, the processing/in-flight marker
// must have been cleared so a later rescan attempt is not permanently
// blocked. Without the deferred processing.Remove (or if a timeout somehow
// bypassed it), prepareHostSbom's `s.processing.Contains(sbomName)` check
// would wedge the host SBOM forever.
func Test_ProcessHostSbom_TimeoutDoesNotBlockLaterRescan(t *testing.T) {
	sm, store, _ := newHostSbomManager(t, hostCfg("node-1"), tinyHostRoot(t))
	sm.hostScanTimeoutOverride = 20 * time.Millisecond

	timedOut := true
	sm.hostSyftScanFn = func(ctx context.Context, src source.Source, cfg *syft.CreateSBOMConfig) (*sbom.SBOM, error) {
		if timedOut {
			<-ctx.Done()
			return nil, ctx.Err()
		}
		return syft.CreateSBOM(ctx, src, cfg)
	}

	sm.processHostSbom("node-1")
	require.Zero(t, sm.processing.Cardinality(), "the processing slot must be released after a timeout")

	// The retryable status left by the timeout must not itself block a later
	// rescan attempt from proceeding. The override is widened back out so this
	// real (fast, but not instant) scan isn't itself cut off by the tiny bound
	// used to force the first attempt to time out.
	timedOut = false
	sm.hostScanTimeoutOverride = 5 * time.Second
	sm.processHostSbom("node-1")

	sbomCR := store.get("host-node-1")
	require.NotNil(t, sbomCR)
	assert.Equal(t, helpersv1.Learning, sbomCR.Annotations[helpersv1.StatusMetadataKey],
		"a rescan following a timeout must be able to complete successfully")
	assert.NotEmpty(t, sbomCR.Spec.Syft.Artifacts, "the successful rescan must have catalogued the fixture package")
	assert.Zero(t, sm.processing.Cardinality())
}
