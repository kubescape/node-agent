package v1

import (
	"context"
	"errors"
	"sync/atomic"
	"testing"
	"time"

	"github.com/anchore/syft/syft"
	"github.com/anchore/syft/syft/sbom"
	"github.com/anchore/syft/syft/source"
	helpersv1 "github.com/kubescape/k8s-interface/instanceidhandler/v1/helpers"
	"github.com/kubescape/node-agent/pkg/config"
	"github.com/kubescape/node-agent/pkg/metricsmanager"
	sbomscanner "github.com/kubescape/node-agent/pkg/sbomscanner/v1"
	"github.com/kubescape/storage/pkg/apis/softwarecomposition/v1beta1"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	_ "modernc.org/sqlite" // required by syft's RPM cataloger
)

// hostScannerSpy is a SBOMScannerClient that records host-scan calls and
// returns a scripted result. Its CreateSBOM is never reached: these tests drive
// the host branch only.
type hostScannerSpy struct {
	ready bool
	calls atomic.Int32
	// errs is consumed one entry per call; the last entry repeats once
	// exhausted. nil means "succeed".
	errs   []error
	result *sbomscanner.HostScanResult
}

func (h *hostScannerSpy) CreateSBOM(_ context.Context, _ sbomscanner.ScanRequest) (*sbomscanner.ScanResult, error) {
	return nil, errors.New("container path not exercised by these tests")
}

func (h *hostScannerSpy) ScanHostFilesystem(_ context.Context, _ sbomscanner.HostScanRequest) (*sbomscanner.HostScanResult, error) {
	n := int(h.calls.Add(1))
	var err error
	switch {
	case len(h.errs) == 0:
	case n <= len(h.errs):
		err = h.errs[n-1]
	default:
		err = h.errs[len(h.errs)-1]
	}
	if err != nil {
		return nil, err
	}
	if h.result != nil {
		return h.result, nil
	}
	return &sbomscanner.HostScanResult{
		SyftDocument: v1beta1.SyftDocument{Artifacts: []v1beta1.SyftPackage{{
			PackageBasicData: v1beta1.PackageBasicData{Name: "sidecar-pkg", Version: "2.0"},
		}}},
		SBOMSize: 1234,
	}, nil
}

func (h *hostScannerSpy) Ready() bool  { return h.ready }
func (h *hostScannerSpy) Close() error { return nil }

// newOffloadManager wires a host manager with a sidecar and an instant busy
// backoff, so the 22-retry ceiling is exercised without waiting out
// the real ~19-minute backoff window (plus admission waits).
func newOffloadManager(t *testing.T, cfg config.Config, spy *hostScannerSpy) (*SbomManager, *fakeSbomClient) {
	t.Helper()
	cfg.HostSbomOffloadEnabled = true
	sm, store, _ := newHostSbomManager(t, cfg, tinyHostRoot(t))
	sm.scannerClient = spy
	sm.busyRetryDelayFn = func(int) time.Duration { return time.Millisecond }
	return sm, store
}

// countingInProcessScan installs a real-but-counted in-process scan, so each
// test can assert exactly how many root-filesystem walks node-agent performed
// itself.
func countingInProcessScan(sm *SbomManager) *atomic.Int32 {
	var calls atomic.Int32
	sm.hostSyftScanFn = func(ctx context.Context, src source.Source, cfg *syft.CreateSBOMConfig) (*sbom.SBOM, error) {
		calls.Add(1)
		return syft.CreateSBOM(ctx, src, cfg)
	}
	return &calls
}

// Test_HostScan_UsesSidecarWhenReady is the core dispatch proof: with a ready
// sidecar, node-agent does not walk the host root itself at all, and the
// sidecar's already-stripped document lands in Spec.Syft.
func Test_HostScan_UsesSidecarWhenReady(t *testing.T) {
	spy := &hostScannerSpy{ready: true}
	sm, store := newOffloadManager(t, hostCfg("node-1"), spy)
	inProcess := countingInProcessScan(sm)

	sm.processHostSbom("node-1")

	assert.Equal(t, int32(1), spy.calls.Load(), "the sidecar must have been used")
	assert.Zero(t, inProcess.Load(), "node-agent must not have scanned in-process as well")

	cr := store.get(hostSbomName("node-1"))
	require.NotNil(t, cr)
	assert.Equal(t, helpersv1.Learning, cr.Annotations[helpersv1.StatusMetadataKey])
	require.Len(t, cr.Spec.Syft.Artifacts, 1)
	assert.Equal(t, "sidecar-pkg", cr.Spec.Syft.Artifacts[0].Name,
		"the sidecar's document must converge into Spec.Syft")
	assert.Equal(t, sm.version, cr.Spec.Metadata.Tool.Version,
		"Tool.Version stays node-agent's own version on both paths")
}

// Test_HostScan_FallsBackInProcess covers every way the sidecar can be absent.
// The dispatch is two-way by design: a host, unlike a container, has no second
// trigger that would revisit a scan parked waiting for a sidecar.
func Test_HostScan_FallsBackInProcess(t *testing.T) {
	cases := []struct {
		name    string
		prepare func(sm *SbomManager)
	}{
		{"no sidecar configured", func(sm *SbomManager) { sm.scannerClient = nil }},
		{"sidecar not ready", func(sm *SbomManager) { sm.scannerClient = &hostScannerSpy{ready: false} }},
		{"offload disabled by config", func(sm *SbomManager) { sm.cfg.HostSbomOffloadEnabled = false }},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			spy := &hostScannerSpy{ready: true}
			sm, store := newOffloadManager(t, hostCfg("node-1"), spy)
			inProcess := countingInProcessScan(sm)
			tc.prepare(sm)

			sm.processHostSbom("node-1")

			assert.Equal(t, int32(1), inProcess.Load(), "the in-process fallback must have run")
			cr := store.get(hostSbomName("node-1"))
			require.NotNil(t, cr)
			assert.Equal(t, helpersv1.Learning, cr.Annotations[helpersv1.StatusMetadataKey])
			assert.NotEmpty(t, cr.Spec.Syft.Artifacts)
		})
	}
	t.Run("sidecar spy is untouched when not ready", func(t *testing.T) {
		spy := &hostScannerSpy{ready: false}
		sm, _ := newOffloadManager(t, hostCfg("node-1"), spy)
		countingInProcessScan(sm)
		sm.processHostSbom("node-1")
		assert.Zero(t, spy.calls.Load())
	})
}

// Test_HostScan_BusyRetriesThenFallsBackForOneCycle is the coverage-gap guard.
//
// A sidecar busy for the whole retry window must not mean "no host SBOM until
// the next rescan tick" -- at a 24h default interval that is a full-day gap.
// The fallback is safe here specifically because a busy rejection happens
// BEFORE dispatch, so no scan work was wasted, and it must not touch any
// failure counter: the sidecar did not fail, it was occupied.
func Test_HostScan_BusyRetriesThenFallsBackForOneCycle(t *testing.T) {
	spy := &hostScannerSpy{ready: true, errs: []error{sbomscanner.ErrScannerBusy}}
	sm, store := newOffloadManager(t, hostCfg("node-1"), spy)
	inProcess := countingInProcessScan(sm)

	sm.processHostSbom("node-1")

	assert.Equal(t, int32(busyRetryMaxAttempts+1), spy.calls.Load(),
		"the sidecar must be retried up to the ceiling before falling back")
	assert.Equal(t, int32(1), inProcess.Load(), "the in-process fallback must complete this cycle")

	cr := store.get(hostSbomName("node-1"))
	require.NotNil(t, cr)
	assert.Equal(t, helpersv1.Learning, cr.Annotations[helpersv1.StatusMetadataKey],
		"a busy sidecar must still produce a completed host SBOM in the same cycle")
	assert.Zero(t, sm.hostSidecarFailures, "busy is not a sidecar failure")
	_, pinned := sm.failureRetries.Get(hostSbomName("node-1"))
	assert.False(t, pinned, "busy must not consume the generic failure budget")

	// Next cycle: a sidecar that is no longer busy is used again immediately --
	// the fallback was a one-cycle exception, not a permanent downgrade.
	spy.errs = nil
	spy.calls.Store(0)
	sm.processHostSbom("node-1")
	assert.Equal(t, int32(1), spy.calls.Load())
}

// Test_HostScan_PostDispatchFailureDoesNotDoubleScan pins the asymmetry with
// the busy case: here the sidecar DID attempt the scan, so re-running it
// in-process in the same cycle would pay the full cost twice -- exactly what
// offloading exists to avoid.
func Test_HostScan_PostDispatchFailureDoesNotDoubleScan(t *testing.T) {
	spy := &hostScannerSpy{ready: true, errs: []error{sbomscanner.ErrScannerCrashed}}
	sm, store := newOffloadManager(t, hostCfg("node-1"), spy)
	inProcess := countingInProcessScan(sm)

	sm.processHostSbom("node-1")

	assert.Equal(t, int32(1), spy.calls.Load(), "a post-dispatch failure is not retried within the cycle")
	assert.Zero(t, inProcess.Load(), "a post-dispatch failure must not trigger a same-cycle in-process rescan")
	assert.Equal(t, 1, sm.hostSidecarFailures)

	cr := store.get(hostSbomName("node-1"))
	require.NotNil(t, cr)
	assert.Equal(t, helpersv1.Initializing, cr.Annotations[helpersv1.StatusMetadataKey],
		"a single sidecar failure must not pin the host SBOM")
}

// Test_HostScan_SidecarFailuresNeverProduceTooLarge is the Requirement 3 guard
// that the "existing tests pass unmodified" check cannot catch, because this is
// a new code path rather than a modified old one.
//
// The host-sidecar failure counter is deliberately separate from the container
// path's crashLoopRetries. Reusing that counter would let repeated sidecar
// connectivity failures -- which say nothing whatsoever about the document's
// size -- push the host SBOM through TooLarge, a one-way door in storage.
func Test_HostScan_SidecarFailuresNeverProduceTooLarge(t *testing.T) {
	spy := &hostScannerSpy{ready: true, errs: []error{sbomscanner.ErrScannerCrashed}}
	sm, store := newOffloadManager(t, hostCfg("node-1"), spy)
	countingInProcessScan(sm)

	for range 10 {
		sm.processHostSbom("node-1")
	}

	cr := store.get(hostSbomName("node-1"))
	require.NotNil(t, cr)
	assert.NotEqual(t, helpersv1.TooLarge, cr.Annotations[helpersv1.StatusMetadataKey],
		"only a genuine size overage may ever produce TooLarge")
	assert.Equal(t, helpersv1.Incomplete, cr.Annotations[helpersv1.StatusMetadataKey],
		"repeated sidecar failures degrade to the retryable Incomplete state")
	assert.Equal(t, 10, sm.hostSidecarFailures)
	_, viaCrashLoop := sm.crashLoopRetries.Get(hostSbomName("node-1"))
	assert.False(t, viaCrashLoop, "the container path's crash-loop counter must never see host sidecar failures")
}

// Test_HostScan_OversizedTransferMatchesInProcessTerminalStatus is the
// equivalence proof for the oversized-document mapping: the same document must
// reach the same terminal state whichever path produced it. Left unmapped, the
// sidecar path would instead retry a full host-root walk forever.
func Test_HostScan_OversizedTransferMatchesInProcessTerminalStatus(t *testing.T) {
	const oversized = 900 * 1024 * 1024

	t.Run("via the sidecar", func(t *testing.T) {
		spy := &hostScannerSpy{ready: true, errs: []error{&sbomscanner.HostDocumentTooLargeError{Size: oversized}}}
		sm, store := newOffloadManager(t, hostCfg("node-1"), spy)
		inProcess := countingInProcessScan(sm)

		sm.processHostSbom("node-1")

		assert.Zero(t, inProcess.Load(), "an oversized document is terminal, not a reason to rescan in-process")
		cr := store.get(hostSbomName("node-1"))
		require.NotNil(t, cr)
		assert.Equal(t, helpersv1.TooLarge, cr.Annotations[helpersv1.StatusMetadataKey])
		assert.Equal(t, "943718400", cr.Annotations[helpersv1.ResourceSizeMetadataKey],
			"the reported transfer size stands in for size.Of on this path")
		assert.Equal(t, "20971520", cr.Annotations[HostMaxSBOMSizeAnnotation],
			"the release condition must record cfg.MaxSBOMSize, as on the in-process path")
		assert.Empty(t, cr.Spec.Syft.Artifacts, "TooLarge clears the spec")
	})

	t.Run("in-process, equivalently oversized", func(t *testing.T) {
		cfg := hostCfg("node-1")
		cfg.MaxSBOMSize = 1 // any real document trips the gate
		sm, store, _ := newHostSbomManager(t, cfg, tinyHostRoot(t))

		sm.processHostSbom("node-1")

		cr := store.get(hostSbomName("node-1"))
		require.NotNil(t, cr)
		assert.Equal(t, helpersv1.TooLarge, cr.Annotations[helpersv1.StatusMetadataKey],
			"both paths must reach the same terminal status for an oversized document")
		assert.Empty(t, cr.Spec.Syft.Artifacts)
	})
}

// Test_HostScan_OversizedTransferWithContentStaysIncomplete proves the
// oversized-transfer mapping honours the hadContent rule rather than bypassing
// it: TooLarge is a one-way door, so an SBOM that already carries real content
// must degrade to the retryable Incomplete instead.
func Test_HostScan_OversizedTransferWithContentStaysIncomplete(t *testing.T) {
	spy := &hostScannerSpy{ready: true}
	sm, store := newOffloadManager(t, hostCfg("node-1"), spy)
	countingInProcessScan(sm)

	// First cycle succeeds, so the SBOM reaches Learning and has content.
	sm.processHostSbom("node-1")
	require.Equal(t, helpersv1.Learning, store.get(hostSbomName("node-1")).Annotations[helpersv1.StatusMetadataKey])

	// Second cycle comes back oversized.
	spy.errs = []error{&sbomscanner.HostDocumentTooLargeError{Size: 900 * 1024 * 1024}}
	sm.processHostSbom("node-1")

	cr := store.get(hostSbomName("node-1"))
	require.NotNil(t, cr)
	assert.Equal(t, helpersv1.Incomplete, cr.Annotations[helpersv1.StatusMetadataKey],
		"a content-bearing host SBOM must never be pushed through the TooLarge one-way door")
	assert.NotContains(t, cr.Annotations, HostMaxSBOMSizeAnnotation)
}

// Test_BusyRetryDelay_IsBoundedAndJittered pins the shared backoff policy: 5s
// initial, doubling to a 60s cap, jittered +/-20%, so the two contenders for
// the single admission slot do not resynchronise onto the same instants.
func Test_BusyRetryDelay_IsBoundedAndJittered(t *testing.T) {
	bases := []time.Duration{5 * time.Second, 10 * time.Second, 20 * time.Second, 40 * time.Second, 60 * time.Second, 60 * time.Second}
	for i, base := range bases {
		attempt := i + 1
		d := busyRetryDelay(attempt)
		assert.GreaterOrEqual(t, d, time.Duration(float64(base)*(1-busyRetryJitterFraction)), "attempt %d", attempt)
		assert.LessOrEqual(t, d, time.Duration(float64(base)*(1+busyRetryJitterFraction)), "attempt %d", attempt)
	}
	assert.LessOrEqual(t, busyRetryDelay(99), time.Duration(float64(busyRetryMaxDelay)*(1+busyRetryJitterFraction)),
		"the backoff must be capped, not unbounded")
}

// Test_HostScan_BusyRetryStopsOnShutdown proves the retry timers are registered
// against the manager's context: a shutdown mid-backoff must abandon the scan
// promptly rather than sleeping out the window into a torn-down manager.
func Test_HostScan_BusyRetryStopsOnShutdown(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	spy := &hostScannerSpy{ready: true, errs: []error{sbomscanner.ErrScannerBusy}}
	sm, _ := newOffloadManager(t, hostCfg("node-1"), spy)
	sm.ctx = ctx
	sm.busyRetryDelayFn = func(int) time.Duration { return time.Hour }
	inProcess := countingInProcessScan(sm)

	done := make(chan struct{})
	go func() {
		sm.processHostSbom("node-1")
		close(done)
	}()

	assert.Eventually(t, func() bool { return spy.calls.Load() >= 1 }, 2*time.Second, 5*time.Millisecond)
	cancel()

	select {
	case <-done:
	case <-time.After(2 * time.Second):
		t.Fatal("the busy backoff did not abandon the scan on shutdown")
	}
	assert.Zero(t, inProcess.Load(), "a shutdown must not start a fresh in-process scan")
	// The sidecar was never confirmed to have failed -- the last observed
	// outcome was "busy" -- so an abort on shutdown must not touch any
	// failure accounting, exactly like a genuine busy fallback. Before the
	// hostScanAborted outcome was introduced, this path fell through to
	// handleHostSidecarFailure, incrementing the counter and potentially
	// issuing a storage write into a manager already being torn down.
	assert.Zero(t, sm.hostSidecarFailures, "shutdown mid-busy-retry must not count as a sidecar failure")
}

// hostReadinessMetrics records only the readiness gauge; other metrics are no-ops.
type hostReadinessMetrics struct {
	metricsmanager.MetricsMock
	values []bool
}

func (m *hostReadinessMetrics) SetSBOMScannerReady(ready bool) {
	m.values = append(m.values, ready)
}

func Test_HostOffload_RecordsReadiness(t *testing.T) {
	spy := &hostScannerSpy{ready: true}
	sm, _ := newOffloadManager(t, hostCfg("node-1"), spy)
	metrics := &hostReadinessMetrics{}
	sm.metrics = metrics
	assert.True(t, sm.hostOffloadAvailable())
	spy.ready = false
	assert.False(t, sm.hostOffloadAvailable())
	sm.scannerClient = nil
	assert.False(t, sm.hostOffloadAvailable())
	spy.ready = true
	sm.scannerClient = spy
	sm.cfg.HostSbomOffloadEnabled = false
	assert.False(t, sm.hostOffloadAvailable())
	assert.Equal(t, []bool{true, false, false, true}, metrics.values)
}

func Test_HostOffload_FailureClearsReadiness(t *testing.T) {
	spy := &hostScannerSpy{ready: true, errs: []error{errors.New("scanner disconnected")}}
	sm, _ := newOffloadManager(t, hostCfg("node-1"), spy)
	metrics := &hostReadinessMetrics{}
	sm.metrics = metrics
	sm.processHostSbom("node-1")
	assert.Equal(t, []bool{true, false}, metrics.values)
}
