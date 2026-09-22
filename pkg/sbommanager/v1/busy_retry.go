package v1

import (
	"math/rand/v2"
	"time"
)

// Bounded retry policy for sbomscanner.ErrScannerBusy, shared verbatim by the
// container path (sbom_manager.go) and the host path (host_sbom.go).
//
// A busy rejection means the sidecar declined to ADMIT the scan: no scan work
// was dispatched, nothing crashed, and nothing timed out. It is therefore never
// routed through either path's failure accounting. It is also not routed
// through pendingScans: that queue's drain condition is scannerClient.Ready()
// == true, which a merely-busy (as opposed to actually-down) sidecar already
// satisfies, so a scan parked there would be re-submitted immediately and
// busy-loop rather than back off.
//
// The ceiling must comfortably exceed the sidecar's own longest realistic
// busy period, not the other way around: the sidecar's admission slot can be
// held for a full host root-filesystem scan (hostScanTimeout, 16 minutes) or
// a full container image scan (also up to 16 minutes), and hostSbomLoop runs
// its scan immediately at startup -- exactly when container-image scans also
// burst. An earlier version of this ceiling was 5 attempts (~2 minutes),
// reasoned as "a sidecar busy for two minutes straight is no longer
// distinguishable from a problem" -- that reasoning was live-cluster-measured
// to be false: a real host scan under PR 1's parallelism cap took 15-20
// minutes, meaning every container scan queued behind it would exhaust that
// ceiling, fall through to handleGenericFailure/reportFailure, and — after
// maxScanRetries such rounds — be pinned Incomplete, all while the sidecar
// was never actually broken. This is a real Requirement 5 regression the
// short ceiling introduced (see the plan's PR 2 review history), so the
// ceiling is now sized to outlast hostScanTimeout with margin: 22 attempts
// (5+10+20+40 ramp, then 18 more at the 60s cap) sums to roughly 19 minutes,
// comfortably longer than either scan type's own timeout. What happens when
// THIS ceiling is reached still differs per path: the container path falls
// through to its normal failure handling (a sidecar busy for ~19 minutes
// straight genuinely is indistinguishable from a real problem), while the
// host path falls back to the in-process scan for that one cycle, since
// waiting for the next rescan tick would mean a coverage gap of up to
// hostSBOMRescanInterval (24h by default).
const (
	busyRetryInitialDelay = 5 * time.Second
	busyRetryMaxDelay     = 60 * time.Second
	busyRetryMaxAttempts  = 22
	// busyRetryJitterFraction spreads retries by ±20%, so the container worker
	// and the host goroutine -- which are exactly the two contenders for the
	// single admission slot -- do not resynchronise onto the same instants and
	// keep bouncing off each other.
	busyRetryJitterFraction = 0.2
)

// busyRetryDelay returns the delay before the given 1-based retry attempt:
// 5s, 10s, 20s, 40s, 60s (capped), each jittered by ±20%.
func busyRetryDelay(attempt int) time.Duration {
	if attempt < 1 {
		attempt = 1
	}
	delay := busyRetryInitialDelay
	for range attempt - 1 {
		delay *= 2
		if delay >= busyRetryMaxDelay {
			delay = busyRetryMaxDelay
			break
		}
	}
	jitter := 1 + busyRetryJitterFraction*(2*rand.Float64()-1)
	return time.Duration(float64(delay) * jitter)
}

// retryDelay resolves the delay through the manager's test seam when one is
// installed, so tests can exercise the full attempt ceiling without waiting out
// the 22-attempt backoff (~19 minutes, excluding admission waits).
func (s *SbomManager) retryDelay(attempt int) time.Duration {
	if s.busyRetryDelayFn != nil {
		return s.busyRetryDelayFn(attempt)
	}
	return busyRetryDelay(attempt)
}
