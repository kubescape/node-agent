package v1

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"os"
	"strings"
	"time"

	"github.com/DmitriyVTitov/size"
	"github.com/anchore/syft/syft"
	"github.com/anchore/syft/syft/cataloging"
	"github.com/anchore/syft/syft/cataloging/pkgcataloging"
	sbomcataloger "github.com/anchore/syft/syft/pkg/cataloger/sbom"
	containercollection "github.com/inspektor-gadget/inspektor-gadget/pkg/container-collection"
	"github.com/kubescape/go-logger"
	"github.com/kubescape/go-logger/helpers"
	helpersv1 "github.com/kubescape/k8s-interface/instanceidhandler/v1/helpers"
	"github.com/kubescape/node-agent/pkg/hostidentity"
	"github.com/kubescape/node-agent/pkg/metricsmanager"
	"github.com/kubescape/node-agent/pkg/sbommanager/v1/syftutil"
	sbomscanner "github.com/kubescape/node-agent/pkg/sbomscanner/v1"
	"github.com/kubescape/storage/pkg/apis/softwarecomposition/v1beta1"
	k8serrors "k8s.io/apimachinery/pkg/api/errors"
	"k8s.io/apimachinery/pkg/util/validation"
)

// HostSbomNameLabelKey labels the host SBOM with the node it describes, since
// none of the image-derived labels (image ID/name/tag) apply to a host.
const HostSbomNameLabelKey = "kubescape.io/host"

// HostMaxSBOMSizeAnnotation records cfg.MaxSBOMSize at the time a host SBOM
// was marked TooLarge, so hostTooLargeReleased can detect a later config
// change and release the block. It is a dedicated key, not
// ScannerMemoryLimitAnnotation.
//
// The host scan can now run in the sbom-scanner sidecar, so "the host has no
// sidecar" is no longer why -- but the conclusion is unchanged, and for a
// sharper reason: ScannerMemoryLimitAnnotation records the limit that decides
// whether the SIDECAR's own memory is exceeded, whereas what marks a host SBOM
// TooLarge is always cfg.MaxSBOMSize (either via size.Of client-side, or via
// the sidecar's transfer-budget check, which is likewise unrelated to the
// scanner's memory limit). Recording the scanner memory limit here would mean
// cfg.MaxSBOMSize -- the value that actually gates the host size check -- could
// never unblock a stuck TooLarge host SBOM.
const HostMaxSBOMSizeAnnotation = "kubescape.io/host-max-sbom-size"

// hostScanTimeout bounds a single host root-filesystem scan. Without it, a
// syft.CreateSBOM call that hangs on a slow or unresponsive mount would block
// the host scan goroutine (see hostSbomLoop) forever: the ticker never fires
// again because the previous tick's call to processHostSbom never returns,
// and no future rescan could ever be attempted.
//
// It intentionally mirrors the 16-minute bound the container path applies to
// its scanner-sidecar call (sbom_manager.go's scanTimeout) rather than
// inventing a shorter host-specific value: a host root-fs walk can easily
// cover more data than a single container image layer, so it deserves at
// least as much headroom, and 16 minutes is still tiny relative to the
// default 24h HostSBOMRescanInterval, so a timed-out scan is retried on the
// very next tick rather than starving the node of a fresh host SBOM.
const hostScanTimeout = 16 * time.Minute

// startHostSbomLifecycle starts the host's SBOM lifecycle: one immediate scan
// followed by a rescan every cfg.HostSBOMRescanInterval.
//
// It is deliberately the only entry point for host SBOM work, and the container
// path never reaches it: ContainerCallback dispatches here and returns before
// any of getMountedVolumes/getImageStatus/awaitAndSubmit, so the host never
// touches image status, overlay mounts or shared container data.
func (s *SbomManager) startHostSbomLifecycle(notif containercollection.PubSubEvent) {
	if !s.cfg.HostMonitoringEnabled {
		return
	}
	// The host add-container notification can be delivered more than once (e.g.
	// the container-watcher collection replays it); only one loop may exist.
	if !s.hostLoopStarted.CompareAndSwap(false, true) {
		return
	}
	hostID, err := hostidentity.ResolveHostID(&s.cfg)
	if err != nil {
		logger.L().Ctx(s.ctx).Error("SbomManager - failed to resolve host ID, skipping host SBOM",
			helpers.Error(err),
			helpers.String("container ID", notif.Container.Runtime.ContainerID))
		s.hostLoopStarted.Store(false)
		return
	}
	go s.hostSbomLoop(hostID)
}

// hostSbomLoop runs the host scan immediately and then on every tick of
// cfg.HostSBOMRescanInterval until the manager's context is cancelled.
//
// The loop runs on its own goroutine rather than on s.pool: the pool has a
// single worker shared by every container on the node, and a full host
// root-filesystem scan parked on it would head-of-line-block container SBOM
// generation for the duration of the scan.
//
// Ticker scope: this is reachable only from startHostSbomLifecycle, which is
// reachable only from the IsHostContainer branch of ContainerCallback. No
// container-path code path has, or may gain, a ticker -- see
// Test_ContainerPath_RemainsOneShot.
func (s *SbomManager) hostSbomLoop(hostID string) {
	s.runHostScan(hostID)

	interval := s.cfg.HostSBOMRescanInterval
	if interval <= 0 {
		// Rescanning explicitly disabled: the host SBOM stays one-shot.
		return
	}
	ticker := time.NewTicker(interval)
	defer ticker.Stop()
	for {
		select {
		case <-s.ctx.Done():
			return
		case <-ticker.C:
			s.runHostScan(hostID)
		}
	}
}

// runHostScan dispatches to the test seam when one is installed.
func (s *SbomManager) runHostScan(hostID string) {
	if s.hostScanFn != nil {
		s.hostScanFn(hostID)
		return
	}
	s.processHostSbom(hostID)
}

// hostSbomName derives the SBOM CR name from the host identity. It is
// explicitly not image-derived: the host has no image tag or digest, so
// names.ImageInfoToSlug (used by the container path) is inapplicable.
// hostIDHashSuffixLen is the number of hex characters from a hostID's SHA-256
// appended to collision-resistant host identifiers (hostSbomName and
// hostSbomLabels), so two distinct host identities that happen to
// sanitize/truncate to the same base don't collide. The full 32 hex
// characters (128 bits) are used -- not a short prefix -- since even an
// 8-character (32-bit) prefix leaves a non-negligible collision chance across
// a large enough fleet, and collisionResistantLabel's maxBaseLen computation
// already accounts for whatever length is chosen here, so there is no
// DNS-1123-label-limit reason to keep it short.
const hostIDHashSuffixLen = 32

// hostIDHashSuffix returns a short, deterministic hash of the RAW hostID
// (before any lossy sanitize/truncate transform), used to make otherwise
// colliding sanitized identifiers unique again.
func hostIDHashSuffix(hostID string) string {
	sum := sha256.Sum256([]byte(hostID))
	return hex.EncodeToString(sum[:])[:hostIDHashSuffixLen]
}

// collisionResistantLabel builds a DNS-1123-label-safe identifier from
// hostID with the given fixed prefix, appending hostIDHashSuffix so two
// distinct hostIDs that sanitize to the same base (e.g. "node.a"/"node-a",
// or two names sharing a long common prefix) don't collide -- whether used
// as a storage key (hostSbomName) or a label value (hostSbomLabels).
func collisionResistantLabel(prefix, hostID string) string {
	suffix := hostIDHashSuffix(hostID)
	base := sanitize(strings.ToLower(hostID))
	maxBaseLen := 63 - len(prefix) - len("-") - len(suffix)
	if len(base) > maxBaseLen {
		base = strings.TrimRight(base[:maxBaseLen], "-")
	}
	return prefix + base + "-" + suffix
}

func hostSbomName(hostID string) string {
	// sanitize is lossy (character replacement, then truncation to 63 chars),
	// so two distinct hostIDs can produce the same sanitized base -- e.g.
	// "node.a" and "node-a", or two names sharing a common 63-char prefix.
	// Since this name is the SBOM's storage key, a collision would let one
	// node silently overwrite another's SBOM.
	return collisionResistantLabel("host-", hostID)
}

// processHostSbom generates (or regenerates) the host's SBOM.
//
// It shares no code with processContainerWithMetadata by design: there is no
// imageStatus to marshal, no layer paths, and no image digest to report
// failures against. It does, however, share the sbom-scanner sidecar: since the
// dedicated ScanHostFilesystem RPC exists, a ready sidecar (with offload
// enabled) runs the scan in its own, generously-provisioned process, and the
// in-process Syft scan over a directory source is the permanent fallback for
// everything else.
//
// The dispatch is deliberately TWO-way (sidecar-ready vs. everything else),
// unlike the container path's three-way branch. The container path can afford
// to park a scan in pendingScans until the sidecar comes back, because another
// container start will drive it. A host is always present and has no such
// second trigger, so it must never silently stall waiting on a sidecar.
//
// It also never calls the kubevuln failure-reporting path on any failure
// branch below: scanfailure.ScanFailureReport is keyed by ImageTag and
// ImageHash and carries a WorkloadIdentifier (namespace/pod/container). A host
// has none of these, so calling it would either send an empty-image report the
// backend cannot correlate, or dereference container metadata the host
// notification does not carry. Omitting it is the explicit decision;
// Test_ProcessHostSbom_NeverReportsFailure locks it in.
func (s *SbomManager) processHostSbom(hostID string) {
	sbomName := hostSbomName(hostID)

	wipSbom, hadContent, ok := s.prepareHostSbom(sbomName, hostID)
	if !ok {
		return
	}

	s.processing.Add(sbomName)
	defer s.processing.Remove(sbomName)

	if s.hostOffloadAvailable() {
		doc, outcome, transferSize := s.hostScanViaSidecar(sbomName)
		switch outcome {
		case hostScanOK:
			s.finishHostSbom(wipSbom, sbomName, hostID, doc, hadContent)
			return
		case hostScanTooLargeToTransfer:
			s.finishHostSbomOversizedTransfer(wipSbom, sbomName, hostID, transferSize, hadContent)
			return
		case hostScanFailed:
			// Post-dispatch failure: the sidecar actually attempted the scan,
			// so retrying in-process in the same cycle would pay the full cost
			// of a second root-filesystem walk -- exactly what offloading
			// exists to avoid. Wait for the next rescan tick instead.
			s.handleHostSidecarFailure(sbomName)
			return
		case hostScanBusyFallback:
			// Pre-dispatch: the sidecar never started any work, so there is no
			// double-scan cost and falling back in-process is free. This is a
			// one-cycle exception; the sidecar stays the default next tick.
			logger.L().Warning("SbomManager - scanner sidecar stayed busy, running this host scan in-process for one cycle",
				helpers.String("sbomName", sbomName))
		}
	}

	doc, ok := s.hostScanInProcess(sbomName)
	if !ok {
		return
	}
	s.finishHostSbom(wipSbom, sbomName, hostID, doc, hadContent)
}

// hostOffloadAvailable reports whether this cycle's scan should go to the
// sidecar. cfg.HostSbomOffloadEnabled is checked first so the kill switch takes
// effect without a health probe.
func (s *SbomManager) hostOffloadAvailable() bool {
	return s.cfg.HostSbomOffloadEnabled && s.scannerClient != nil && s.scannerClient.Ready()
}

// hostScanOutcome classifies a sidecar host-scan attempt. The distinction that
// matters is whether the sidecar actually dispatched the scan: a busy rejection
// did not, so it costs nothing to fall back in-process, whereas any other
// failure did, so falling back would double the work.
type hostScanOutcome int

const (
	hostScanOK hostScanOutcome = iota
	hostScanFailed
	hostScanBusyFallback
	hostScanTooLargeToTransfer
)

// hostSidecarFailureWarnThreshold is how many consecutive post-dispatch sidecar
// failures are tolerated before the host SBOM is declared degraded in the log.
// Crossing it changes nothing about the retry cadence -- the scan keeps
// retrying on the normal rescan interval, and it never pins a status.
const hostSidecarFailureWarnThreshold = 3

// hostScanViaSidecar runs one host scan through the sidecar, including the
// bounded busy-retry window.
//
// The returned document is already stripped and serialized by the sidecar, so
// it converges with the in-process path one step later than the scan call
// itself -- at the wipSbom.Spec.Syft assignment in finishHostSbom, not here.
func (s *SbomManager) hostScanViaSidecar(sbomName string) (v1beta1.SyftDocument, hostScanOutcome, int64) {
	timeout := hostScanTimeout
	if s.hostScanTimeoutOverride > 0 {
		timeout = s.hostScanTimeoutOverride
	}

	for attempt := 1; ; attempt++ {
		scanStart := time.Now()
		scanCtx, scanCancel := context.WithTimeout(s.ctx, timeout)
		result, err := s.scannerClient.ScanHostFilesystem(scanCtx, sbomscanner.HostScanRequest{
			SourceName: sbomName,
			// The sidecar resolves its own HOST_ROOT and compiles in the host
			// exclusion set, so neither is sent.
			EnableEmbeddedSBOMs: s.cfg.EnableEmbeddedSboms,
			Timeout:             timeout,
		})
		scanCancel()
		scanDuration := time.Since(scanStart)

		switch {
		case err == nil:
			s.metrics.ReportSBOMScan("success", metricsmanager.ScanPathSidecar)
			s.metrics.ObserveSBOMScanDuration("success", metricsmanager.ScanPathSidecar, scanDuration)
			return result.SyftDocument, hostScanOK, result.SBOMSize

		case errors.Is(err, sbomscanner.ErrScannerBusy):
			// Explicitly NOT a failure: nothing was scanned, nothing crashed.
			// No failure counter is touched on this branch.
			s.metrics.ReportSBOMScan("busy", metricsmanager.ScanPathSidecar)
			if attempt > busyRetryMaxAttempts {
				return v1beta1.SyftDocument{}, hostScanBusyFallback, 0
			}
			logger.L().Debug("SbomManager - scanner sidecar busy, retrying host scan",
				helpers.String("sbomName", sbomName),
				helpers.Int("attempt", attempt),
				helpers.Int("maxAttempts", busyRetryMaxAttempts))
			if !s.waitForBusyRetry(attempt) {
				// Manager shutting down: neither a failure nor a fallback.
				return v1beta1.SyftDocument{}, hostScanFailed, 0
			}

		case errors.Is(err, sbomscanner.ErrHostDocumentTooLargeToTransfer):
			var tooLarge *sbomscanner.HostDocumentTooLargeError
			var reported int64
			if errors.As(err, &tooLarge) {
				reported = tooLarge.Size
			}
			s.metrics.ReportSBOMScan("too_large", metricsmanager.ScanPathSidecar)
			s.metrics.ObserveSBOMScanDuration("too_large", metricsmanager.ScanPathSidecar, scanDuration)
			logger.L().Warning("SbomManager - host SBOM too large to transfer from the scanner sidecar",
				helpers.Error(err),
				helpers.String("sbomName", sbomName),
				helpers.Int("reportedSize", int(reported)))
			return v1beta1.SyftDocument{}, hostScanTooLargeToTransfer, reported

		default:
			status := "error"
			if errors.Is(err, context.DeadlineExceeded) {
				status = "timeout"
			}
			s.metrics.ReportSBOMScan(status, metricsmanager.ScanPathSidecar)
			s.metrics.ObserveSBOMScanDuration(status, metricsmanager.ScanPathSidecar, scanDuration)
			logger.L().Ctx(s.ctx).Error("SbomManager - host SBOM scan via the scanner sidecar failed",
				helpers.Error(err),
				helpers.String("sbomName", sbomName))
			return v1beta1.SyftDocument{}, hostScanFailed, 0
		}
	}
}

// waitForBusyRetry sleeps out one backoff step, reporting false if the manager
// is shutting down. It is a timer selected against s.ctx rather than a bare
// sleep so a shutdown is not delayed by up to 60 seconds. Unlike the container
// path's equivalent, it may block its goroutine: the host scan has a goroutine
// of its own and shares it with nothing.
func (s *SbomManager) waitForBusyRetry(attempt int) bool {
	timer := time.NewTimer(s.retryDelay(attempt))
	defer timer.Stop()
	select {
	case <-s.ctx.Done():
		return false
	case <-timer.C:
		return true
	}
}

// handleHostSidecarFailure records a post-dispatch sidecar failure against the
// host's OWN counter.
//
// That counter is deliberately not the container path's crashLoopRetries.
// crashLoopRetries is the one mechanism that can pin an SBOM into the TooLarge
// one-way door, and its meaning there is "the image does not fit in the
// scanner's memory limit". Sidecar connectivity failures say nothing about the
// host document's size, so feeding them into that counter would let a flapping
// sidecar permanently freeze the host SBOM as TooLarge -- a state only a
// genuine size overage may ever produce.
func (s *SbomManager) handleHostSidecarFailure(sbomName string) {
	s.hostSidecarFailures++
	if s.hostSidecarFailures >= hostSidecarFailureWarnThreshold {
		logger.L().Warning("SbomManager - host SBOM scanning via the scanner sidecar is degraded; still retrying on the normal rescan interval",
			helpers.String("sbomName", sbomName),
			helpers.Int("consecutiveFailures", s.hostSidecarFailures))
	}
	// Generic (retryable, at worst Incomplete) failure handling, identical to
	// the in-process path's. It can never reach TooLarge.
	s.handleGenericFailure(sbomName)
}

// hostScanInProcess runs the host scan inside node-agent, bounded by the
// CPU-limit-derived parallelism cap. It reports false once the failure has been
// fully handled.
func (s *SbomManager) hostScanInProcess(sbomName string) (v1beta1.SyftDocument, bool) {
	scanStart := time.Now()
	src, err := syftutil.NewHostSource(s.hostFSPrefix, sbomName, s.version)
	if err != nil {
		logger.L().Ctx(s.ctx).Error("SbomManager - failed to create host directory source",
			helpers.Error(err),
			helpers.String("path", s.hostFSPrefix),
			helpers.String("sbomName", sbomName))
		s.handleGenericFailure(sbomName)
		return v1beta1.SyftDocument{}, false
	}
	defer func() {
		_ = src.Close()
	}()

	scanFn := syft.CreateSBOM
	if s.hostSyftScanFn != nil {
		scanFn = s.hostSyftScanFn
	}
	timeout := hostScanTimeout
	if s.hostScanTimeoutOverride > 0 {
		timeout = s.hostScanTimeoutOverride
	}
	parallelism := s.resolveHostScanParallelism()
	// Logged unconditionally at scan start: the resolved value is the single
	// variable this cap exists to control, and an unlogged one is exactly what
	// would let a silent regression back to unbounded parallelism (n ==
	// NumCPU) pass an otherwise all-green live-cluster verification. Info,
	// not Debug, so that verification does not additionally depend on the
	// deployment running at a raised log level; it fires once per rescan
	// interval (24h by default), not per container.
	logger.L().Info("SbomManager - starting host SBOM scan",
		helpers.String("sbomName", sbomName),
		helpers.Int("parallelism", parallelism))
	scanCtx, scanCancel := context.WithTimeout(s.ctx, timeout)
	syftSBOM, err := scanFn(scanCtx, src, hostSbomConfig(s.version, s.cfg.EnableEmbeddedSboms, parallelism))
	scanCancel()
	if err != nil {
		scanDuration := time.Since(scanStart)
		if errors.Is(err, context.DeadlineExceeded) {
			s.metrics.ReportSBOMScan("timeout", metricsmanager.ScanPathInProcess)
			s.metrics.ObserveSBOMScanDuration("timeout", metricsmanager.ScanPathInProcess, scanDuration)
			logger.L().Ctx(s.ctx).Error("SbomManager - host SBOM scan timed out",
				helpers.Error(err),
				helpers.String("sbomName", sbomName),
				helpers.String("timeout", timeout.String()))
		} else {
			s.metrics.ReportSBOMScan("error", metricsmanager.ScanPathInProcess)
			s.metrics.ObserveSBOMScanDuration("error", metricsmanager.ScanPathInProcess, scanDuration)
			logger.L().Ctx(s.ctx).Error("SbomManager - failed to generate host SBOM",
				helpers.Error(err),
				helpers.String("sbomName", sbomName))
		}
		// handleGenericFailure/processing.Remove (deferred by the caller) both
		// run regardless of the failure's cause, so a timeout -- like any other
		// scan error -- clears the in-flight marker and leaves the SBOM in a
		// retryable status (Incomplete once maxScanRetries is reached,
		// otherwise unchanged), letting the next rescan tick try again
		// instead of being permanently stuck.
		s.handleGenericFailure(sbomName)
		return v1beta1.SyftDocument{}, false
	}
	s.metrics.ReportSBOMScan("success", metricsmanager.ScanPathInProcess)
	s.metrics.ObserveSBOMScanDuration("success", metricsmanager.ScanPathInProcess, time.Since(scanStart))
	v1beta1.StripSBOM(syftSBOM)
	return syftutil.ToSyftDocument(syftSBOM), true
}

// finishHostSbom is where the two scan paths converge: both hand over a
// finished SyftDocument, and everything from here -- metadata stamping, the
// size gate, persistence -- is identical regardless of which produced it.
//
// The size gate in particular is untouched by the sidecar work: it is still
// size.Of(wipSbom) against cfg.MaxSBOMSize, measured client-side after the
// document is attached, exactly as before.
func (s *SbomManager) finishHostSbom(wipSbom *v1beta1.SBOMSyft, sbomName, hostID string, doc v1beta1.SyftDocument, hadContent bool) {
	s.resetHostSbomCounters(sbomName)
	s.stampHostSbomMetadata(wipSbom)
	wipSbom.Spec.Syft = doc

	sz := size.Of(wipSbom)
	wipSbom.Annotations[helpersv1.ResourceSizeMetadataKey] = fmt.Sprintf("%d", sz)
	if sz > s.cfg.MaxSBOMSize {
		logger.L().Debug("SbomManager - host SBOM exceeds size limit",
			helpers.String("sbomName", sbomName),
			helpers.Int("maxSBOMSize", s.cfg.MaxSBOMSize),
			helpers.Int("size", sz))
		s.markHostSbomOversized(wipSbom, hadContent)
	} else {
		wipSbom.Annotations[helpersv1.StatusMetadataKey] = helpersv1.Learning
	}

	s.saveHostSbom(wipSbom, sbomName, hostID)
}

// finishHostSbomOversizedTransfer handles a host scan that succeeded in the
// sidecar but produced a document too large to send back.
//
// It routes into exactly the same hadContent/TooLarge/Incomplete branch
// finishHostSbom uses, so this document reaches the same terminal state it
// would have reached in-process. Only the size INPUT differs: the sidecar's
// measured serialized-byte count stands in for size.Of's deep-object
// measurement, since the document itself never arrived to be measured. The two
// track the same underlying quantity to within a constant factor, and under the
// default configuration (128MB transfer budget vs. a 20MB size limit) the
// mapping is unambiguous -- a document that cannot be transferred is many times
// over the size limit either way.
func (s *SbomManager) finishHostSbomOversizedTransfer(wipSbom *v1beta1.SBOMSyft, sbomName, hostID string, transferSize int64, hadContent bool) {
	s.resetHostSbomCounters(sbomName)
	s.stampHostSbomMetadata(wipSbom)
	wipSbom.Annotations[helpersv1.ResourceSizeMetadataKey] = fmt.Sprintf("%d", transferSize)
	s.markHostSbomOversized(wipSbom, hadContent)
	s.saveHostSbom(wipSbom, sbomName, hostID)
}

// markHostSbomOversized applies the shared oversized-document decision.
//
// TooLarge is a one-way door in the storage layer, so a host SBOM that already
// carries real content must never be pushed through it -- the same rule the
// container path applies via wipSbomHadContent.
func (s *SbomManager) markHostSbomOversized(wipSbom *v1beta1.SBOMSyft, hadContent bool) {
	if hadContent {
		wipSbom.Annotations[helpersv1.StatusMetadataKey] = helpersv1.Incomplete
		return
	}
	wipSbom.Annotations[helpersv1.StatusMetadataKey] = helpersv1.TooLarge
	wipSbom.Annotations[HostMaxSBOMSizeAnnotation] = fmt.Sprintf("%d", s.cfg.MaxSBOMSize)
	wipSbom.Spec = v1beta1.SBOMSyftSpec{}
}

// stampHostSbomMetadata records the document's own self-description.
//
// Tool.Version is node-agent's s.version on BOTH paths, not the sidecar's. The
// two are the same expression (packageVersion("github.com/anchore/syft"))
// resolved from the same go.mod, so in any real deployment they are the same
// string -- which is also why ScanHostFilesystemResponse carries no
// tool_version field to reconcile.
func (s *SbomManager) stampHostSbomMetadata(wipSbom *v1beta1.SBOMSyft) {
	delete(wipSbom.Annotations, NodeNameMetadataKey)
	wipSbom.Spec.Metadata.Report.CreatedAt = wipSbom.CreationTimestamp
	wipSbom.Spec.Metadata.Tool.Name = "syft"
	wipSbom.Spec.Metadata.Tool.Version = s.version
}

func (s *SbomManager) resetHostSbomCounters(sbomName string) {
	s.failureRetries.Remove(sbomName)
	s.crashLoopRetries.Remove(sbomName)
	s.hostSidecarFailures = 0
}

func (s *SbomManager) saveHostSbom(wipSbom *v1beta1.SBOMSyft, sbomName, hostID string) {
	if _, err := s.storageClient.ReplaceSBOM(wipSbom); err != nil {
		logger.L().Ctx(s.ctx).Error("SbomManager - failed to save host SBOM",
			helpers.Error(err),
			helpers.String("sbomName", sbomName))
		return
	}
	logger.L().Debug("SbomManager - saved host SBOM after successful processing",
		helpers.String("sbomName", sbomName),
		helpers.String("hostID", hostID))
}

// prepareHostSbom reserves the host SBOM slot and decides whether this scan
// should proceed, returning the object to fill in, whether it already carried
// real content, and the go/no-go.
//
// TooLarge interaction (explicit decision): a TooLarge trip does NOT permanently
// stop the rescan ticker -- the loop keeps ticking -- but it DOES cause each
// subsequent rescan to return here without scanning, for as long as the
// conditions that produced it are unchanged. It is released when either
// cfg.MaxSBOMSize (recorded via HostMaxSBOMSizeAnnotation) or the Syft tool
// version changes. This is host's own analogue of the container path's two
// escape hatches (a Syft tool-version bump or a change to the sidecar's
// scanner-memory-limit annotation) rather than a literal reuse of them: what
// marks a host SBOM TooLarge is always cfg.MaxSBOMSize, on both the in-process
// and the sidecar path, so that is its size-based escape hatch -- not the
// sidecar's scanner memory limit, which gates a different thing entirely.
//
// The tool-version half stays keyed on node-agent's OWN s.version even when the
// sidecar produced the scan. That is not an oversight: this annotation is
// written in prepareHostSbom, BEFORE the scan that would report a version even
// runs, so a sidecar-reported version could not participate in this condition
// even if the response carried one. Both binaries resolve the same Syft version
// from the same go.mod, so the two agree in any real deployment. The accepted
// consequence is that bumping Syft in the sidecar alone would not release a
// stuck TooLarge host SBOM; node-agent's own version (which ships in the same
// image) must change too.
//
// The alternative (rescan unconditionally) was rejected: TooLarge is a one-way
// door in the storage layer -- GuaranteedUpdate silently drops every write once
// status=too-large is set -- so an unconditional rescan would burn a full
// host-root filesystem walk every interval and then throw the result away.
func (s *SbomManager) prepareHostSbom(sbomName, hostID string) (*v1beta1.SBOMSyft, bool, bool) {
	wipSbom := &v1beta1.SBOMSyft{
		Name: sbomName,
		Annotations: map[string]string{
			helpersv1.StatusMetadataKey:      helpersv1.Initializing,
			NodeNameMetadataKey:              s.cfg.NodeName,
			helpersv1.ToolVersionMetadataKey: s.version,
		},
		Labels: hostSbomLabels(hostID),
	}
	created, err := s.storageClient.CreateSBOM(wipSbom)
	switch {
	case k8serrors.IsAlreadyExists(err):
		existing, getErr := s.storageClient.GetSBOMMeta(sbomName)
		if getErr != nil {
			logger.L().Ctx(s.ctx).Error("SbomManager - failed to get existing host SBOM metadata",
				helpers.Error(getErr),
				helpers.String("sbomName", sbomName))
			return nil, false, false
		}
		if s.processing.Contains(sbomName) {
			logger.L().Debug("SbomManager - host SBOM is already being processed, skipping",
				helpers.String("sbomName", sbomName))
			return nil, false, false
		}
		if existing.Annotations == nil {
			existing.Annotations = map[string]string{}
		}
		switch existing.Annotations[helpersv1.StatusMetadataKey] {
		case helpersv1.TooLarge:
			if !s.hostTooLargeReleased(existing) {
				logger.L().Debug("SbomManager - host SBOM previously too large, skipping rescan",
					helpers.String("sbomName", sbomName))
				return nil, false, false
			}
			logger.L().Debug("SbomManager - host SBOM too-large conditions changed, rescanning",
				helpers.String("sbomName", sbomName))
			fallthrough
		default:
			// Initializing, an interrupted run, or a TooLarge SBOM whose
			// blocking conditions have just changed (fallthrough above):
			// neither case ever retained content (TooLarge always clears
			// Spec, see the hadContent==false write path), so hadContent
			// stays false.
			existing.Annotations[helpersv1.ToolVersionMetadataKey] = s.version
			return existing, false, true
		case helpersv1.Incomplete:
			// Incomplete is AMBIGUOUS, unlike Learning below: handleGenericFailure
			// sets it via an annotation-only patch (markSBOMStatus never touches
			// Spec) after repeated scan failures, which fires whether or not this
			// SBOM ever completed a scan. So it covers two different cases: an
			// SBOM that never had content (every attempt failed before a size
			// could be computed), and one that previously had good or oversized
			// content preserved from before the failures started (the
			// hadContent==true write-path below only sets Incomplete, never
			// clears Spec). Assuming either answer unconditionally is wrong: always
			// true would let a content-less SBOM dodge TooLarge forever; always
			// false would wipe genuinely retained content via the TooLarge branch
			// on the next oversized scan. ResourceSizeMetadataKey is set exactly
			// once a scan actually completes (success or oversized) and is never
			// cleared by markSBOMStatus, so its presence reliably distinguishes
			// the two.
			hadContent := existing.Annotations[helpersv1.ResourceSizeMetadataKey] != ""
			existing.Annotations[helpersv1.ToolVersionMetadataKey] = s.version
			return existing, hadContent, true
		case helpersv1.Learning:
			// Unlike the container path -- which skips a completed SBOM unless
			// the tool version changed -- the host SBOM is meant to track a
			// mutating, long-lived filesystem, so a completed SBOM is exactly
			// what the rescan ticker exists to refresh. Learning is reached only
			// via a successful, under-budget scan, so it unambiguously had
			// content.
			existing.Annotations[helpersv1.ToolVersionMetadataKey] = s.version
			return existing, true, true
		}
	case err != nil:
		logger.L().Ctx(s.ctx).Error("SbomManager - failed to create empty host SBOM before processing",
			helpers.Error(err),
			helpers.String("sbomName", sbomName))
		return nil, false, false
	default:
		return created, false, true
	}
}

// hostTooLargeReleased reports whether the conditions that produced a TooLarge
// host SBOM have changed since it was recorded.
func (s *SbomManager) hostTooLargeReleased(existing *v1beta1.SBOMSyft) bool {
	if existing.Annotations[helpersv1.ToolVersionMetadataKey] != s.version {
		return true
	}
	recordedLimit := existing.Annotations[HostMaxSBOMSizeAnnotation]
	return recordedLimit != "" && s.cfg.MaxSBOMSize > 0 && recordedLimit != fmt.Sprintf("%d", s.cfg.MaxSBOMSize)
}

// hostSbomLabels builds the host SBOM's labels from the host identity. The
// container path's labelsFromImageID is unusable here: it parses an image
// reference, and a host has none.
func hostSbomLabels(hostID string) map[string]string {
	// Both label values get the same collision-resistant suffix as
	// hostSbomName: without it, two distinct node identities that sanitize
	// to the same base (e.g. "node.a"/"node-a") would produce identical
	// label values, so a label-based lookup for one node's SBOM could match
	// the other's even though their CR names (hostSbomName) are unique.
	identifier := collisionResistantLabel("", hostID)
	labels := map[string]string{
		HostSbomNameLabelKey: identifier,
		NodeNameMetadataKey:  identifier,
	}
	for key, value := range labels {
		if errs := validation.IsDNS1123Label(value); len(errs) != 0 {
			delete(labels, key)
		}
	}
	return labels
}

// cpuLimitMillisEnvVar carries this container's own declared CPU limit, in
// integer millicores, supplied by the chart via the Kubernetes downward API
// (resourceFieldRef: {resource: limits.cpu, divisor: "1m"}).
//
// The downward API is used deliberately in preference to reading the cgroup
// CPU quota directly: node-agent bind-mounts the HOST's /sys/fs/cgroup over
// its own (see pkg/metricsmanager/otel/resource_metrics.go, which had to build
// container-scope cgroup resolution for exactly this reason), so a naive
// root-level cgroup read inside this container returns the node's quota, not
// the container's -- and its failure direction is invisible: it falls back to
// runtime.NumCPU(), i.e. exactly the unbounded behaviour the cap exists to
// prevent. resourceFieldRef is resolved by kubelet at pod-admission time from
// the container's own spec and is immune to that trap entirely.
const cpuLimitMillisEnvVar = "CPU_LIMIT_MILLIS"

// parallelismFromCPULimitMillis converts a CPU_LIMIT_MILLIS value into a Syft
// cataloger parallelism. See syftutil.ParallelismFromCPULimitMillis for the
// full rationale (downward API vs. cgroup read, and why the vendored fork's
// uncapped default is NumCPU()*4 rather than NumCPU()).
//
// The logic lives in syftutil because the sbom-scanner sidecar applies the
// identical cap to its own scans from a different package; this wrapper keeps
// the host path's call sites and tests reading naturally.
func parallelismFromCPULimitMillis(raw string) (int, bool) {
	return syftutil.ParallelismFromCPULimitMillis(raw)
}

// resolveHostScanParallelism uses a positive config override, then the
// container's CPU limit, then serial scanning. Missing or invalid CPU limits
// must not restore host-wide parallelism in a CPU-constrained container.
func (s *SbomManager) resolveHostScanParallelism() int {
	if s.cfg.HostSbomScanParallelism > 0 {
		return s.cfg.HostSbomScanParallelism
	}
	if n, ok := parallelismFromCPULimitMillis(os.Getenv(cpuLimitMillisEnvVar)); ok {
		return n
	}
	if s.cfg.EnableSbomGeneration && s.cfg.HostMonitoringEnabled {
		logger.L().Warning("SbomManager - CPU_LIMIT_MILLIS missing or invalid, host SBOM scan falls back to serial parallelism",
			helpers.String("envVar", cpuLimitMillisEnvVar),
			helpers.Int("parallelism", 1))
	}
	return 1
}

// hostSbomConfig mirrors the container in-process fallback's Syft configuration
// (same cataloger removals, same embedded-SBOM opt-in) so host and container
// SBOMs are produced by comparable tooling.
//
// parallelism is resolved by the caller (resolveHostScanParallelism) rather
// than here: this function is package-level and has no access to s.cfg or the
// environment.
func hostSbomConfig(version string, embeddedSboms bool, parallelism int) *syft.CreateSBOMConfig {
	cfg := syft.DefaultCreateSBOMConfig()
	cfg.ToolName = "syft"
	cfg.ToolVersion = version
	cfg = cfg.WithCatalogerSelection(
		cataloging.NewSelectionRequest().WithRemovals(
			"file-digest-cataloger",
			"file-metadata-cataloger",
			"file-executable-cataloger",
		),
	)
	// The vendored Syft fork resolves 0 to runtime.NumCPU()*4; an explicit
	// value here is what bounds the scan to this container's CPU quota.
	cfg = cfg.WithParallelism(parallelism)
	if embeddedSboms {
		cfg.WithCatalogers(pkgcataloging.NewCatalogerReference(sbomcataloger.NewCataloger(), []string{pkgcataloging.ImageTag}))
	}
	return cfg
}
