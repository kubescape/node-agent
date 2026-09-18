package v1

import (
	"context"
	"errors"
	"fmt"
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
	"github.com/kubescape/node-agent/pkg/sbommanager/v1/syftutil"
	"github.com/kubescape/storage/pkg/apis/softwarecomposition/v1beta1"
	k8serrors "k8s.io/apimachinery/pkg/api/errors"
	"k8s.io/apimachinery/pkg/util/validation"
)

// HostSbomNameLabelKey labels the host SBOM with the node it describes, since
// none of the image-derived labels (image ID/name/tag) apply to a host.
const HostSbomNameLabelKey = "kubescape.io/host"

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
func hostSbomName(hostID string) string {
	return "host-" + sanitize(strings.ToLower(hostID))
}

// processHostSbom generates (or regenerates) the host's SBOM.
//
// It shares no code with processContainerWithMetadata by design: there is no
// imageStatus to marshal, no layer paths to hand to the scanner sidecar (whose
// ScanRequest is image-shaped: ImageID/ImageTag/LayerPaths/ImageStatus), and no
// image digest to report failures against. The host therefore always scans
// in-process with Syft over a directory source.
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

	scanStart := time.Now()
	src, err := syftutil.NewHostSource(s.hostFSPrefix, sbomName, s.version)
	if err != nil {
		logger.L().Ctx(s.ctx).Error("SbomManager - failed to create host directory source",
			helpers.Error(err),
			helpers.String("path", s.hostFSPrefix),
			helpers.String("sbomName", sbomName))
		s.handleGenericFailure(sbomName)
		return
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
	scanCtx, scanCancel := context.WithTimeout(s.ctx, timeout)
	syftSBOM, err := scanFn(scanCtx, src, hostSbomConfig(s.version, s.cfg.EnableEmbeddedSboms))
	scanCancel()
	if err != nil {
		scanDuration := time.Since(scanStart)
		if errors.Is(err, context.DeadlineExceeded) {
			s.metrics.ReportSBOMScan("timeout")
			s.metrics.ObserveSBOMScanDuration("timeout", scanDuration)
			logger.L().Ctx(s.ctx).Error("SbomManager - host SBOM scan timed out",
				helpers.Error(err),
				helpers.String("sbomName", sbomName),
				helpers.String("timeout", timeout.String()))
		} else {
			s.metrics.ReportSBOMScan("error")
			s.metrics.ObserveSBOMScanDuration("error", scanDuration)
			logger.L().Ctx(s.ctx).Error("SbomManager - failed to generate host SBOM",
				helpers.Error(err),
				helpers.String("sbomName", sbomName))
		}
		// handleGenericFailure/processing.Remove (deferred above) both run
		// regardless of the failure's cause, so a timeout -- like any other
		// scan error -- clears the in-flight marker and leaves the SBOM in a
		// retryable status (Incomplete once maxScanRetries is reached,
		// otherwise unchanged), letting the next rescan tick try again
		// instead of being permanently stuck.
		s.handleGenericFailure(sbomName)
		return
	}
	s.metrics.ReportSBOMScan("success")
	s.metrics.ObserveSBOMScanDuration("success", time.Since(scanStart))
	v1beta1.StripSBOM(syftSBOM)

	s.failureRetries.Remove(sbomName)
	s.crashLoopRetries.Remove(sbomName)
	delete(wipSbom.Annotations, NodeNameMetadataKey)
	wipSbom.Spec.Metadata.Report.CreatedAt = wipSbom.CreationTimestamp
	wipSbom.Spec.Metadata.Tool.Name = "syft"
	wipSbom.Spec.Metadata.Tool.Version = s.version
	wipSbom.Spec.Syft = syftutil.ToSyftDocument(syftSBOM)

	sz := size.Of(wipSbom)
	wipSbom.Annotations[helpersv1.ResourceSizeMetadataKey] = fmt.Sprintf("%d", sz)
	if sz > s.cfg.MaxSBOMSize {
		logger.L().Debug("SbomManager - host SBOM exceeds size limit",
			helpers.String("sbomName", sbomName),
			helpers.Int("maxSBOMSize", s.cfg.MaxSBOMSize),
			helpers.Int("size", sz))
		// TooLarge is a one-way door in the storage layer, so a host SBOM that
		// already carries real content must never be pushed through it -- the
		// same rule the container path applies via wipSbomHadContent.
		if hadContent {
			wipSbom.Annotations[helpersv1.StatusMetadataKey] = helpersv1.Incomplete
		} else {
			wipSbom.Annotations[helpersv1.StatusMetadataKey] = helpersv1.TooLarge
			wipSbom.Annotations[ScannerMemoryLimitAnnotation] = fmt.Sprintf("%d", s.scannerMemLimit)
			wipSbom.Spec = v1beta1.SBOMSyftSpec{}
		}
	} else {
		wipSbom.Annotations[helpersv1.StatusMetadataKey] = helpersv1.Learning
	}

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
// conditions that produced it are unchanged. It is released when either the
// scanner memory limit or the Syft tool version changes, which are exactly the
// two escape hatches the container path already honours.
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
	recordedLimit := existing.Annotations[ScannerMemoryLimitAnnotation]
	return recordedLimit != "" && s.scannerMemLimit > 0 && recordedLimit != fmt.Sprintf("%d", s.scannerMemLimit)
}

// hostSbomLabels builds the host SBOM's labels from the host identity. The
// container path's labelsFromImageID is unusable here: it parses an image
// reference, and a host has none.
func hostSbomLabels(hostID string) map[string]string {
	labels := map[string]string{
		HostSbomNameLabelKey: sanitize(strings.ToLower(hostID)),
		NodeNameMetadataKey:  sanitize(strings.ToLower(hostID)),
	}
	for key, value := range labels {
		if errs := validation.IsDNS1123Label(value); len(errs) != 0 {
			delete(labels, key)
		}
	}
	return labels
}

// hostSbomConfig mirrors the container in-process fallback's Syft configuration
// (same cataloger removals, same embedded-SBOM opt-in) so host and container
// SBOMs are produced by comparable tooling.
func hostSbomConfig(version string, embeddedSboms bool) *syft.CreateSBOMConfig {
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
	if embeddedSboms {
		cfg.WithCatalogers(pkgcataloging.NewCatalogerReference(sbomcataloger.NewCataloger(), []string{pkgcataloging.ImageTag}))
	}
	return cfg
}
