package v1

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"os"
	"strconv"
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

// HostMaxSBOMSizeAnnotation records cfg.MaxSBOMSize at the time a host SBOM
// was marked TooLarge, so hostTooLargeReleased can detect a later config
// change and release the block. It is a dedicated key, not
// ScannerMemoryLimitAnnotation: that annotation records the sidecar
// scanner's memory limit, which never applies to the host branch (host
// always scans in-process with Syft, never via the sidecar) -- recording it
// here would mean cfg.MaxSBOMSize, the value that actually gates the host
// size check, could never unblock a stuck TooLarge host SBOM.
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
			wipSbom.Annotations[HostMaxSBOMSizeAnnotation] = fmt.Sprintf("%d", s.cfg.MaxSBOMSize)
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
// conditions that produced it are unchanged. It is released when either
// cfg.MaxSBOMSize (recorded via HostMaxSBOMSizeAnnotation) or the Syft tool
// version changes. This is host's own analogue of the container path's two
// escape hatches (a Syft tool-version bump or a change to the sidecar's
// scanner-memory-limit annotation) rather than a literal reuse of them: host
// always scans in-process (it has no sidecar), so its size-based escape hatch
// is cfg.MaxSBOMSize, not the sidecar's scanner memory limit.
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
// cataloger parallelism. The bool reports whether the raw value was usable;
// false means the caller must take the serial fallback (see
// resolveHostScanParallelism), and is returned rather than silently folding
// the fallback in here so the fallback branch itself is directly testable.
//
// Whole CPUs are used (integer division): 394m -> 0 -> clamped to 1, 1000m ->
// 1, 2500m -> 2. n==1 is passed to Syft as parallelism 1, which the vendored
// fork (github.com/kubescape/syft, see go.mod's replace directive) special-
// cases to mean fully serial, no cataloger goroutines at all -- stronger than
// "one goroutine". This matters because that fork's default (parallelism 0)
// is NOT runtime.NumCPU(): syft/create_sbom.go resolves 0 to
// runtime.NumCPU()*4, so on an 8-CPU node a 394m container would schedule
// cataloger work across 32 goroutines against a quota of well under half a
// CPU -- 4x worse than the naive "NumCPU()" story suggests -- and get
// CFS-throttled hard enough to starve node-agent's own liveness endpoint.
func parallelismFromCPULimitMillis(raw string) (int, bool) {
	millis, err := strconv.Atoi(strings.TrimSpace(raw))
	if err != nil || millis <= 0 {
		return 0, false
	}
	n := millis / 1000
	if n < 1 {
		n = 1
	}
	return n, true
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
