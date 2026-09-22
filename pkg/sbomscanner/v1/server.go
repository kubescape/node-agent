package v1

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	gort "runtime"
	"runtime/debug"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/anchore/syft/syft"
	"github.com/anchore/syft/syft/cataloging"
	"github.com/anchore/syft/syft/cataloging/pkgcataloging"
	sbomcataloger "github.com/anchore/syft/syft/pkg/cataloger/sbom"
	"github.com/anchore/syft/syft/sbom"
	"github.com/anchore/syft/syft/source"
	"github.com/kubescape/go-logger"
	"github.com/kubescape/go-logger/helpers"
	"github.com/kubescape/node-agent/pkg/otelsetup"
	"github.com/kubescape/node-agent/pkg/sbommanager/v1/syftutil"
	pb "github.com/kubescape/node-agent/pkg/sbomscanner/v1/proto"
	"github.com/kubescape/storage/pkg/apis/softwarecomposition/v1beta1"
	"go.opentelemetry.io/otel/attribute"
	otelcodes "go.opentelemetry.io/otel/codes"
	"go.opentelemetry.io/otel/trace"
	"golang.org/x/sync/semaphore"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
	runtime "k8s.io/cri-api/pkg/apis/runtime/v1"
)

const (
	// admissionWindow bounds how long a request may WAIT for the single scan
	// slot, as opposed to how long its scan may RUN (which stays the request's
	// own timeout_seconds, up to 16 minutes).
	//
	// The two budgets are deliberately separate. Acquiring on the request's own
	// deadline would be behaviourally identical to the sync.Mutex this replaced
	// -- a caller would simply block for up to its full scan budget -- and would
	// therefore not bound queueing at all. Acquiring with TryAcquire (no wait)
	// would go too far the other way: the container path's existing, shipped
	// behaviour under contention is "blocks, eventually succeeds", and turning
	// every momentary overlap into a reported failure would regress it. A short
	// wait absorbs normal overlap; exceeding it yields ErrScannerBusy, which
	// both callers treat as "retry soon", never as a scan failure.
	//
	// Exported as AdmissionWindow so callers (host_sbom.go's ScanHostFilesystem
	// call) can size their OWN request context to timeout+AdmissionWindow,
	// not just timeout -- otherwise a scan admitted late (having spent up to
	// this long queueing before the server even starts its own
	// timeout_seconds clock) could still be killed client-side exactly at the
	// scan timeout, before the server's own deadline, misreporting a
	// legitimately-in-budget scan as a client timeout.
	admissionWindow = 45 * time.Second
	// AdmissionWindow is admissionWindow, exported for callers outside this
	// package that need to size a request deadline around it.
	AdmissionWindow = admissionWindow

	// hostScanTransferSafetyMargin is held back from MaxgRPCMessageSize when
	// deciding whether a host document can be sent. The serialized document is
	// not the whole gRPC frame (there is protobuf framing and field overhead
	// around it), so sizing the check at exactly the limit would let a document
	// pass the check and still be rejected by the transport -- which is the
	// undistinguishable generic failure this check exists to avoid.
	hostScanTransferSafetyMargin = 4 * 1024 * 1024
	maxTransferableDocumentSize  = MaxgRPCMessageSize - hostScanTransferSafetyMargin

	// scannerBusyStatusMarker is embedded in the ResourceExhausted status
	// message for an admission-window timeout. gRPC itself also returns
	// ResourceExhausted for its own message-size limits, so the code alone
	// cannot distinguish "the sidecar is busy" from "the transport refused the
	// payload"; the marker does. Server and client share this constant, so the
	// two ends cannot drift.
	scannerBusyStatusMarker = "sbom-scanner: admission window exhausted"

	// hostDocTooLargeStatusPrefix is the machine-readable prefix of the
	// OutOfRange status returned when a host document is produced but cannot be
	// transferred. The measured byte count follows it, and the client parses it
	// back out to stand in for size.Of on this path.
	hostDocTooLargeStatusPrefix = "sbom-scanner: host document too large to transfer: "

	// hostRootEnvVar is the sidecar's own view of the node root filesystem. It
	// is resolved here, in the sidecar, rather than accepted from the request:
	// node-agent and the sidecar resolve this variable independently, so a
	// mismatched mount would otherwise let the sidecar return a valid-looking
	// SBOM of the wrong filesystem.
	hostRootEnvVar      = "HOST_ROOT"
	defaultHostRoot     = "/host"
	cpuLimitMillisEnv   = "CPU_LIMIT_MILLIS"
	hostScanSourceScope = "host"
)

// hostRootMarkerDirs are the directories a plausible Linux host root must
// contain. These markers reject incomplete or unrelated directories, but do
// not establish host identity: container root filesystems have them too.
// resolveHostRoot separately rejects the scanner's own root filesystem.
var hostRootMarkerDirs = []string{"etc", "usr", "var"}

type scannerServer struct {
	pb.UnimplementedSBOMScannerServer
	// admission serialises scans across BOTH RPCs: a host root-filesystem walk
	// and a container image scan are the two heaviest things this process does,
	// and running them concurrently in a 1 CPU / 4Gi container is what the
	// shared slot exists to prevent. Weighted(1) is exactly sized, not
	// arbitrary: the maximum concurrency reaching this process is 2 -- the
	// node-agent worker pool's single container-scan worker, plus the host
	// scan's own goroutine.
	//
	// It replaced a sync.Mutex specifically because a mutex cannot express a
	// bounded wait: see admissionWindow for why waiting is bounded separately
	// from scanning.
	admission *semaphore.Weighted
	version   string
	// admissionTimeout is admissionWindow in production. It is a field purely
	// so tests can compress the window; the admission-contention behaviour it
	// governs is otherwise unobservable in a unit test.
	admissionTimeout time.Duration

	// hostRootMu/hostRootResolved/hostRoot memoise HOST_ROOT resolution and
	// validation, so the resolved path is logged exactly once rather than on
	// every rescan, while still being resolved lazily (the env var is read at
	// first use, which keeps NewScannerServer free of I/O and testable).
	//
	// This is deliberately a mutex-guarded bool, not sync.Once: a host scan
	// runs at most once per HostSBOMRescanInterval (24h by default), so a
	// single transient stat failure (a mount not yet settled, a slow
	// CSI-backed /host, an EIO) memoised by Once would permanently disable
	// host offload for the sidecar's entire lifetime -- costing a day or more
	// of host SBOM coverage for a condition that may no longer hold on the
	// very next call. Only a SUCCESSFUL resolution is memoised; a failure is
	// re-attempted on every call.
	hostRootMu       sync.Mutex
	hostRootResolved bool
	hostRoot         string

	// hostScanFn is a test seam replacing the real syft.CreateSBOM for the host
	// RPC. Nil in production.
	hostScanFn func(ctx context.Context, src source.Source, cfg *syft.CreateSBOMConfig) (*sbom.SBOM, error)
	// hostDocumentSizeOverride, when non-zero, replaces the measured document
	// length in the transfer-budget check. Test seam: producing a genuinely
	// >124MB document in a unit test is not practical.
	hostDocumentSizeOverride int
}

// realCreateSBOM is the production scan function the hostScanFn test seam
// replaces.
var realCreateSBOM = syft.CreateSBOM

func NewScannerServer() pb.SBOMScannerServer {
	return newScannerServer()
}

func newScannerServer() *scannerServer {
	return &scannerServer{
		admission:        semaphore.NewWeighted(1),
		version:          packageVersion("github.com/anchore/syft"),
		admissionTimeout: admissionWindow,
	}
}

// acquireAdmission waits up to admissionWindow for the single scan slot.
//
// The admission context is derived from ctx (so a client that goes away stops
// the wait immediately) but carries its own, much shorter deadline, so a
// caller with a 16-minute scan budget still learns within ~45s that the sidecar
// is occupied instead of silently queueing for the whole budget.
func (s *scannerServer) acquireAdmission(ctx context.Context) error {
	admCtx, cancel := context.WithTimeout(ctx, s.admissionTimeout)
	defer cancel()
	if err := s.admission.Acquire(admCtx, 1); err != nil {
		// Distinguish "the caller went away" from "we could not admit in time":
		// only the latter is ErrScannerBusy. Checking the PARENT ctx is what
		// makes this distinction, since admCtx expiring is the busy case.
		if ctx.Err() != nil {
			return contextStatusError(ctx)
		}
		return status.Errorf(codes.ResourceExhausted, "%s after %s: %v", scannerBusyStatusMarker, s.admissionTimeout, err)
	}
	return nil
}

func contextStatusError(ctx context.Context) error {
	if errors.Is(ctx.Err(), context.DeadlineExceeded) {
		return status.Error(codes.DeadlineExceeded, "scan timed out")
	}
	return status.Error(codes.Canceled, "scan canceled")
}

// resolveHostRoot validates the sidecar's own HOST_ROOT, caching and logging
// the first successful result. Failed validation is retried on the next call.
//
// Validation is a hard precondition rather than a warning: silently scanning
// the wrong filesystem produces a structurally valid SBOM that describes the
// wrong machine, which no downstream consumer can detect.
func (s *scannerServer) resolveHostRoot() (string, error) {
	s.hostRootMu.Lock()
	defer s.hostRootMu.Unlock()

	if s.hostRootResolved {
		return s.hostRoot, nil
	}

	root := os.Getenv(hostRootEnvVar)
	if root == "" {
		root = defaultHostRoot
	}
	var err error
	info, statErr := os.Stat(root)
	switch {
	case statErr != nil:
		err = fmt.Errorf("host root %q is not accessible: %w", root, statErr)
	case !info.IsDir():
		err = fmt.Errorf("host root %q is not a directory", root)
	default:
		// Stat follows symlinks, and SameFile compares filesystem identity,
		// covering both path aliases and bind mounts of the scanner's root.
		containerRoot, rootErr := os.Stat("/")
		if rootErr != nil {
			err = fmt.Errorf("cannot validate host root %q against scanner root: %w", root, rootErr)
		} else if os.SameFile(info, containerRoot) {
			err = fmt.Errorf("host root %q is the scanner's own root filesystem", root)
		} else if missing := missingHostRootMarkers(root); len(missing) > 0 {
			err = fmt.Errorf("host root %q does not look like a node root filesystem (missing %s)",
				root, strings.Join(missing, ", "))
		}
	}
	if err != nil {
		// Deliberately NOT memoised: a transient condition (a mount not yet
		// settled, a slow CSI-backed /host, an EIO) must not permanently
		// disable host offload for this process's lifetime -- see the struct
		// field doc comment. Every call re-validates until one succeeds.
		logger.L().Error("sbom-scanner: host root validation failed",
			helpers.Error(err),
			helpers.String("hostRoot", root))
		return "", err
	}

	s.hostRoot = root
	s.hostRootResolved = true
	logger.L().Info("sbom-scanner: host root resolved", helpers.String("hostRoot", root))
	return root, nil
}

func missingHostRootMarkers(root string) []string {
	var missing []string
	for _, marker := range hostRootMarkerDirs {
		info, err := os.Stat(filepath.Join(root, marker))
		if err != nil || !info.IsDir() {
			missing = append(missing, "/"+marker)
		}
	}
	return missing
}

// scanParallelism bounds Syft's cataloger parallelism to this container's own
// declared CPU limit, read from CPU_LIMIT_MILLIS (supplied by the chart via the
// Kubernetes downward API).
//
// The sidecar's cgroup topology would in fact permit a direct cgroup read --
// unlike node-agent, it does not bind-mount the host's /sys/fs/cgroup -- but
// the downward API is used in both processes so there is one quota-detection
// mechanism to reason about, not two.
func scanParallelism() int {
	if n, ok := syftutil.ParallelismFromCPULimitMillis(os.Getenv(cpuLimitMillisEnv)); ok {
		return n
	}
	// Older charts and custom manifests may omit the limit. Keep both host
	// and image scans serial rather than using the host's CPU count.
	logger.L().Warning("sbom-scanner: CPU_LIMIT_MILLIS missing or invalid, scan falls back to serial parallelism",
		helpers.String("envVar", cpuLimitMillisEnv),
		helpers.Int("parallelism", 1))
	return 1
}

// scanConfig builds the Syft configuration shared by both RPCs.
func (s *scannerServer) scanConfig(enableEmbeddedSboms bool) *syft.CreateSBOMConfig {
	cfg := syft.DefaultCreateSBOMConfig()
	cfg.ToolName = "syft"
	cfg.ToolVersion = s.version
	cfg = cfg.WithCatalogerSelection(
		cataloging.NewSelectionRequest().WithRemovals(
			"file-digest-cataloger",
			"file-metadata-cataloger",
			"file-executable-cataloger",
		),
	)
	// The vendored Syft fork resolves parallelism 0 to runtime.NumCPU()*4, so
	// leaving it unset would schedule cataloger work far beyond this 1-CPU
	// container's quota and CFS-throttle the whole sidecar.
	cfg = cfg.WithParallelism(scanParallelism())
	if enableEmbeddedSboms {
		cfg.WithCatalogers(pkgcataloging.NewCatalogerReference(sbomcataloger.NewCataloger(), []string{pkgcataloging.ImageTag}))
	}
	return cfg
}

// scanAndSerialize is the body shared by CreateSBOM and ScanHostFilesystem:
// config construction, allocation instrumentation, the OTEL span, the Syft
// scan, error mapping, stripping, document conversion and serialization.
//
// Everything above it (request validation, source construction) and below it
// (transfer-budget checks, response shaping) differs between the two RPCs;
// everything here is identical, so both paths necessarily produce comparable
// documents from comparable configuration.
func (s *scannerServer) scanAndSerialize(ctx context.Context, src source.Source, enableEmbeddedSboms bool, spanAttrs []attribute.KeyValue) ([]byte, error) {
	cfg := s.scanConfig(enableEmbeddedSboms)

	var memBefore, memAfter gort.MemStats
	gort.ReadMemStats(&memBefore)

	scanCtx, scanSpan := otelsetup.Tracer().Start(ctx, "sbom.scan", trace.WithAttributes(spanAttrs...))
	scanFn := realCreateSBOM
	if s.hostScanFn != nil {
		scanFn = s.hostScanFn
	}
	syftSBOM, err := scanFn(scanCtx, src, cfg)
	gort.ReadMemStats(&memAfter)
	// TotalAlloc is monotonically increasing (cumulative bytes allocated),
	// so the delta is always ≥ 0 even when GC runs mid-scan.
	totalBefore := float64(memBefore.TotalAlloc) / (1024 * 1024)
	totalAfter := float64(memAfter.TotalAlloc) / (1024 * 1024)
	scanSpan.SetAttributes(
		attribute.Float64("alloc.total.before_mb", totalBefore),
		attribute.Float64("alloc.total.after_mb", totalAfter),
		attribute.Float64("alloc.total.delta_mb", totalAfter-totalBefore),
	)
	if err != nil {
		scanSpan.SetStatus(otelcodes.Error, err.Error())
	}
	scanSpan.End()
	if err != nil {
		if ctx.Err() != nil {
			return nil, contextStatusError(ctx)
		}
		return nil, status.Errorf(codes.Internal, "failed to generate SBOM: %v", err)
	}

	v1beta1.StripSBOM(syftSBOM)
	doc := syftutil.ToSyftDocument(syftSBOM)

	docBytes, err := json.Marshal(doc)
	if err != nil {
		return nil, status.Errorf(codes.Internal, "failed to serialize SBOM: %v", err)
	}
	return docBytes, nil
}

func (s *scannerServer) CreateSBOM(ctx context.Context, req *pb.CreateSBOMRequest) (*pb.CreateSBOMResponse, error) {
	if err := s.acquireAdmission(ctx); err != nil {
		return nil, err
	}
	defer s.admission.Release(1)

	if req.TimeoutSeconds > 0 {
		var cancel context.CancelFunc
		ctx, cancel = context.WithTimeout(ctx, time.Duration(req.TimeoutSeconds)*time.Second)
		defer cancel()
	}

	var imageStatus runtime.ImageStatusResponse
	if err := json.Unmarshal(req.ImageStatus, &imageStatus); err != nil {
		return nil, status.Errorf(codes.InvalidArgument, "invalid image_status: %v", err)
	}

	src, err := syftutil.NewSource(req.ImageTag, req.ImageId, req.ImageId, &imageStatus, req.LayerPaths, req.MaxImageSize)
	if err != nil {
		if errors.Is(err, syftutil.ErrImageTooLarge) {
			return nil, status.Error(codes.FailedPrecondition, ErrImageTooLarge.Error())
		}
		return nil, status.Errorf(codes.Internal, "failed to create image source: %v", err)
	}

	docBytes, err := s.scanAndSerialize(ctx, src, req.EnableEmbeddedSboms, []attribute.KeyValue{
		attribute.String("image.tag", req.ImageTag),
		attribute.String("image.id", req.ImageId),
	})
	if err != nil {
		return nil, err
	}

	logger.L().Info("SBOM scan completed",
		helpers.String("imageTag", req.ImageTag),
		helpers.Int("sbomSize", len(docBytes)))

	return &pb.CreateSBOMResponse{
		SbomDocument: docBytes,
		SbomSize:     int64(len(docBytes)),
	}, nil
}

// ScanHostFilesystem scans this sidecar's own view of the node root filesystem.
//
// It exists as a dedicated RPC rather than a variant of CreateSBOM because the
// two carry no request fields in common: there is no image, no layer set and no
// CRI status here, and conversely no source alias or host root there.
func (s *scannerServer) ScanHostFilesystem(ctx context.Context, req *pb.ScanHostFilesystemRequest) (*pb.ScanHostFilesystemResponse, error) {
	if req.SourceName == "" {
		return nil, status.Error(codes.InvalidArgument, "source_name is required")
	}

	// Validated BEFORE admission: a misconfigured host root is a permanent
	// precondition failure, and making the caller queue behind a 16-minute
	// image scan only to be told its configuration is wrong helps nobody.
	hostRoot, err := s.resolveHostRoot()
	if err != nil {
		return nil, status.Error(codes.FailedPrecondition, err.Error())
	}

	if err := s.acquireAdmission(ctx); err != nil {
		return nil, err
	}
	defer s.admission.Release(1)

	if req.TimeoutSeconds > 0 {
		var cancel context.CancelFunc
		ctx, cancel = context.WithTimeout(ctx, time.Duration(req.TimeoutSeconds)*time.Second)
		defer cancel()
	}

	src, err := syftutil.NewHostSource(hostRoot, req.SourceName, s.version)
	if err != nil {
		return nil, status.Errorf(codes.Internal, "failed to create host directory source: %v", err)
	}
	defer func() {
		_ = src.Close()
	}()

	logger.L().Info("sbom-scanner: starting host filesystem scan",
		helpers.String("sourceName", req.SourceName),
		helpers.String("hostRoot", hostRoot),
		helpers.Int("parallelism", scanParallelism()))

	docBytes, err := s.scanAndSerialize(ctx, src, req.EnableEmbeddedSboms, []attribute.KeyValue{
		attribute.String("host.root", hostRoot),
		attribute.String("source.name", req.SourceName),
		attribute.String("source.scope", hostScanSourceScope),
	})
	if err != nil {
		return nil, err
	}

	// Measured before the send is attempted, so an undeliverable document is
	// reported as a distinguishable, terminal condition the caller can map onto
	// the same TooLarge/Incomplete branch an oversized in-process scan reaches
	// -- rather than as an opaque transport error that would be retried (and
	// the whole root filesystem re-walked) on every rescan interval forever.
	size := len(docBytes)
	if s.hostDocumentSizeOverride > 0 {
		size = s.hostDocumentSizeOverride
	}
	if size > maxTransferableDocumentSize {
		logger.L().Warning("sbom-scanner: host SBOM too large to transfer",
			helpers.String("sourceName", req.SourceName),
			helpers.Int("sbomSize", size),
			helpers.Int("transferBudget", maxTransferableDocumentSize))
		return nil, status.Error(codes.OutOfRange, hostDocTooLargeStatusPrefix+strconv.Itoa(size))
	}

	logger.L().Info("sbom-scanner: host filesystem scan completed",
		helpers.String("sourceName", req.SourceName),
		helpers.Int("sbomSize", size))

	return &pb.ScanHostFilesystemResponse{
		SbomDocument: docBytes,
		SbomSize:     int64(size),
	}, nil
}

func (s *scannerServer) Health(_ context.Context, _ *pb.HealthRequest) (*pb.HealthResponse, error) {
	return &pb.HealthResponse{
		Version: s.version,
		Ready:   true,
	}, nil
}

func packageVersion(name string) string {
	bi, ok := debug.ReadBuildInfo()
	if ok {
		for _, dep := range bi.Deps {
			if dep.Path == name {
				return dep.Version
			}
		}
	}
	return "unknown"
}
