package v1

import (
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/kubescape/storage/pkg/apis/softwarecomposition/v1beta1"
)

var (
	ErrScannerCrashed  = errors.New("SBOM scanner sidecar crashed during scan")
	ErrScannerNotReady = errors.New("SBOM scanner sidecar not ready")
	ErrImageTooLarge   = errors.New("image size exceeds maximum allowed size")
	// ErrScannerBusy reports that the sidecar could not admit this scan within
	// the admission window -- another scan holds the single admission slot.
	//
	// It is emphatically NOT a scan failure: no scan work was dispatched, so
	// neither caller may route it through its failure/retry accounting
	// (reportFailure, failureRetries, crashLoopRetries, or the host path's
	// sidecar-failure counter). Both callers retry it under a short bounded
	// backoff instead; see busyRetryDelay in pkg/sbommanager/v1.
	ErrScannerBusy = errors.New("SBOM scanner sidecar busy")
	// ErrHostDocumentTooLargeToTransfer reports that a host SBOM was produced
	// successfully but its serialized form exceeds the gRPC transfer budget, so
	// the sidecar declined to send it.
	//
	// It exists so that an oversized host document reaches the SAME terminal
	// state via the sidecar as it would in-process: without it, the send would
	// fail as a generic transport error and the host path would re-walk the
	// whole root filesystem every rescan interval forever, which is exactly the
	// outcome the TooLarge state machine exists to prevent.
	ErrHostDocumentTooLargeToTransfer = errors.New("host SBOM document exceeds the gRPC transfer budget")
	// ErrScannerHostScanRejected reports a pre-dispatch rejection of a host scan
	// request (an invalid source_name, or a HOST_ROOT that does not resolve to a
	// plausible host filesystem). Like ErrScannerBusy, no scan work was
	// dispatched, so the caller may fall back in-process for this one cycle at
	// no double-scan cost -- unlike ErrScannerBusy, this is a configuration
	// defect, not transient contention, so the caller logs it at a level an
	// operator will notice rather than treating it as routine.
	ErrScannerHostScanRejected = errors.New("SBOM scanner sidecar rejected the host scan request before dispatch")
)

type ScanRequest struct {
	ImageID             string
	ImageTag            string
	LayerPaths          []string
	ImageStatus         []byte // serialized CRI ImageStatusResponse JSON
	MaxImageSize        int64
	MaxSBOMSize         int32
	EnableEmbeddedSBOMs bool
	Timeout             time.Duration
}

type ScanResult struct {
	SyftDocument v1beta1.SyftDocument
	SBOMSize     int64
}

// HostScanRequest is the host counterpart of ScanRequest. It carries none of
// the image-shaped fields (no image ID/tag, no layer paths, no CRI image
// status) and no root path: the sidecar resolves and validates its own
// HOST_ROOT. See ScanHostFilesystemRequest in the proto for why each omitted
// field is omitted.
type HostScanRequest struct {
	// SourceName is the Syft source alias name, i.e. the host SBOM's CR name.
	// The sidecar cannot derive it: it comes from the host identity only
	// node-agent resolves.
	SourceName          string
	EnableEmbeddedSBOMs bool
	Timeout             time.Duration
}

type HostScanResult struct {
	SyftDocument v1beta1.SyftDocument
	SBOMSize     int64
}

// HostDocumentTooLargeError carries the serialized size the sidecar measured
// before declining to send an oversized host document. The size is what the
// host path records in ResourceSizeMetadataKey and compares against
// cfg.MaxSBOMSize, standing in for size.Of(wipSbom) on this one path.
//
// It unwraps to ErrHostDocumentTooLargeToTransfer, so callers that only need
// the classification can use errors.Is and ignore the size.
type HostDocumentTooLargeError struct {
	Size int64
}

func (e *HostDocumentTooLargeError) Error() string {
	return fmt.Sprintf("%s: %d bytes", ErrHostDocumentTooLargeToTransfer.Error(), e.Size)
}

func (e *HostDocumentTooLargeError) Unwrap() error { return ErrHostDocumentTooLargeToTransfer }

type SBOMScannerClient interface {
	CreateSBOM(ctx context.Context, req ScanRequest) (*ScanResult, error)
	// ScanHostFilesystem scans the sidecar's own view of the node root
	// filesystem. It may return ErrScannerBusy (admission window exhausted, not
	// a scan failure) or a *HostDocumentTooLargeError (scan succeeded, document
	// undeliverable).
	ScanHostFilesystem(ctx context.Context, req HostScanRequest) (*HostScanResult, error)
	Ready() bool
	Close() error
}
