package v1

import (
	"context"
	"errors"
	"time"

	"github.com/kubescape/storage/pkg/apis/softwarecomposition/v1beta1"
)

var (
	ErrScannerCrashed  = errors.New("SBOM scanner sidecar crashed during scan")
	ErrScannerNotReady = errors.New("SBOM scanner sidecar not ready")
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

type SBOMScannerClient interface {
	CreateSBOM(ctx context.Context, req ScanRequest) (*ScanResult, error)
	Ready() bool
	Close() error
}
