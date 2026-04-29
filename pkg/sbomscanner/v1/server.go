package v1

import (
	"context"
	"encoding/json"
	"errors"
	"runtime/debug"
	"sync"
	"time"

	"github.com/anchore/syft/syft"
	"github.com/anchore/syft/syft/cataloging"
	"github.com/anchore/syft/syft/cataloging/pkgcataloging"
	sbomcataloger "github.com/anchore/syft/syft/pkg/cataloger/sbom"
	"github.com/kubescape/go-logger"
	"github.com/kubescape/go-logger/helpers"
	"github.com/kubescape/node-agent/pkg/sbommanager/v1/syftutil"
	pb "github.com/kubescape/node-agent/pkg/sbomscanner/v1/proto"
	"github.com/kubescape/storage/pkg/apis/softwarecomposition/v1beta1"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
	runtime "k8s.io/cri-api/pkg/apis/runtime/v1"
)

type scannerServer struct {
	pb.UnimplementedSBOMScannerServer
	mu      sync.Mutex // single-client sidecar; a context-aware semaphore is unnecessary here
	version string
}

func NewScannerServer() pb.SBOMScannerServer {
	return &scannerServer{
		version: packageVersion("github.com/anchore/syft"),
	}
}

func (s *scannerServer) CreateSBOM(ctx context.Context, req *pb.CreateSBOMRequest) (*pb.CreateSBOMResponse, error) {
	s.mu.Lock()
	defer s.mu.Unlock()

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
			return nil, status.Error(codes.FailedPrecondition, "image size exceeds maximum allowed size")
		}
		return nil, status.Errorf(codes.Internal, "failed to create image source: %v", err)
	}

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
	if req.EnableEmbeddedSboms {
		cfg.WithCatalogers(pkgcataloging.NewCatalogerReference(sbomcataloger.NewCataloger(), []string{pkgcataloging.ImageTag}))
	}

	syftSBOM, err := syft.CreateSBOM(ctx, src, cfg)
	if err != nil {
		if ctx.Err() == context.Canceled {
			return nil, status.Error(codes.Canceled, "scan canceled")
		}
		if ctx.Err() == context.DeadlineExceeded {
			return nil, status.Error(codes.DeadlineExceeded, "scan timed out")
		}
		return nil, status.Errorf(codes.Internal, "failed to generate SBOM: %v", err)
	}

	v1beta1.StripSBOM(syftSBOM)
	doc := syftutil.ToSyftDocument(syftSBOM)

	docBytes, err := json.Marshal(doc)
	if err != nil {
		return nil, status.Errorf(codes.Internal, "failed to serialize SBOM: %v", err)
	}

	logger.L().Info("SBOM scan completed",
		helpers.String("imageTag", req.ImageTag),
		helpers.Int("sbomSize", len(docBytes)))

	return &pb.CreateSBOMResponse{
		SbomDocument: docBytes,
		SbomSize:     int64(len(docBytes)),
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
