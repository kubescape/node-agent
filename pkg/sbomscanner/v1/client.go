package v1

import (
	"context"
	"encoding/json"
	"fmt"
	"strconv"
	"strings"
	"time"

	"github.com/cenkalti/backoff/v5"
	"github.com/kubescape/go-logger"
	"github.com/kubescape/go-logger/helpers"
	pb "github.com/kubescape/node-agent/pkg/sbomscanner/v1/proto"
	"github.com/kubescape/storage/pkg/apis/softwarecomposition/v1beta1"
	"go.opentelemetry.io/contrib/instrumentation/google.golang.org/grpc/otelgrpc"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/credentials/insecure"
	grpcstats "google.golang.org/grpc/stats"
	"google.golang.org/grpc/status"
)

const (
	healthCheckTimeout = 5 * time.Second
	MaxgRPCMessageSize = 128 * 1024 * 1024
)

type sbomScannerClient struct {
	conn   *grpc.ClientConn
	client pb.SBOMScannerClient
}

func NewSBOMScannerClient(socketPath string) (SBOMScannerClient, error) {
	target := fmt.Sprintf("unix://%s", socketPath)
	conn, err := grpc.NewClient(target,
		grpc.WithTransportCredentials(insecure.NewCredentials()),
		grpc.WithStatsHandler(otelgrpc.NewClientHandler(
			otelgrpc.WithFilter(func(info *grpcstats.RPCTagInfo) bool {
				return info.FullMethodName != pb.SBOMScanner_Health_FullMethodName
			}),
		)),
		grpc.WithDefaultCallOptions(
			grpc.MaxCallRecvMsgSize(MaxgRPCMessageSize),
			grpc.MaxCallSendMsgSize(MaxgRPCMessageSize),
		),
	)
	if err != nil {
		return nil, fmt.Errorf("failed to create gRPC client: %w", err)
	}

	c := &sbomScannerClient{
		conn:   conn,
		client: pb.NewSBOMScannerClient(conn),
	}

	_, err = backoff.Retry(context.Background(), func() (struct{}, error) {
		ctx, cancel := context.WithTimeout(context.Background(), healthCheckTimeout)
		defer cancel()
		resp, err := c.client.Health(ctx, &pb.HealthRequest{})
		if err != nil {
			return struct{}{}, fmt.Errorf("health check failed: %w", err)
		}
		if !resp.Ready {
			return struct{}{}, fmt.Errorf("scanner not ready")
		}
		return struct{}{}, nil
	}, backoff.WithBackOff(backoff.NewExponentialBackOff()))
	if err != nil {
		logger.L().Error("SBOM scanner sidecar health check failed after retries", helpers.Error(err))
		conn.Close()
		return nil, err
	}

	logger.L().Info("SBOM scanner sidecar connected")
	return c, nil
}

func (c *sbomScannerClient) CreateSBOM(ctx context.Context, req ScanRequest) (*ScanResult, error) {
	pbReq := &pb.CreateSBOMRequest{
		ImageId:             req.ImageID,
		ImageTag:            req.ImageTag,
		LayerPaths:          req.LayerPaths,
		ImageStatus:         req.ImageStatus,
		MaxImageSize:        req.MaxImageSize,
		MaxSbomSize:         req.MaxSBOMSize,
		EnableEmbeddedSboms: req.EnableEmbeddedSBOMs,
		TimeoutSeconds:      int64(req.Timeout.Seconds()),
	}

	resp, err := c.client.CreateSBOM(ctx, pbReq)
	if err != nil {
		st, ok := status.FromError(err)
		if ok && (st.Code() == codes.Unavailable || st.Code() == codes.Aborted) {
			return nil, fmt.Errorf("%w: %v", ErrScannerCrashed, err)
		}
		if ok && isScannerBusyStatus(st) {
			return nil, fmt.Errorf("%w: %v", ErrScannerBusy, err)
		}
		if ok && st.Code() == codes.FailedPrecondition {
			return nil, fmt.Errorf("%w: %v", ErrImageTooLarge, err)
		}
		return nil, err
	}

	var doc v1beta1.SyftDocument
	if err := json.Unmarshal(resp.SbomDocument, &doc); err != nil {
		return nil, fmt.Errorf("failed to deserialize SBOM document: %w", err)
	}

	return &ScanResult{
		SyftDocument: doc,
		SBOMSize:     resp.SbomSize,
	}, nil
}

// isScannerBusyStatus reports whether st is the sidecar's own admission-window
// rejection.
//
// The code alone is not sufficient: gRPC returns ResourceExhausted for its own
// message-size limits too, and misreading one of those as "just busy" would
// make the caller retry a payload that can never fit. The marker is a constant
// shared with the server (see scannerBusyStatusMarker), so the two ends cannot
// drift apart.
func isScannerBusyStatus(st *status.Status) bool {
	return st.Code() == codes.ResourceExhausted && strings.Contains(st.Message(), scannerBusyStatusMarker)
}

// ScanHostFilesystem asks the sidecar to scan its own view of the node root
// filesystem.
//
// Error mapping follows CreateSBOM's pattern, with two host-specific additions:
// ErrScannerBusy (admission window exhausted -- no scan was dispatched, so the
// caller must not count it as a failure) and *HostDocumentTooLargeError (the
// scan succeeded but its document cannot cross the socket, which the caller
// maps onto the same TooLarge/Incomplete branch an oversized in-process scan
// reaches).
func (c *sbomScannerClient) ScanHostFilesystem(ctx context.Context, req HostScanRequest) (*HostScanResult, error) {
	pbReq := &pb.ScanHostFilesystemRequest{
		SourceName:          req.SourceName,
		EnableEmbeddedSboms: req.EnableEmbeddedSBOMs,
		TimeoutSeconds:      int64(req.Timeout.Seconds()),
	}

	resp, err := c.client.ScanHostFilesystem(ctx, pbReq)
	if err != nil {
		st, ok := status.FromError(err)
		if ok && (st.Code() == codes.Unavailable || st.Code() == codes.Aborted) {
			return nil, fmt.Errorf("%w: %v", ErrScannerCrashed, err)
		}
		if ok && isScannerBusyStatus(st) {
			return nil, fmt.Errorf("%w: %v", ErrScannerBusy, err)
		}
		if ok && st.Code() == codes.OutOfRange && strings.HasPrefix(st.Message(), hostDocTooLargeStatusPrefix) {
			size, convErr := strconv.ParseInt(strings.TrimPrefix(st.Message(), hostDocTooLargeStatusPrefix), 10, 64)
			if convErr != nil {
				// The classification still holds even if the size did not
				// survive; 0 simply means "unknown", which the caller records
				// as-is rather than mistaking for a transient failure.
				size = 0
			}
			return nil, &HostDocumentTooLargeError{Size: size}
		}
		return nil, err
	}

	var doc v1beta1.SyftDocument
	if err := json.Unmarshal(resp.SbomDocument, &doc); err != nil {
		return nil, fmt.Errorf("failed to deserialize host SBOM document: %w", err)
	}

	return &HostScanResult{
		SyftDocument: doc,
		SBOMSize:     resp.SbomSize,
	}, nil
}

func (c *sbomScannerClient) Ready() bool {
	ctx, cancel := context.WithTimeout(context.Background(), healthCheckTimeout)
	defer cancel()
	resp, err := c.client.Health(ctx, &pb.HealthRequest{})
	if err != nil {
		return false
	}
	return resp.Ready
}

func (c *sbomScannerClient) Close() error {
	return c.conn.Close()
}
