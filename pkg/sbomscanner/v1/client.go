package v1

import (
	"context"
	"encoding/json"
	"fmt"
	"time"

	"github.com/cenkalti/backoff/v5"
	"github.com/kubescape/go-logger"
	"github.com/kubescape/go-logger/helpers"
	pb "github.com/kubescape/node-agent/pkg/sbomscanner/v1/proto"
	"github.com/kubescape/storage/pkg/apis/softwarecomposition/v1beta1"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/credentials/insecure"
	"google.golang.org/grpc/status"
)

const (
	healthCheckTimeout = 5 * time.Second
)

type sbomScannerClient struct {
	conn   *grpc.ClientConn
	client pb.SBOMScannerClient
}

func NewSBOMScannerClient(socketPath string) (SBOMScannerClient, error) {
	target := fmt.Sprintf("unix://%s", socketPath)
	conn, err := grpc.NewClient(target,
		grpc.WithTransportCredentials(insecure.NewCredentials()),
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
