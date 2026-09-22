package v1

import (
	"context"
	"net"
	"path/filepath"
	"testing"

	pb "github.com/kubescape/node-agent/pkg/sbomscanner/v1/proto"
	"github.com/stretchr/testify/require"
	"google.golang.org/grpc"
)

// An older sidecar can pass its health check without implementing host scans.
type legacyScannerServer struct {
	pb.UnimplementedSBOMScannerServer
}

func (*legacyScannerServer) Health(context.Context, *pb.HealthRequest) (*pb.HealthResponse, error) {
	return &pb.HealthResponse{Ready: true}, nil
}

func TestClient_HostScanUnsupportedFallsBack(t *testing.T) {
	socketPath := filepath.Join(t.TempDir(), "scanner.sock")
	listener, err := net.Listen("unix", socketPath)
	require.NoError(t, err)
	server := grpc.NewServer()
	pb.RegisterSBOMScannerServer(server, &legacyScannerServer{})
	t.Cleanup(server.Stop)
	go server.Serve(listener)

	client, err := NewSBOMScannerClient(socketPath)
	require.NoError(t, err)
	t.Cleanup(func() { require.NoError(t, client.Close()) })
	require.True(t, client.Ready())

	result, err := client.ScanHostFilesystem(t.Context(), HostScanRequest{SourceName: "host-node-1"})
	require.Nil(t, result)
	require.ErrorIs(t, err, ErrScannerHostScanRejected)
	require.NotErrorIs(t, err, ErrScannerCrashed)
	require.True(t, client.Ready())
}
