package v1

import (
	"context"
	"encoding/json"
	"net"
	"os"
	"path/filepath"
	"testing"

	pb "github.com/kubescape/node-agent/pkg/sbomscanner/v1/proto"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/credentials/insecure"
	"google.golang.org/grpc/status"
	runtime "k8s.io/cri-api/pkg/apis/runtime/v1"
	_ "modernc.org/sqlite"
)

func makeTestImageStatus(t *testing.T) []byte {
	t.Helper()
	infoJSON := `{"imageSpec":{"rootfs":{"type":"layers","diff_ids":["sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"]},"architecture":"amd64","os":"linux","config":{}}}`
	isr := &runtime.ImageStatusResponse{
		Image: &runtime.Image{
			Id:          "sha256:abc",
			RepoTags:    []string{"test:latest"},
			RepoDigests: []string{"test@sha256:abc"},
			Size:        100,
		},
		Info: map[string]string{"info": infoJSON},
	}
	data, err := json.Marshal(isr)
	require.NoError(t, err)
	return data
}

func startIntegrationServer(t *testing.T) (SBOMScannerClient, *grpc.Server, string) {
	t.Helper()
	dir := t.TempDir()
	sock := filepath.Join(dir, "scanner.sock")

	lis, err := net.Listen("unix", sock)
	require.NoError(t, err)

	srv := grpc.NewServer()
	pb.RegisterSBOMScannerServer(srv, NewScannerServer())
	go srv.Serve(lis)

	conn, err := grpc.NewClient("unix://"+sock,
		grpc.WithTransportCredentials(insecure.NewCredentials()),
	)
	require.NoError(t, err)

	client := &sbomScannerClient{
		conn:   conn,
		client: pb.NewSBOMScannerClient(conn),
	}

	return client, srv, sock
}

func TestIntegration_FullScanLifecycle(t *testing.T) {
	client, srv, sock := startIntegrationServer(t)
	defer srv.Stop()
	defer os.Remove(sock)
	defer client.Close()

	assert.True(t, client.Ready())

	layerDir := t.TempDir()
	require.NoError(t, os.WriteFile(filepath.Join(layerDir, "test.txt"), []byte("hello"), 0644))

	result, err := client.CreateSBOM(context.Background(), ScanRequest{
		ImageID:      "sha256:abc",
		ImageTag:     "test:latest",
		LayerPaths:   []string{layerDir},
		ImageStatus:  makeTestImageStatus(t),
		MaxImageSize: 1024 * 1024 * 1024,
		MaxSBOMSize:  10 * 1024 * 1024,
	})
	require.NoError(t, err)
	assert.NotNil(t, result)
	assert.Greater(t, result.SBOMSize, int64(0))
}

func TestIntegration_SimulatedOOM(t *testing.T) {
	client, srv, sock := startIntegrationServer(t)
	defer os.Remove(sock)
	defer client.Close()

	assert.True(t, client.Ready())

	// Kill the server to simulate OOM
	srv.Stop()

	_, err := client.CreateSBOM(context.Background(), ScanRequest{
		ImageID:      "sha256:abc",
		ImageTag:     "test:latest",
		LayerPaths:   []string{t.TempDir()},
		ImageStatus:  makeTestImageStatus(t),
		MaxImageSize: 1024 * 1024 * 1024,
	})
	require.Error(t, err)
	assert.ErrorIs(t, err, ErrScannerCrashed)
}

func TestIntegration_ImageTooLarge(t *testing.T) {
	client, srv, sock := startIntegrationServer(t)
	defer srv.Stop()
	defer os.Remove(sock)
	defer client.Close()

	layerDir := t.TempDir()
	require.NoError(t, os.WriteFile(filepath.Join(layerDir, "big.bin"), make([]byte, 2048), 0644))

	_, err := client.CreateSBOM(context.Background(), ScanRequest{
		ImageID:      "sha256:abc",
		ImageTag:     "test:latest",
		LayerPaths:   []string{layerDir},
		ImageStatus:  makeTestImageStatus(t),
		MaxImageSize: 1,
	})
	require.Error(t, err)
	st, ok := status.FromError(err)
	require.True(t, ok)
	assert.Equal(t, codes.FailedPrecondition, st.Code())
}

func TestIntegration_ReadyCheck(t *testing.T) {
	client, srv, sock := startIntegrationServer(t)
	defer os.Remove(sock)

	assert.True(t, client.Ready())

	srv.Stop()

	assert.False(t, client.Ready())

	client.Close()
}
