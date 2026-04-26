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
)

func startTestServer(t *testing.T) (pb.SBOMScannerClient, func()) {
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

	client := pb.NewSBOMScannerClient(conn)
	cleanup := func() {
		conn.Close()
		srv.Stop()
		os.Remove(sock)
	}
	return client, cleanup
}

func TestHealth(t *testing.T) {
	client, cleanup := startTestServer(t)
	defer cleanup()

	resp, err := client.Health(context.Background(), &pb.HealthRequest{})
	require.NoError(t, err)
	assert.True(t, resp.Ready)
	assert.NotEmpty(t, resp.Version)
}

func TestCreateSBOM_InvalidImageStatus(t *testing.T) {
	client, cleanup := startTestServer(t)
	defer cleanup()

	resp, err := client.CreateSBOM(context.Background(), &pb.CreateSBOMRequest{
		ImageId:      "test-image",
		ImageTag:     "test:latest",
		ImageStatus:  []byte("invalid json"),
		MaxImageSize: 1024 * 1024 * 1024,
	})
	assert.Nil(t, resp)
	require.Error(t, err)
	st, ok := status.FromError(err)
	require.True(t, ok)
	assert.Equal(t, codes.InvalidArgument, st.Code())
}

func makeImageStatusJSON(t *testing.T) []byte {
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

func TestCreateSBOM_ImageTooLarge(t *testing.T) {
	client, cleanup := startTestServer(t)
	defer cleanup()

	layerDir := t.TempDir()
	require.NoError(t, os.WriteFile(filepath.Join(layerDir, "bigfile"), make([]byte, 1024), 0644))

	resp, err := client.CreateSBOM(context.Background(), &pb.CreateSBOMRequest{
		ImageId:      "sha256:abc",
		ImageTag:     "test:latest",
		LayerPaths:   []string{layerDir},
		ImageStatus:  makeImageStatusJSON(t),
		MaxImageSize: 1,
	})
	assert.Nil(t, resp)
	require.Error(t, err)
	st, ok := status.FromError(err)
	require.True(t, ok)
	assert.Equal(t, codes.FailedPrecondition, st.Code())
}

func TestCreateSBOM_ContextCancelled(t *testing.T) {
	client, cleanup := startTestServer(t)
	defer cleanup()

	ctx, cancel := context.WithCancel(context.Background())
	cancel()

	resp, err := client.CreateSBOM(ctx, &pb.CreateSBOMRequest{
		ImageId:  "test-image",
		ImageTag: "test:latest",
	})
	assert.Nil(t, resp)
	require.Error(t, err)
	st, ok := status.FromError(err)
	require.True(t, ok)
	assert.Equal(t, codes.Canceled, st.Code())
}
