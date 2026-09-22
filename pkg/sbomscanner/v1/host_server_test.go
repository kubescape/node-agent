package v1

import (
	"context"
	"net"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/anchore/syft/syft"
	"github.com/anchore/syft/syft/sbom"
	"github.com/anchore/syft/syft/source"
	pb "github.com/kubescape/node-agent/pkg/sbomscanner/v1/proto"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/credentials/insecure"
	"google.golang.org/grpc/status"
	_ "modernc.org/sqlite" // required by syft's RPM cataloger
)

// fakeHostRoot builds a directory that passes the sidecar's host-root
// validation (all marker directories present) and carries one catalogable
// package, so a real Syft scan over it finishes in well under a second.
func fakeHostRoot(t *testing.T) string {
	t.Helper()
	root := t.TempDir()
	for _, dir := range hostRootMarkerDirs {
		require.NoError(t, os.MkdirAll(filepath.Join(root, dir), 0o755))
	}
	distInfo := filepath.Join(root, "usr/lib/python3/dist-packages/hostpkg-1.0.dist-info")
	require.NoError(t, os.MkdirAll(distInfo, 0o755))
	require.NoError(t, os.WriteFile(filepath.Join(distInfo, "METADATA"),
		[]byte("Metadata-Version: 2.1\nName: hostpkg\nVersion: 1.0\n"), 0o644))
	require.NoError(t, os.WriteFile(filepath.Join(distInfo, "RECORD"), nil, 0o644))
	return root
}

// startServer wires a real gRPC server around the given scannerServer, so the
// tests exercise the actual status codes that cross the wire rather than the
// handler's return value directly.
func startServer(t *testing.T, srv *scannerServer) (pb.SBOMScannerClient, SBOMScannerClient) {
	t.Helper()
	sock := filepath.Join(t.TempDir(), "scanner.sock")
	lis, err := net.Listen("unix", sock)
	require.NoError(t, err)

	grpcSrv := grpc.NewServer(
		grpc.MaxRecvMsgSize(MaxgRPCMessageSize),
		grpc.MaxSendMsgSize(MaxgRPCMessageSize),
	)
	pb.RegisterSBOMScannerServer(grpcSrv, srv)
	go func() { _ = grpcSrv.Serve(lis) }()

	conn, err := grpc.NewClient("unix://"+sock,
		grpc.WithTransportCredentials(insecure.NewCredentials()),
		grpc.WithDefaultCallOptions(
			grpc.MaxCallRecvMsgSize(MaxgRPCMessageSize),
			grpc.MaxCallSendMsgSize(MaxgRPCMessageSize),
		),
	)
	require.NoError(t, err)
	t.Cleanup(func() {
		_ = conn.Close()
		grpcSrv.Stop()
		_ = os.Remove(sock)
	})

	return pb.NewSBOMScannerClient(conn), &sbomScannerClient{conn: conn, client: pb.NewSBOMScannerClient(conn)}
}

func TestScanHostFilesystem_HappyPath(t *testing.T) {
	t.Setenv(hostRootEnvVar, fakeHostRoot(t))
	raw, _ := startServer(t, newScannerServer())

	resp, err := raw.ScanHostFilesystem(context.Background(), &pb.ScanHostFilesystemRequest{
		SourceName: "host-node-1",
	})
	require.NoError(t, err)
	assert.Greater(t, resp.SbomSize, int64(0))
	assert.Equal(t, int64(len(resp.SbomDocument)), resp.SbomSize,
		"sbom_size must describe the document actually sent")
}

func TestScanHostFilesystem_RequiresSourceName(t *testing.T) {
	t.Setenv(hostRootEnvVar, fakeHostRoot(t))
	raw, _ := startServer(t, newScannerServer())

	_, err := raw.ScanHostFilesystem(context.Background(), &pb.ScanHostFilesystemRequest{})
	require.Error(t, err)
	st, ok := status.FromError(err)
	require.True(t, ok)
	assert.Equal(t, codes.InvalidArgument, st.Code())
}

// TestScanHostFilesystem_HostRootValidation is the guard against the sidecar
// silently scanning the wrong filesystem: node-agent and the sidecar resolve
// HOST_ROOT independently, so a mismatch must fail loudly rather than return a
// structurally valid SBOM of the wrong machine.
func TestScanHostFilesystem_HostRootValidation(t *testing.T) {
	t.Run("missing path", func(t *testing.T) {
		t.Setenv(hostRootEnvVar, filepath.Join(t.TempDir(), "does-not-exist"))
		raw, _ := startServer(t, newScannerServer())

		_, err := raw.ScanHostFilesystem(context.Background(), &pb.ScanHostFilesystemRequest{SourceName: "host-node-1"})
		require.Error(t, err)
		st, _ := status.FromError(err)
		assert.Equal(t, codes.FailedPrecondition, st.Code())
	})

	t.Run("implausible host root", func(t *testing.T) {
		// A directory that exists but has none of the marker directories -- the
		// shape a wrong mount point would actually have.
		t.Setenv(hostRootEnvVar, t.TempDir())
		raw, _ := startServer(t, newScannerServer())

		_, err := raw.ScanHostFilesystem(context.Background(), &pb.ScanHostFilesystemRequest{SourceName: "host-node-1"})
		require.Error(t, err)
		st, _ := status.FromError(err)
		assert.Equal(t, codes.FailedPrecondition, st.Code())
		assert.Contains(t, st.Message(), "does not look like a node root filesystem")
	})
}

func TestScanHostFilesystem_Timeout(t *testing.T) {
	t.Setenv(hostRootEnvVar, fakeHostRoot(t))
	srv := newScannerServer()
	srv.hostScanFn = func(ctx context.Context, _ source.Source, _ *syft.CreateSBOMConfig) (*sbom.SBOM, error) {
		<-ctx.Done()
		return nil, ctx.Err()
	}
	raw, _ := startServer(t, srv)

	_, err := raw.ScanHostFilesystem(context.Background(), &pb.ScanHostFilesystemRequest{
		SourceName:     "host-node-1",
		TimeoutSeconds: 1,
	})
	require.Error(t, err)
	st, _ := status.FromError(err)
	assert.Equal(t, codes.DeadlineExceeded, st.Code())
}

// TestScanHostFilesystem_OversizedTransfer proves the server refuses to attempt
// a send it knows will fail, and reports the measured size in a form the client
// can read back.
//
// Without this, an oversized host document would surface as an opaque transport
// error, be retried as a generic failure, and re-walk the whole host root every
// rescan interval forever.
func TestScanHostFilesystem_OversizedTransfer(t *testing.T) {
	t.Setenv(hostRootEnvVar, fakeHostRoot(t))
	srv := newScannerServer()
	srv.hostDocumentSizeOverride = maxTransferableDocumentSize + 1
	raw, typed := startServer(t, srv)

	_, err := raw.ScanHostFilesystem(context.Background(), &pb.ScanHostFilesystemRequest{SourceName: "host-node-1"})
	require.Error(t, err)
	st, _ := status.FromError(err)
	assert.Equal(t, codes.OutOfRange, st.Code())

	// And, through the typed client, as a size-carrying classified error.
	_, err = typed.ScanHostFilesystem(context.Background(), HostScanRequest{SourceName: "host-node-1"})
	require.ErrorIs(t, err, ErrHostDocumentTooLargeToTransfer)
	var tooLarge *HostDocumentTooLargeError
	require.ErrorAs(t, err, &tooLarge)
	assert.Equal(t, int64(maxTransferableDocumentSize+1), tooLarge.Size)
}

// TestAdmission_HostScanBlocksImageScan is the falsifiable admission test.
//
// A long host scan is held open, and a concurrent image CreateSBOM is issued
// with a compressed admission window. The assertion is threefold: the image
// call returns ErrScannerBusy, it does so WITHIN its admission window rather
// than blocking for the whole host scan, and it does not return immediately --
// a TryAcquire-style design would fail that last point, and it is precisely
// what would regress the container path's existing "blocks, eventually
// succeeds" behaviour into spurious reported failures.
func TestAdmission_HostScanBlocksImageScan(t *testing.T) {
	t.Setenv(hostRootEnvVar, fakeHostRoot(t))
	srv := newScannerServer()
	srv.admissionTimeout = 300 * time.Millisecond

	release := make(chan struct{})
	started := make(chan struct{})
	srv.hostScanFn = func(ctx context.Context, _ source.Source, _ *syft.CreateSBOMConfig) (*sbom.SBOM, error) {
		close(started)
		select {
		case <-release:
		case <-ctx.Done():
		}
		return &sbom.SBOM{}, nil
	}
	raw, typed := startServer(t, srv)

	hostDone := make(chan struct{})
	go func() {
		defer close(hostDone)
		_, _ = raw.ScanHostFilesystem(context.Background(), &pb.ScanHostFilesystemRequest{SourceName: "host-node-1"})
	}()
	<-started

	start := time.Now()
	_, err := typed.CreateSBOM(context.Background(), ScanRequest{
		ImageID:     "sha256:abc",
		ImageTag:    "test:latest",
		ImageStatus: makeTestImageStatus(t),
	})
	elapsed := time.Since(start)

	require.ErrorIs(t, err, ErrScannerBusy,
		"a host scan holding the admission slot must yield a busy error, not a scan failure")
	assert.GreaterOrEqual(t, elapsed, srv.admissionTimeout,
		"admission must WAIT out its window; returning immediately is the rejected TryAcquire design")
	assert.Less(t, elapsed, 5*time.Second,
		"admission must not block for the host scan's whole duration")

	close(release)
	<-hostDone
}

// TestAdmission_SlotIsReleased proves the semaphore is released on both the
// success and the error path, so one failed scan cannot wedge the sidecar.
func TestAdmission_SlotIsReleased(t *testing.T) {
	t.Setenv(hostRootEnvVar, fakeHostRoot(t))
	srv := newScannerServer()
	srv.admissionTimeout = 200 * time.Millisecond
	raw, _ := startServer(t, srv)

	// An InvalidArgument failure, after admission was taken.
	_, err := raw.CreateSBOM(context.Background(), &pb.CreateSBOMRequest{ImageStatus: []byte("not json")})
	require.Error(t, err)

	// The next request must still be admitted.
	resp, err := raw.ScanHostFilesystem(context.Background(), &pb.ScanHostFilesystemRequest{SourceName: "host-node-1"})
	require.NoError(t, err)
	assert.Greater(t, resp.SbomSize, int64(0))
}

// TestScanParallelism_CapsToCPULimit pins the sidecar's own copy of PR 1's cap.
func TestScanParallelism_CapsToCPULimit(t *testing.T) {
	t.Setenv(cpuLimitMillisEnv, "1000")
	assert.Equal(t, 1, scanParallelism())

	t.Setenv(cpuLimitMillisEnv, "2500")
	assert.Equal(t, 2, scanParallelism())

	// 394m (the observed node-agent limit) floors to 0 and is clamped to 1 --
	// never to Syft's uncapped NumCPU()*4 default.
	t.Setenv(cpuLimitMillisEnv, "394")
	assert.Equal(t, 1, scanParallelism())

	srv := newScannerServer()
	assert.Equal(t, 1, srv.scanConfig(false).Parallelism,
		"the cap must actually reach the Syft config, not just be computed")
}

func TestScanParallelism_FallsBackToSerial(t *testing.T) {
	for _, raw := range []string{"", "394m", "0", "-1"} {
		t.Run("invalid_"+raw, func(t *testing.T) {
			t.Setenv(cpuLimitMillisEnv, raw)
			assert.Equal(t, 1, scanParallelism())
			srv := newScannerServer()
			for _, embedded := range []bool{false, true} {
				assert.Equal(t, 1, srv.scanConfig(embedded).Parallelism,
					"both RPCs must receive serial Syft configuration")
			}
		})
	}
	t.Run("unset", func(t *testing.T) {
		t.Setenv(cpuLimitMillisEnv, "")
		require.NoError(t, os.Unsetenv(cpuLimitMillisEnv))
		assert.Equal(t, 1, newScannerServer().scanConfig(false).Parallelism)
	})
}
