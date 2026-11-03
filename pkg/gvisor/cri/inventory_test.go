package cri

import (
	"context"
	"net"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"google.golang.org/grpc"
	runtimeapi "k8s.io/cri-api/pkg/apis/runtime/v1"
)

type inventoryServer struct {
	runtimeapi.UnimplementedRuntimeServiceServer
	container *runtimeapi.Container
	sandbox   *runtimeapi.PodSandboxStatus
	block     bool
}

func (s *inventoryServer) ListContainers(ctx context.Context, _ *runtimeapi.ListContainersRequest) (*runtimeapi.ListContainersResponse, error) {
	if s.block {
		<-ctx.Done()
		return nil, ctx.Err()
	}
	return &runtimeapi.ListContainersResponse{Containers: []*runtimeapi.Container{s.container}}, nil
}

func (s *inventoryServer) PodSandboxStatus(context.Context, *runtimeapi.PodSandboxStatusRequest) (*runtimeapi.PodSandboxStatusResponse, error) {
	return &runtimeapi.PodSandboxStatusResponse{Status: s.sandbox}, nil
}

func (s *inventoryServer) Status(context.Context, *runtimeapi.StatusRequest) (*runtimeapi.StatusResponse, error) {
	return &runtimeapi.StatusResponse{Status: &runtimeapi.RuntimeStatus{Conditions: []*runtimeapi.RuntimeCondition{{Type: "RuntimeReady", Status: true}}}}, nil
}

func TestGVisorCRIInventory(t *testing.T) {
	id, sandboxID := strings.Repeat("a", 64), strings.Repeat("b", 64)
	for _, tc := range []string{"exact_created", "exact_running", "prefix", "exited", "wrong_sandbox", "wrong_handler", "missing_uid", "cancellation", "deadline"} {
		t.Run(tc, func(t *testing.T) {
			server := &inventoryServer{
				container: &runtimeapi.Container{Id: id, PodSandboxId: sandboxID, Metadata: &runtimeapi.ContainerMetadata{Name: "app"}},
				sandbox:   &runtimeapi.PodSandboxStatus{Id: sandboxID, RuntimeHandler: "runsc", Metadata: &runtimeapi.PodSandboxMetadata{Namespace: "apps", Name: "sandbox", Uid: "pod-uid"}},
			}
			switch tc {
			case "exact_running":
				server.container.State = runtimeapi.ContainerState_CONTAINER_RUNNING
			case "prefix":
				server.container.Id = id + "c"
			case "exited":
				server.container.State = runtimeapi.ContainerState_CONTAINER_EXITED
			case "wrong_sandbox":
				server.sandbox.Id = strings.Repeat("c", 64)
			case "wrong_handler":
				server.sandbox.RuntimeHandler = "runc"
			case "missing_uid":
				server.sandbox.Metadata.Uid = ""
			case "cancellation", "deadline":
				server.block = true
			}
			// Keep the Unix path short even under macOS's long TMPDIR prefix.
			dir, err := os.MkdirTemp("", "gv-cri-")
			if err != nil {
				t.Fatal(err)
			}
			defer os.RemoveAll(dir)
			path := filepath.Join(dir, "cri.sock")
			listener, err := net.Listen("unix", path)
			if err != nil {
				t.Fatal(err)
			}
			grpcServer := grpc.NewServer()
			runtimeapi.RegisterRuntimeServiceServer(grpcServer, server)
			go grpcServer.Serve(listener)
			defer grpcServer.Stop()
			inventory, err := New(path, "runsc")
			if err != nil {
				t.Fatal(err)
			}
			defer inventory.Close()
			ctx, cancel := context.WithTimeout(context.Background(), time.Second)
			defer cancel()
			if err := inventory.Check(ctx); err != nil {
				t.Fatal(err)
			}
			if tc == "cancellation" {
				cancel()
			}
			if tc == "deadline" {
				var cancelDeadline context.CancelFunc
				ctx, cancelDeadline = context.WithTimeout(ctx, 30*time.Millisecond)
				defer cancelDeadline()
			}
			started := time.Now()
			identity, err := inventory.Resolve(ctx, id)
			if tc == "deadline" && time.Since(started) > time.Second {
				t.Fatal("CRI RPC ignored deadline")
			}
			valid := tc == "exact_created" || tc == "exact_running"
			if (err == nil) != valid {
				t.Fatalf("identity verification: got %v, valid=%v", err, valid)
			}
			if valid && (identity.ContainerID != id || identity.SandboxID != sandboxID || identity.PodUID != "pod-uid") {
				t.Fatal("inventory fields changed")
			}
		})
	}
}

func TestGVisorCRIRejectsRemoteEndpoint(t *testing.T) {
	if _, err := New("tcp://127.0.0.1:1234", "runsc"); err == nil {
		t.Fatal("remote endpoint accepted")
	}
}
