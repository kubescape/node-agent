package main

import (
	"net"
	"os"
	"os/signal"
	"syscall"

	"github.com/kubescape/go-logger"
	"github.com/kubescape/go-logger/helpers"
	sbomscanner "github.com/kubescape/node-agent/pkg/sbomscanner/v1"
	pb "github.com/kubescape/node-agent/pkg/sbomscanner/v1/proto"
	"google.golang.org/grpc"
)

func main() {
	socketPath := os.Getenv("SOCKET_PATH")
	if socketPath == "" {
		socketPath = "/sbom-comm/scanner.sock"
	}

	// Remove stale socket file from a previous run
	os.Remove(socketPath)

	lis, err := net.Listen("unix", socketPath)
	if err != nil {
		logger.L().Fatal("failed to listen on socket", helpers.Error(err), helpers.String("path", socketPath))
	}

	srv := grpc.NewServer()
	pb.RegisterSBOMScannerServer(srv, sbomscanner.NewScannerServer())

	sigCh := make(chan os.Signal, 1)
	signal.Notify(sigCh, syscall.SIGTERM, syscall.SIGINT)

	go func() {
		sig := <-sigCh
		logger.L().Info("received signal, shutting down", helpers.String("signal", sig.String()))
		srv.GracefulStop()
		os.Remove(socketPath)
	}()

	logger.L().Info("SBOM scanner sidecar started", helpers.String("socket", socketPath))
	if err := srv.Serve(lis); err != nil {
		logger.L().Fatal("gRPC server failed", helpers.Error(err))
	}
}
