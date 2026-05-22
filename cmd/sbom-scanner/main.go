package main

import (
	"context"
	"net"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/kubescape/go-logger"
	"github.com/kubescape/go-logger/helpers"
	"github.com/kubescape/node-agent/pkg/otelsetup"
	sbomscanner "github.com/kubescape/node-agent/pkg/sbomscanner/v1"
	pb "github.com/kubescape/node-agent/pkg/sbomscanner/v1/proto"
	"go.opentelemetry.io/contrib/instrumentation/google.golang.org/grpc/otelgrpc"
	goruntime "go.opentelemetry.io/contrib/instrumentation/runtime"
	"google.golang.org/grpc"
	_ "modernc.org/sqlite"
)

func main() {
	ctx := context.Background()

	// Initialize OTEL providers from standard env vars (OTEL_EXPORTER_OTLP_ENDPOINT etc.).
	// Gracefully degrades to no-op when endpoint is not configured.
	otelShutdown, err := otelsetup.InitProviders(ctx, otelsetup.ProviderConfig{
		ServiceName:    "sbom-scanner",
		ServiceVersion: os.Getenv("RELEASE"),
		NodeName:       os.Getenv("NODE_NAME"),
		PodName:        os.Getenv("POD_NAME"),
		Namespace:      os.Getenv("NAMESPACE"),
		ClusterName:    os.Getenv("CLUSTER_NAME"),
		AccountID:      os.Getenv("ACCOUNT_ID"),
		AccessKey:      os.Getenv("ACCESS_KEY"),
	})
	if err != nil {
		logger.L().Warning("sbom-scanner: OTEL init failed, running without telemetry", helpers.Error(err))
	}
	if otelShutdown != nil {
		defer func() {
			shutdownCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
			defer cancel()
			_ = otelShutdown(shutdownCtx)
		}()
	}

	// Emit Go runtime metrics (heap_alloc, GC, goroutines) every 30s so
	// syft memory spikes are visible in SigNoz alongside scan traces.
	if err := goruntime.Start(goruntime.WithMinimumReadMemStatsInterval(30 * time.Second)); err != nil {
		logger.L().Warning("sbom-scanner: Go runtime metrics unavailable", helpers.Error(err))
	}

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

	srv := grpc.NewServer(grpc.StatsHandler(otelgrpc.NewServerHandler()))
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
