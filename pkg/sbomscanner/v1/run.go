package v1

import (
	"context"
	"net"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/kubescape/go-logger"
	"github.com/kubescape/go-logger/helpers"
	otelmetrics "github.com/kubescape/node-agent/pkg/metricsmanager/otel"
	"github.com/kubescape/node-agent/pkg/otelsetup"
	pb "github.com/kubescape/node-agent/pkg/sbomscanner/v1/proto"
	"go.opentelemetry.io/contrib/instrumentation/google.golang.org/grpc/otelgrpc"
	goruntime "go.opentelemetry.io/contrib/instrumentation/runtime"
	"google.golang.org/grpc"
	grpcstats "google.golang.org/grpc/stats"
)

func RunServer(ctx context.Context, accountID, accessKey string) {
	// Initialize OTEL providers from standard env vars (OTEL_EXPORTER_OTLP_ENDPOINT etc.).
	// Gracefully degrades to no-op when endpoint is not configured.
	otelShutdown, err := otelsetup.InitProviders(ctx, otelsetup.ProviderConfig{
		ServiceName:    "sbom-scanner",
		ServiceVersion: os.Getenv("RELEASE"),
		NodeName:       os.Getenv("NODE_NAME"),
		PodName:        os.Getenv("POD_NAME"),
		Namespace:      os.Getenv("NAMESPACE"),
		ClusterName:    os.Getenv("CLUSTER_NAME"),
		AccountID:      accountID,
		AccessKey:      accessKey,
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

	// Emit Go runtime metrics only when metrics collection is configured;
	// avoids ~2–3 KB/hr of metric volume for deployments without telemetry.
	if os.Getenv("OTEL_EXPORTER_OTLP_ENDPOINT") != "" ||
		os.Getenv("OTEL_METRICS_EXPORTER") != "" ||
		os.Getenv("OTEL_EXPORTER_OTLP_METRICS_ENDPOINT") != "" {
		if err := goruntime.Start(goruntime.WithMinimumReadMemStatsInterval(30 * time.Second)); err != nil {
			logger.L().Warning("sbom-scanner: Go runtime metrics unavailable", helpers.Error(err))
		}
		// Per-process memory gauges (rss + cgroup usage/limit), same as the main
		// agent. The sidecar mounts its own namespaced /sys/fs/cgroup (no host
		// override), so the cgroup resolver reads the namespace root directly —
		// no container ID needed.
		otelmetrics.RegisterProcessMemoryMetrics(otelsetup.Meter(), "")
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

	srv := grpc.NewServer(grpc.StatsHandler(otelgrpc.NewServerHandler(
		otelgrpc.WithFilter(func(info *grpcstats.RPCTagInfo) bool {
			return info.FullMethodName != pb.SBOMScanner_Health_FullMethodName
		}),
	)))
	pb.RegisterSBOMScannerServer(srv, NewScannerServer())

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
