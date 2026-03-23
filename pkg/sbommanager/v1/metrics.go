package v1

import (
	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promauto"
)

var (
	sbomScanTotal = promauto.NewCounterVec(prometheus.CounterOpts{
		Name: "sbom_scan_total",
		Help: "Total SBOM scan attempts",
	}, []string{"status"})

	sbomScanDuration = promauto.NewHistogramVec(prometheus.HistogramOpts{
		Name:    "sbom_scan_duration_seconds",
		Help:    "SBOM scan duration in seconds",
		Buckets: prometheus.ExponentialBuckets(1, 2, 12),
	}, []string{"status"})

	sbomScannerRestartsTotal = promauto.NewCounter(prometheus.CounterOpts{
		Name: "sbom_scanner_restarts_total",
		Help: "Total number of SBOM scanner sidecar restarts detected via connection loss",
	})

	sbomScannerReady = promauto.NewGauge(prometheus.GaugeOpts{
		Name: "sbom_scanner_ready",
		Help: "Whether the SBOM scanner sidecar is connected and healthy (1=ready, 0=not ready)",
	})
)
