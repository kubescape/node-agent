package otelmetrics

import (
	"bufio"
	"context"
	"os"
	"runtime"
	"strconv"
	"strings"
	"sync/atomic"

	"go.opentelemetry.io/otel/metric"
)

// registerResourceMetrics wires up observable gauges for process-level and
// host-level resource. Called once from NewOTELMetricsManager; panics on
// instrument creation failure (same policy as mustCounter/mustGauge).
func registerResourceMetrics(meter metric.Meter, containerCount *atomic.Int64) {
	hostMemTotal := readHostMemTotalBytes()
	hostCPUCount := int64(runtime.NumCPU())

	rssGauge, err := meter.Int64ObservableGauge("node_agent.process.memory.rss_bytes",
		metric.WithDescription("Process RSS (resident set size) from /proc/self/status"),
		metric.WithUnit("By"),
	)
	if err != nil {
		panic("otelmetrics: gauge node_agent.process.memory.rss_bytes: " + err.Error())
	}
	cgroupMemGauge, err := meter.Int64ObservableGauge("node_agent.process.memory.cgroup_bytes",
		metric.WithDescription("Container memory usage from cgroupv2 memory.current or cgroupv1 memory.usage_in_bytes"),
		metric.WithUnit("By"),
	)
	if err != nil {
		panic("otelmetrics: gauge node_agent.process.memory.cgroup_bytes: " + err.Error())
	}
	hostMemGauge, err := meter.Int64ObservableGauge("node_agent.host.memory.total_bytes",
		metric.WithDescription("Host total physical memory from /proc/meminfo MemTotal"),
		metric.WithUnit("By"),
	)
	if err != nil {
		panic("otelmetrics: gauge node_agent.host.memory.total_bytes: " + err.Error())
	}
	hostCPUGauge, err := meter.Int64ObservableGauge("node_agent.host.cpu.count",
		metric.WithDescription("Host logical CPU count"),
	)
	if err != nil {
		panic("otelmetrics: gauge node_agent.host.cpu.count: " + err.Error())
	}
	containerCountGauge, err := meter.Int64ObservableGauge("node_agent.container.count",
		metric.WithDescription("Currently observed container count (start − stop events)"),
	)
	if err != nil {
		panic("otelmetrics: gauge node_agent.container.count: " + err.Error())
	}

	_, _ = meter.RegisterCallback(func(_ context.Context, o metric.Observer) error {
		o.ObserveInt64(rssGauge, readProcessRSSBytes())
		o.ObserveInt64(cgroupMemGauge, readCgroupMemBytes())
		o.ObserveInt64(hostMemGauge, hostMemTotal)
		o.ObserveInt64(hostCPUGauge, hostCPUCount)
		o.ObserveInt64(containerCountGauge, containerCount.Load())
		return nil
	}, rssGauge, cgroupMemGauge, hostMemGauge, hostCPUGauge, containerCountGauge)
}

func readProcessRSSBytes() int64 {
	f, err := os.Open("/proc/self/status")
	if err != nil {
		return 0
	}
	defer f.Close()
	s := bufio.NewScanner(f)
	for s.Scan() {
		line := s.Text()
		if strings.HasPrefix(line, "VmRSS:") {
			fields := strings.Fields(line)
			if len(fields) >= 2 {
				kb, _ := strconv.ParseInt(fields[1], 10, 64)
				return kb * 1024
			}
		}
	}
	return 0
}

func readCgroupMemBytes() int64 {
	// cgroupv2 (Kubernetes ≥1.25 default)
	if data, err := os.ReadFile("/sys/fs/cgroup/memory.current"); err == nil {
		v, _ := strconv.ParseInt(strings.TrimSpace(string(data)), 10, 64)
		return v
	}
	// cgroupv1 fallback
	if data, err := os.ReadFile("/sys/fs/cgroup/memory/memory.usage_in_bytes"); err == nil {
		v, _ := strconv.ParseInt(strings.TrimSpace(string(data)), 10, 64)
		return v
	}
	return 0
}

func readHostMemTotalBytes() int64 {
	f, err := os.Open("/proc/meminfo")
	if err != nil {
		return 0
	}
	defer f.Close()
	s := bufio.NewScanner(f)
	for s.Scan() {
		line := s.Text()
		if strings.HasPrefix(line, "MemTotal:") {
			fields := strings.Fields(line)
			if len(fields) >= 2 {
				kb, _ := strconv.ParseInt(fields[1], 10, 64)
				return kb * 1024
			}
		}
	}
	return 0
}
