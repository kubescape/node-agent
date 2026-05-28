package otelmetrics

import (
	"bufio"
	"context"
	"io/fs"
	"os"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"

	"go.opentelemetry.io/otel/metric"
)

const cgroupRoot = "/sys/fs/cgroup"

// registerResourceMetrics wires up observable gauges for process-level and
// host-level resource. Called once from NewOTELMetricsManager; panics on
// instrument creation failure (same policy as mustCounter/mustGauge).
func registerResourceMetrics(meter metric.Meter, containerCount *atomic.Int64, ownContainerID string) {
	// Per-process memory gauges (rss + cgroup usage/limit) — shared with the
	// sbom-scanner sidecar so both containers report the same memory signals.
	RegisterProcessMemoryMetrics(meter, ownContainerID)

	hostMemTotal := readHostMemTotalBytes()
	hostCPUCount := int64(runtime.NumCPU())

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
		o.ObserveInt64(hostMemGauge, hostMemTotal)
		o.ObserveInt64(hostCPUGauge, hostCPUCount)
		o.ObserveInt64(containerCountGauge, containerCount.Load())
		return nil
	}, hostMemGauge, hostCPUGauge, containerCountGauge)
}

// RegisterProcessMemoryMetrics registers the per-process/per-container memory
// gauges — rss_bytes, cgroup_bytes, cgroup_limit_bytes — on the given meter.
// Both the main agent and the sbom-scanner sidecar call this so each container
// reports its own memory usage and limit (distinguished downstream by
// service.name). ownContainerID, when non-empty, lets the cgroup resolver find
// the correct scope under a host-mounted cgroup tree (the main-agent topology);
// pass "" for containers that mount their own namespaced /sys/fs/cgroup (the
// sidecar), where a direct read of the namespace root works.
//
// MUST be called after otelsetup.InitProviders so the real MeterProvider is set.
func RegisterProcessMemoryMetrics(meter metric.Meter, ownContainerID string) {
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
	cgroupLimitGauge, err := meter.Int64ObservableGauge("node_agent.process.memory.cgroup_limit_bytes",
		metric.WithDescription("Container memory limit from cgroupv2 memory.max or cgroupv1 memory.limit_in_bytes (0 = unlimited). Pair with cgroup_bytes for OOM headroom."),
		metric.WithUnit("By"),
	)
	if err != nil {
		panic("otelmetrics: gauge node_agent.process.memory.cgroup_limit_bytes: " + err.Error())
	}

	_, _ = meter.RegisterCallback(func(_ context.Context, o metric.Observer) error {
		o.ObserveInt64(rssGauge, readProcessRSSBytes())
		cur, lim := readCgroupMem(ownContainerID)
		o.ObserveInt64(cgroupMemGauge, cur)
		o.ObserveInt64(cgroupLimitGauge, lim)
		return nil
	}, rssGauge, cgroupMemGauge, cgroupLimitGauge)
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

var (
	cgroupResolveOnce sync.Once
	cgroupCurrentPath string // path to memory.current / memory.usage_in_bytes ("" if unresolved)
	cgroupMaxPath     string // path to memory.max / memory.limit_in_bytes ("" if unresolved)
)

// readCgroupMem returns the process's cgroup memory usage and limit in bytes
// (limit 0 = unlimited / unresolved). Paths are resolved once and cached since
// a process never changes cgroup.
func readCgroupMem(ownContainerID string) (current, limit int64) {
	cgroupResolveOnce.Do(func() {
		cgroupCurrentPath, cgroupMaxPath = resolveCgroupMemoryPaths(ownContainerID)
	})
	if cgroupCurrentPath != "" {
		if data, err := os.ReadFile(cgroupCurrentPath); err == nil {
			current = parseCgroupMemValue(string(data))
		}
	}
	if cgroupMaxPath != "" {
		if data, err := os.ReadFile(cgroupMaxPath); err == nil {
			limit = parseCgroupMemValue(string(data))
		}
	}
	return current, limit
}

// resolveCgroupMemoryPaths locates this process's cgroup memory files.
//
// node-agent runs with a private cgroup namespace (so /proc/self/cgroup
// reports "0::/") while bind-mounting the host's /sys/fs/cgroup over its own,
// so the namespaced path cannot be joined with the host tree — reading the
// fixed root path yields 0. Strategies, in order:
//  1. If our own container ID is known (resolved from the k8s API at startup),
//     find the matching *.scope directory in the host cgroup tree. This is the
//     node-agent topology. Self-discovery from /proc is unreliable here:
//     /proc/self/cgroup is "0::/", and /proc/self/mountinfo is polluted with
//     every other container's ID via shared mount propagation of /host.
//  2. Join /proc/self/cgroup with the cgroup root; use it if memory.current
//     exists there. This covers both the host cgroup namespace (rel is the full
//     path) and a container's own namespaced /sys/fs/cgroup mount, where
//     /proc/self/cgroup is "0::/" and the namespace root (cgroupRoot itself) is
//     the container's own cgroup — the sbom-scanner sidecar topology. The main
//     agent overrides /sys/fs/cgroup with the host tree, whose root has no
//     memory.current, so this path no-ops there and strategy 1 wins.
//  3. cgroupv1 fixed mount layout.
func resolveCgroupMemoryPaths(ownContainerID string) (current, max string) {
	if ownContainerID != "" {
		if dir := findCgroupScopeDir(cgroupRoot, ownContainerID); dir != "" {
			return filepath.Join(dir, "memory.current"), filepath.Join(dir, "memory.max")
		}
	}
	// cgroupv2: join /proc/self/cgroup with the root. filepath.Join collapses
	// the "0::/" namespace-root case to cgroupRoot itself.
	if rel, ok := parseSelfCgroupV2(readFileString("/proc/self/cgroup")); ok {
		dir := filepath.Join(cgroupRoot, rel)
		if fileExists(filepath.Join(dir, "memory.current")) {
			return filepath.Join(dir, "memory.current"), filepath.Join(dir, "memory.max")
		}
	}
	// cgroupv1 fallback (fixed mount layout).
	if fileExists("/sys/fs/cgroup/memory/memory.usage_in_bytes") {
		return "/sys/fs/cgroup/memory/memory.usage_in_bytes", "/sys/fs/cgroup/memory/memory.limit_in_bytes"
	}
	return "", ""
}

// parseSelfCgroupV2 returns the cgroup v2 path from the "0::<path>" line of
// /proc/self/cgroup and ok=true when that line is present (path may be "/", the
// namespace root). ok=false means no cgroupv2 line (e.g. cgroupv1-only).
func parseSelfCgroupV2(content string) (string, bool) {
	for _, line := range strings.Split(content, "\n") {
		if strings.HasPrefix(line, "0::") {
			return strings.TrimPrefix(line, "0::"), true
		}
	}
	return "", false
}

// findCgroupScopeDir walks the cgroup tree for a "*<id>*.scope" directory.
// Returns the first match, or "" if none. Bounded one-time cost (cached caller).
func findCgroupScopeDir(root, id string) string {
	var found string
	_ = filepath.WalkDir(root, func(path string, d fs.DirEntry, err error) error {
		if err != nil || !d.IsDir() {
			return nil //nolint:nilerr // skip unreadable subtrees, keep walking
		}
		name := d.Name()
		if strings.HasSuffix(name, ".scope") && strings.Contains(name, id) {
			found = path
			return filepath.SkipAll
		}
		return nil
	})
	return found
}

// parseCgroupMemValue parses a cgroup memory file value; the literal "max"
// (cgroupv2 unlimited) and unparseable input both yield 0.
func parseCgroupMemValue(s string) int64 {
	s = strings.TrimSpace(s)
	if s == "" || s == "max" {
		return 0
	}
	v, err := strconv.ParseInt(s, 10, 64)
	if err != nil {
		return 0
	}
	return v
}

func readFileString(path string) string {
	data, err := os.ReadFile(path)
	if err != nil {
		return ""
	}
	return string(data)
}

func fileExists(path string) bool {
	_, err := os.Stat(path)
	return err == nil
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
