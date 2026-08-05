package otelmetrics

import (
	"bufio"
	"context"
	"io/fs"
	"os"
	"path/filepath"
	"regexp"
	"runtime"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"

	"github.com/kubescape/go-logger"
	"github.com/kubescape/go-logger/helpers"
	"go.opentelemetry.io/otel/metric"
)

const cgroupRoot = "/sys/fs/cgroup"

// registerResourceMetrics wires up observable gauges for process-level and
// host-level resource. Called once from NewOTELMetricsManager; panics on
// instrument creation failure (same policy as mustCounter/mustGauge).
func registerResourceMetrics(meter metric.Meter, containerCount *atomic.Int64, ownContainerID, ownPodUID string) {
	// Per-process memory gauges (rss + cgroup usage/limit) — shared with the
	// sbom-scanner sidecar so both containers report the same memory signals.
	RegisterProcessMemoryMetrics(meter, ownContainerID)

	// Pod-scoped memory gauges — registered only here (the main agent), never
	// from the sidecar-shared RegisterProcessMemoryMetrics.
	RegisterPodMemoryMetrics(meter, ownContainerID, ownPodUID)

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

// RegisterPodMemoryMetrics registers pod-scoped memory gauges covering every
// container in this pod, including sidecars with no instrumentation of their
// own. Called only from registerResourceMetrics (the main agent), never from
// the shared RegisterProcessMemoryMetrics — registering it per-container would
// double-count the pod under any aggregation.
//
// ownContainerID == "" (sbom-scanner sidecar, cmd/host, cmd/ecs) registers
// nothing at all, so no empty series is ever emitted from those topologies.
func RegisterPodMemoryMetrics(meter metric.Meter, ownContainerID, ownPodUID string) {
	if ownContainerID == "" {
		return
	}

	podMemGauge, err := meter.Int64ObservableGauge("node_agent.pod.memory.cgroup_bytes",
		metric.WithDescription("Pod memory usage from the parent pod cgroup slice (kubepods-...-pod<UID>.slice) memory.current — covers every container in the pod, including uninstrumented sidecars"),
		metric.WithUnit("By"),
	)
	if err != nil {
		panic("otelmetrics: gauge node_agent.pod.memory.cgroup_bytes: " + err.Error())
	}
	podLimitGauge, err := meter.Int64ObservableGauge("node_agent.pod.memory.cgroup_limit_bytes",
		metric.WithDescription("Pod memory limit from the parent pod cgroup slice memory.max (0 = unlimited or unresolved). Pair with node_agent.pod.memory.cgroup_bytes for OOM headroom."),
		metric.WithUnit("By"),
	)
	if err != nil {
		panic("otelmetrics: gauge node_agent.pod.memory.cgroup_limit_bytes: " + err.Error())
	}

	_, _ = meter.RegisterCallback(func(_ context.Context, o metric.Observer) error {
		cur, lim := readPodCgroupMem(ownContainerID, ownPodUID)
		o.ObserveInt64(podMemGauge, cur)
		o.ObserveInt64(podLimitGauge, lim)
		return nil
	}, podMemGauge, podLimitGauge)
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
	cgroupScopeDir    string // this container's ".scope" dir under cgroupRoot ("" if not found that way); reused by the pod-level resolver
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
//
//  1. If our own container ID is known (resolved from the k8s API at startup),
//     find the matching *.scope directory in the host cgroup tree and read
//     whichever memory-accounting filenames actually exist there (cgroupv2
//     memory.current/memory.max, or cgroupv1 memory.usage_in_bytes/
//     memory.limit_in_bytes). This is the node-agent topology. Self-discovery
//     from /proc is unreliable here: /proc/self/cgroup is "0::/", and
//     /proc/self/mountinfo is polluted with every other container's ID via
//     shared mount propagation of /host.
//
//     When the container ID is known but no scope directory can be verified,
//     this returns "", "" immediately — it deliberately does NOT fall through
//     to strategies 2/3 below. Those two strategies read from cgroupRoot's own
//     root, which is only a valid proxy for "this container's memory" when the
//     caller mounts its own namespaced /sys/fs/cgroup (strategy 2/3's actual
//     intended topology, see below). For the main agent, which bind-mounts the
//     HOST's /sys/fs/cgroup, that same root is the whole node — falling
//     through would silently report the host's memory as this container's own
//     (a wrong-but-plausible number is worse than a missing series).
//
//  2. Join /proc/self/cgroup with the cgroup root; use it if memory.current
//     exists there. This covers both the host cgroup namespace (rel is the full
//     path) and a container's own namespaced /sys/fs/cgroup mount, where
//     /proc/self/cgroup is "0::/" and the namespace root (cgroupRoot itself) is
//     the container's own cgroup — the sbom-scanner sidecar topology.
//
//  3. cgroupv1 fixed mount layout.
//
// Strategies 2 and 3 only run when ownContainerID == "" — i.e. the caller
// either doesn't know which container it is, or mounts its own namespaced
// cgroup root (see above), the two cases where reading cgroupRoot's own root
// is actually scoped to the right thing.
func resolveCgroupMemoryPaths(ownContainerID string) (current, max string) {
	return resolveCgroupMemoryPathsUnder(cgroupRoot, ownContainerID, readFileString("/proc/self/cgroup"))
}

// resolveCgroupMemoryPathsUnder is the testable core of resolveCgroupMemoryPaths:
// root replaces the cgroupRoot const, and selfCgroupContent replaces a live
// read of /proc/self/cgroup, so tests can exercise every strategy against a
// synthetic tree instead of the real host filesystem.
func resolveCgroupMemoryPathsUnder(root, ownContainerID, selfCgroupContent string) (current, max string) {
	if ownContainerID != "" {
		dir := findCgroupScopeDir(root, ownContainerID)
		if dir == "" {
			return "", ""
		}
		cgroupScopeDir = dir // published under cgroupResolveOnce for cachedCgroupScopeDir
		if fileExists(filepath.Join(dir, "memory.current")) {
			return filepath.Join(dir, "memory.current"), filepath.Join(dir, "memory.max")
		}
		// cgroupv1: same (verified) directory, different filenames.
		return filepath.Join(dir, "memory.usage_in_bytes"), filepath.Join(dir, "memory.limit_in_bytes")
	}
	// cgroupv2: join /proc/self/cgroup with the root. filepath.Join collapses
	// the "0::/" namespace-root case to root itself.
	if rel, ok := parseSelfCgroupV2(selfCgroupContent); ok {
		dir := filepath.Join(root, rel)
		if fileExists(filepath.Join(dir, "memory.current")) {
			return filepath.Join(dir, "memory.current"), filepath.Join(dir, "memory.max")
		}
	}
	// cgroupv1 fallback (fixed mount layout).
	v1Current := filepath.Join(root, "memory", "memory.usage_in_bytes")
	if fileExists(v1Current) {
		return v1Current, filepath.Join(root, "memory", "memory.limit_in_bytes")
	}
	return "", ""
}

var (
	podCgroupResolveOnce sync.Once
	podCgroupCurrentPath string // path to the pod slice's memory.current ("" if unresolved)
	podCgroupMaxPath     string // path to the pod slice's memory.max ("" if unresolved)
)

// podSliceNameRe matches a systemd pod-slice directory name and captures the
// escaped pod UID. Only the "pod<uid>.slice" *suffix* is mandatory; any number
// of leading "<segment>-" parts is accepted, which covers every real shape:
// "pod<uid>.slice", "kubepods-pod<uid>.slice" (guaranteed QoS),
// "kubepods-<tier>-pod<uid>.slice" (burstable/besteffort) and the extra
// segments a custom kubelet --cgroup-root introduces
// ("kubelet-kubepods-burstable-pod<uid>.slice"). The QoS and root slices
// ("kubepods.slice", "kubepods-burstable.slice", "kubepods-besteffort.slice",
// "system.slice") are still rejected by shape since none of them ends in
// "pod<uid>.slice". Loosening the prefix is safe because the mandatory pod-UID
// equality check below — not the name shape — is the real correctness guard. A
// pod UID is 32 hex digits plus 4 separators, which systemd escapes "-" → "_",
// hence [0-9a-f_]{32,}; that escaping is also why the "-"-delimited prefix
// segments can never eat into the UID capture.
var podSliceNameRe = regexp.MustCompile(`^(?:[a-z0-9]+-)*pod([0-9a-f_]{32,})\.slice$`)

// resolvePodCgroupMemoryPaths locates the pod-level cgroup memory files by
// walking one level up from this container's ".scope" directory to its parent
// "kubepods-...-pod<UID>.slice". The kernel already aggregates every container
// in the pod at that level, including third-party sidecars (clamav) that carry
// no OTEL instrumentation of their own.
//
// systemd cgroup driver on cgroup v2 only. The parent-name guard below matches
// the systemd slice naming convention; under the cgroupfs driver
// findCgroupScopeDir does not match at all (it requires a ".scope" suffix). The
// memory.current check is likewise v2-only: this function hardcodes the v2
// filename pair in its return, so accepting a v1 directory would hand back
// paths that do not exist. Both cases return "", "".
//
// Returns "", "" when the pod slice cannot be positively identified.
func resolvePodCgroupMemoryPaths(ownContainerID, ownPodUID string) (current, max string) {
	return resolvePodCgroupMemoryPathsUnder(cgroupRoot, ownContainerID, ownPodUID)
}

// resolvePodCgroupMemoryPathsUnder is the testable core of
// resolvePodCgroupMemoryPaths, parameterised on the cgroup tree root.
func resolvePodCgroupMemoryPathsUnder(root, ownContainerID, ownPodUID string) (current, max string) {
	// Sidecar / cmd/host / cmd/ecs topologies: no own container ID means no pod
	// slice can be identified, and a pod-level number would be wrong anyway.
	// This is by design, so it is deliberately not logged.
	if ownContainerID == "" {
		return "", ""
	}
	// Past this point we expected to find a pod slice, so every failure is a
	// possible misconfiguration. The result is cached for the process lifetime,
	// so log what was rejected — otherwise the silence is indistinguishable
	// from the by-design case above, forever.
	reject := func(rejected string) (string, string) {
		logger.L().Warning("otelmetrics: pod-level cgroup memory unresolved, pod memory metrics will report 0",
			helpers.String("containerID", ownContainerID),
			helpers.String("podUID", ownPodUID),
			helpers.String("rejected", rejected))
		return "", ""
	}
	dir := cachedCgroupScopeDir(root, ownContainerID)
	if dir == "" {
		return reject("no .scope directory found for this container ID")
	}
	// Never let the walk-up escape to a QoS or node-wide slice.
	parent := filepath.Dir(dir)
	if parent == dir || parent == root || !strings.HasPrefix(parent+"/", root+"/") {
		return reject("scope directory has no in-tree parent slice: " + dir)
	}
	m := podSliceNameRe.FindStringSubmatch(filepath.Base(parent))
	if m == nil {
		return reject("parent slice name is not a pod slice: " + filepath.Base(parent))
	}
	// Mandatory verification against the pod UID when it is known; the regex
	// already constrains the captured segment to [0-9a-f_], so no case folding
	// is involved. An unknown UID falls back to the name-shape guard alone.
	if ownPodUID != "" && m[1] != strings.ReplaceAll(ownPodUID, "-", "_") {
		return reject("parent slice belongs to a different pod UID: " + filepath.Base(parent))
	}
	if !fileExists(filepath.Join(parent, "memory.current")) {
		return reject("parent slice has no memory.current (cgroup v1?): " + parent)
	}
	return filepath.Join(parent, "memory.current"), filepath.Join(parent, "memory.max")
}

// cachedCgroupScopeDir returns this container's ".scope" directory in the
// cgroup tree. Under the real cgroup root it reuses the container-level
// resolver's cached result — both resolvers look for the exact same directory —
// so the tree is walked at most once per process instead of once per resolver.
// A test root falls back to a direct walk.
func cachedCgroupScopeDir(root, ownContainerID string) string {
	if root != cgroupRoot {
		return findCgroupScopeDir(root, ownContainerID)
	}
	cgroupResolveOnce.Do(func() {
		cgroupCurrentPath, cgroupMaxPath = resolveCgroupMemoryPaths(ownContainerID)
	})
	return cgroupScopeDir
}

// readPodCgroupMem returns the pod-level cgroup memory usage and limit in bytes
// (limit 0 = unlimited / unresolved). Paths are resolved once and cached — a
// pod never changes cgroup — mirroring readCgroupMem's contract: a stale path
// yields a read error and therefore 0, never a wrong number.
func readPodCgroupMem(ownContainerID, ownPodUID string) (current, limit int64) {
	podCgroupResolveOnce.Do(func() {
		podCgroupCurrentPath, podCgroupMaxPath = resolvePodCgroupMemoryPaths(ownContainerID, ownPodUID)
	})
	if podCgroupCurrentPath != "" {
		if data, err := os.ReadFile(podCgroupCurrentPath); err == nil {
			current = parseCgroupMemValue(string(data))
		}
	}
	if podCgroupMaxPath != "" {
		if data, err := os.ReadFile(podCgroupMaxPath); err == nil {
			limit = parseCgroupMemValue(string(data))
		}
	}
	return current, limit
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

// scopeNameMatchesID reports whether a cgroup ".scope" directory name identifies
// exactly the given container ID — i.e. the ID appears as a whole
// delimiter-bounded segment ("cri-containerd-<id>.scope", "docker-<id>.scope",
// "crio-<id>.scope"), not as a substring of a longer hex ID.
func scopeNameMatchesID(name, id string) bool {
	if id == "" || !strings.HasSuffix(name, ".scope") {
		return false
	}
	base := strings.TrimSuffix(name, ".scope")
	// The ID must end the name (no trailing hex) and start at a delimiter
	// boundary (no leading hex), so a longer ID that merely contains the query
	// as a substring cannot match.
	if !strings.HasSuffix(base, id) {
		return false
	}
	if len(base) == len(id) {
		return true
	}
	switch base[len(base)-len(id)-1] {
	case '-', '_', '.', '/':
		return true
	}
	return false
}

// findCgroupScopeDir walks the cgroup tree for the ".scope" directory belonging
// to container id. Returns the first *verified* match, or "" if none. Bounded
// one-time cost (cached caller).
//
// Root cause note (hypothesis H4 for the observed "cgroup_bytes < rss_bytes"
// anomaly): the previous implementation matched on directory *name* only and
// returned filepath.SkipAll on that bare name match. On a cgroup-v1/hybrid host
// WalkDir visits /sys/fs/cgroup/blkio, /cpu, /cpuacct, /devices, /freezer — all
// lexically before /memory — and any of them can hold a
// "cri-containerd-<id>.scope" directory. The walk therefore locked in a
// directory with no memory accounting file at all, readCgroupMem silently
// read 0, and sync.Once cached that outcome for the process lifetime.
//
// The existence check below is therefore load-bearing, not defensive, and so
// is "keep walking" (return nil) instead of SkipAll on a name-only match:
// that is what lets the walk skip the decoy controller subtrees and reach the
// real memory-controller scope.
//
// The check accepts EITHER the cgroupv2 filename memory.current or the
// cgroupv1 filename memory.usage_in_bytes — cgroup v1's memory controller
// mounts as its own subtree with its own copy of the directory name, so a v1
// host's real memory-controller scope has memory.usage_in_bytes, not
// memory.current, and rejecting it here would make v1 hosts indistinguishable
// from "no scope found at all". resolveCgroupMemoryPaths re-checks which file
// is actually present at the returned directory and returns the matching
// pair, so this never hands back a nonexistent path.
func findCgroupScopeDir(root, id string) string {
	if id == "" {
		return ""
	}
	var found string
	_ = filepath.WalkDir(root, func(path string, d fs.DirEntry, err error) error {
		if err != nil || !d.IsDir() {
			return nil //nolint:nilerr // skip unreadable subtrees, keep walking
		}
		if !scopeNameMatchesID(d.Name(), id) {
			return nil
		}
		hasV2 := fileExists(filepath.Join(path, "memory.current"))
		hasV1 := fileExists(filepath.Join(path, "memory.usage_in_bytes"))
		if !hasV2 && !hasV1 {
			return nil // name matches but wrong controller subtree — keep walking
		}
		found = path
		return filepath.SkipAll
	})
	return found
}

// parseCgroupMemValue parses a cgroup memory file value; the literal "max"
// (cgroupv2 unlimited) and unparseable input both yield 0.
// v1UnlimitedThreshold is a generous lower bound for cgroup v1's "unlimited"
// limit sentinel (kernels report a value near math.MaxInt64, rounded down to
// a page boundary — the exact value depends on page size/arch, e.g.
// 9223372036854771712 on 4KB-page x86_64). No real container's memory usage
// or limit can plausibly reach this, so treating anything at or above it as
// "unlimited" (0) matches the cgroupv2 "max" convention without risking a
// false positive on a real value.
const v1UnlimitedThreshold = int64(1) << 62

func parseCgroupMemValue(s string) int64 {
	s = strings.TrimSpace(s)
	if s == "" || s == "max" {
		return 0
	}
	v, err := strconv.ParseInt(s, 10, 64)
	if err != nil {
		return 0
	}
	if v >= v1UnlimitedThreshold {
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
