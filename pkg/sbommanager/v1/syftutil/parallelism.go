package syftutil

import (
	"strconv"
	"strings"
)

// ParallelismFromCPULimitMillis converts a CPU_LIMIT_MILLIS value -- this
// container's own declared CPU limit in integer millicores, supplied by the
// chart via the Kubernetes downward API (resourceFieldRef: {resource:
// limits.cpu, divisor: "1m"}) -- into a Syft cataloger parallelism. The bool
// reports whether the raw value was usable; false means the caller must take
// its serial fallback, and is returned rather than silently folding
// the fallback in here so the fallback branch itself is directly testable.
//
// The downward API is used deliberately in preference to reading the cgroup CPU
// quota directly: node-agent bind-mounts the HOST's /sys/fs/cgroup over its own
// (see pkg/metricsmanager/otel/resource_metrics.go, which had to build
// container-scope cgroup resolution for exactly this reason), so a naive
// root-level cgroup read inside that container returns the node's quota, not
// the container's -- and its failure direction is invisible: it falls back to
// runtime.NumCPU(), i.e. exactly the unbounded behaviour the cap exists to
// prevent. resourceFieldRef is resolved by kubelet at pod-admission time from
// the container's own spec and is immune to that trap entirely. The sbom-
// scanner sidecar's own cgroup topology would permit a direct read, but it uses
// the same mechanism so there is one quota-detection code path, not two.
//
// Whole CPUs are used (integer division): 394m -> 0 -> clamped to 1, 1000m ->
// 1, 2500m -> 2. n==1 is passed to Syft as parallelism 1, which the vendored
// fork (github.com/kubescape/syft, see go.mod's replace directive) special-
// cases to mean fully serial, no cataloger goroutines at all -- stronger than
// "one goroutine". This matters because that fork's default (parallelism 0)
// is NOT runtime.NumCPU(): syft/create_sbom.go resolves 0 to
// runtime.NumCPU()*4, so on an 8-CPU node a 394m container would schedule
// cataloger work across 32 goroutines against a quota of well under half a
// CPU -- 4x worse than the naive "NumCPU()" story suggests -- and get
// CFS-throttled hard enough to starve the container's own liveness endpoint.
func ParallelismFromCPULimitMillis(raw string) (int, bool) {
	millis, err := strconv.Atoi(strings.TrimSpace(raw))
	if err != nil || millis <= 0 {
		return 0, false
	}
	n := millis / 1000
	if n < 1 {
		n = 1
	}
	return n, true
}
