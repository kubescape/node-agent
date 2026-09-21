package v1

import (
	"context"
	"os"
	"runtime"
	"testing"

	"github.com/anchore/syft/syft"
	"github.com/anchore/syft/syft/sbom"
	"github.com/anchore/syft/syft/source"
	"github.com/kubescape/node-agent/pkg/config"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// unsetCPULimitMillis removes CPU_LIMIT_MILLIS for the duration of a test.
// t.Setenv cannot express "unset", and the ambient environment of a developer
// machine or CI runner must not decide whether the fallback branch is taken.
func unsetCPULimitMillis(t *testing.T) {
	t.Helper()
	if orig, ok := os.LookupEnv(cpuLimitMillisEnvVar); ok {
		t.Cleanup(func() { _ = os.Setenv(cpuLimitMillisEnvVar, orig) })
	} else {
		t.Cleanup(func() { _ = os.Unsetenv(cpuLimitMillisEnvVar) })
	}
	require.NoError(t, os.Unsetenv(cpuLimitMillisEnvVar))
}

// Test_ParallelismFromCPULimitMillis pins the millicores-to-parallelism
// computation, including the clamp that makes a sub-1-CPU limit (the observed
// production case, 394m) resolve to 1 rather than 0 -- 0 is Syft's own
// "use runtime.NumCPU()" sentinel, so an unclamped integer division would
// silently reinstate exactly the unbounded behaviour the cap exists to remove.
//
// The unusable cases assert the returned ok == false, i.e. that the fallback
// branch is genuinely taken, not merely that the numeric result happens to
// match runtime.NumCPU() on the machine running the test.
func Test_ParallelismFromCPULimitMillis(t *testing.T) {
	tests := []struct {
		name string
		raw  string
		want int
		ok   bool
	}{
		{name: "394m, the observed production limit, clamps to 1", raw: "394", want: 1, ok: true},
		{name: "exactly one CPU", raw: "1000", want: 1, ok: true},
		{name: "2500m truncates to whole CPUs", raw: "2500", want: 2, ok: true},
		{name: "8 CPUs", raw: "8000", want: 8, ok: true},
		{name: "surrounding whitespace is tolerated", raw: " 2500 ", want: 2, ok: true},
		{name: "unset falls back", raw: "", want: 0, ok: false},
		{name: "unparseable falls back", raw: "394m", want: 0, ok: false},
		{name: "zero falls back", raw: "0", want: 0, ok: false},
		{name: "negative falls back", raw: "-1", want: 0, ok: false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, ok := parallelismFromCPULimitMillis(tt.raw)
			assert.Equal(t, tt.ok, ok)
			assert.Equal(t, tt.want, got)
		})
	}
}

// Test_ResolveHostScanParallelism_FromEnv proves the resolved value comes from
// the container's own declared CPU limit as delivered by the downward API.
func Test_ResolveHostScanParallelism_FromEnv(t *testing.T) {
	t.Setenv(cpuLimitMillisEnvVar, "394")
	sm, _, _ := newHostSbomManager(t, hostCfg("node-1"), t.TempDir())

	assert.Equal(t, 1, sm.resolveHostScanParallelism())
}

// Test_ResolveHostScanParallelism_FallsBackToNumCPU covers the older-chart
// case: no CPU_LIMIT_MILLIS at all, so the scan runs at Syft's historical
// parallelism rather than failing. The WARN log that accompanies this is the
// operator-visible signal that the cap is not in effect.
func Test_ResolveHostScanParallelism_FallsBackToNumCPU(t *testing.T) {
	unsetCPULimitMillis(t)
	cfg := hostCfg("node-1")
	cfg.EnableSbomGeneration = true
	sm, _, _ := newHostSbomManager(t, cfg, t.TempDir())

	assert.Equal(t, runtime.NumCPU(), sm.resolveHostScanParallelism())
}

// Test_ResolveHostScanParallelism_ConfigOverrideTakesPrecedence proves the
// hostSbomScanParallelism escape hatch wins over the computed value, so a
// computed value that proves wrong in the field can be corrected by config
// alone, without a new image build.
func Test_ResolveHostScanParallelism_ConfigOverrideTakesPrecedence(t *testing.T) {
	t.Setenv(cpuLimitMillisEnvVar, "8000")
	cfg := hostCfg("node-1")
	cfg.HostSbomScanParallelism = 3
	sm, _, _ := newHostSbomManager(t, cfg, t.TempDir())

	assert.Equal(t, 3, sm.resolveHostScanParallelism(),
		"a non-zero hostSbomScanParallelism must override the CPU-limit-derived value")

	// The override must also win over the fallback, not just over a computed
	// value -- otherwise an older chart would ignore the operator's setting.
	unsetCPULimitMillis(t)
	assert.Equal(t, 3, sm.resolveHostScanParallelism())
}

// Test_HostSbomConfig_SetsParallelism proves the resolved value actually
// reaches Syft's config rather than being computed and dropped. Parallelism
// left at 0 is Syft's "use runtime.NumCPU()" default, which is the exact
// no-op failure mode this assertion exists to catch.
func Test_HostSbomConfig_SetsParallelism(t *testing.T) {
	assert.Equal(t, 0, syft.DefaultCreateSBOMConfig().Parallelism,
		"syft's own default is the unbounded sentinel; the assertions below are only meaningful because of it")

	cfg := hostSbomConfig("v1.0.0", false, 1)
	assert.Equal(t, 1, cfg.Parallelism)

	cfg = hostSbomConfig("v1.0.0", true, 4)
	assert.Equal(t, 4, cfg.Parallelism, "the embedded-SBOM cataloger opt-in must not drop the cap")
}

// Test_ProcessHostSbom_ScansWithResolvedParallelism closes the loop end to
// end: the value resolved from CPU_LIMIT_MILLIS is the one the actual scan
// call receives.
func Test_ProcessHostSbom_ScansWithResolvedParallelism(t *testing.T) {
	t.Setenv(cpuLimitMillisEnvVar, "2500")
	sm, _, _ := newHostSbomManager(t, hostCfg("node-1"), tinyHostRoot(t))

	var observed int
	sm.hostSyftScanFn = func(ctx context.Context, src source.Source, cfg *syft.CreateSBOMConfig) (*sbom.SBOM, error) {
		observed = cfg.Parallelism
		return syft.CreateSBOM(ctx, src, cfg)
	}

	sm.processHostSbom("node-1")

	assert.Equal(t, 2, observed)
}

// Test_HostSbomScanParallelism_DefaultsToZero pins the config default: zero
// means "compute it", so the computed path is what a stock deployment gets.
func Test_HostSbomScanParallelism_DefaultsToZero(t *testing.T) {
	var cfg config.Config
	assert.Zero(t, cfg.HostSbomScanParallelism)
}
