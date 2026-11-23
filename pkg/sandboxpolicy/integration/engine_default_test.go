//go:build !sandbox_shared_qualification

package integration

import (
	"context"
	"errors"
	"fmt"
	"slices"
	"strings"
	"testing"

	"github.com/inspektor-gadget/inspektor-gadget/gadgets/enforce_exec/fullruntime"
	"github.com/inspektor-gadget/inspektor-gadget/pkg/runtime/local"
	"github.com/kubescape/node-agent/pkg/config"
	"github.com/kubescape/node-agent/pkg/sandboxpolicy/igbackend"
	api "github.com/kubescape/storage/pkg/apis/sandbox/v1alpha1"
	"github.com/opencontainers/go-digest"
	"github.com/spf13/viper"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"oras.land/oras-go/v2/content/memory"
)

const (
	testBTF612 = "0d7b3abe2b50e1b252b167061fea565e78fb712b691d1c04dd5651872dafcd82"
	// testOtherBTF is any kernel that is not a per-binding proof kernel.
	testOtherBTF = "eeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeee"
	// testRelease is the release of the fake running kernel.
	testRelease = "6.1.158-180.294.amzn2023.x86_64"
)

func testProductImages() map[string]config.SandboxSharedImage {
	return map[string]config.SandboxSharedImage{testBTF612: {Image: "shared:product", ProfileFile: "/etc/sandbox-shared-profiles/a.json", ManifestDigest: "sha256:" + strings.Repeat("b", 64)}}
}

// fakeKernel makes the running kernel btf: IG's product kernel gate admits it
// unless check names the check it fails (like fullruntime.SharedProductKernel,
// the refusal wraps the *KernelCheckError and ErrSharedNativeUnavailable).
func fakeKernel(t *testing.T, btf, check string) {
	t.Helper()
	gate, read := sharedProductKernel, runningKernelBTF
	t.Cleanup(func() { sharedProductKernel, runningKernelBTF = gate, read })
	runningKernelBTF = func() (string, error) { return btf, nil }
	sharedProductKernel = func() (fullruntime.KernelIdentity, error) {
		if check != "" {
			return fullruntime.KernelIdentity{}, fmt.Errorf("shared product node refused: %w: %w", &fullruntime.KernelCheckError{Check: check, Err: errors.New("fake " + check + " failure")}, fullruntime.ErrSharedNativeUnavailable)
		}
		return fullruntime.KernelIdentity{Arch: "amd64", Release: testRelease, BTF: btf, BuildID: "00"}, nil
	}
}

func readyCondition(t *testing.T, engine igbackend.FullEngine) metav1.Condition {
	t.Helper()
	shared, ok := engine.(*igbackend.SharedEngine)
	if !ok {
		t.Fatalf("engine %T, want the shared engine", engine)
	}
	status := &api.NodeStatus{Conditions: []metav1.Condition{{Type: "Ready", Status: metav1.ConditionTrue, Reason: "Reconciled"}}}
	igbackend.ApplySharedNodeHealth(status, shared.Health(), 1, metav1.Now())
	return status.Conditions[0]
}

// The compiled-in image is IG's g19pkg128 pin: its name, manifest digest
// and profile. A pin rotation in IG fails here until the image follows.
func TestCompiledInImageMatchesIGPin(t *testing.T) {
	pins := fullruntime.SharedProductImagePins()
	i := slices.IndexFunc(pins, func(p fullruntime.SharedProductImagePin) bool { return p.Profile == sharedProductProfile })
	if i < 0 {
		t.Fatalf("IG pins no %s image", sharedProductProfile)
	}
	pin := pins[i]
	image := compiledProductImage
	if image.Image != pin.Image || image.Image != "enforce-exec-shared:"+sharedProductProfile || image.ManifestDigest != pin.ManifestDigest || image.ProfileFile != "" {
		t.Fatalf("compiled-in image %+v, IG pin %+v", image, pin)
	}
	d, err := digest.Parse(image.ManifestDigest)
	if err != nil || d.Algorithm() != digest.SHA256 {
		t.Fatalf("manifest digest %q: %v", image.ManifestDigest, err)
	}
	if image.Profile == nil || *image.Profile != pin.SharedProfile {
		t.Fatalf("compiled-in profile %+v, IG pin %+v", image.Profile, pin.SharedProfile)
	}
	if _, err := image.Profile.Validate(); err != nil {
		t.Fatalf("profile: %v", err)
	}
	if p := pinnedProductProfile("g19pkg0"); p != nil {
		t.Fatalf("profile %+v for an unpinned image", p)
	}
}

// The engine comes from the running kernel. A runtime-less service makes
// the shared product constructor fail ("runtime and trusted shared image
// store"), which proves it was reached; the per-binding engine is proven by
// its legacy budget cap.
func TestDefaultEngineSelection(t *testing.T) {
	ctx := context.Background()
	const reachedShared = "runtime and trusted shared image store"
	for _, tc := range []struct {
		name   string
		btf    string
		check  string // the check IG's gate fails
		engine config.SandboxPolicyEngineConfig
		// want: "shared" (constructor reached), "per-binding", or the
		// Ready reason of a refused engine.
		want, message string
	}{
		{name: "admitted kernel", btf: testOtherBTF, want: "shared"},
		{name: "admitted AL2023 kernel", btf: testBTF612, want: "shared"},
		{name: "admitted kernel, ignored image entries", btf: testOtherBTF, engine: config.SandboxPolicyEngineConfig{SharedImages: testProductImages()}, want: "shared"},
		// The architecture or an identity check: KernelNotQualified.
		{name: "other architecture", btf: testOtherBTF, check: fullruntime.KernelCheckArch, want: "KernelNotQualified", message: "arch check"},
		{name: "unreadable BTF", btf: testOtherBTF, check: fullruntime.KernelCheckBTF, want: "KernelNotQualified", message: "btf check"},
		{name: "unreadable release", btf: testOtherBTF, check: fullruntime.KernelCheckRelease, want: "KernelNotQualified", message: "release check"},
		{name: "unreadable build-id", btf: testOtherBTF, check: fullruntime.KernelCheckBuildID, want: "KernelNotQualified", message: "build-id check"},
		// A control check: SharedEngineUnavailable with the check.
		{name: "no bpf LSM", btf: testOtherBTF, check: fullruntime.KernelCheckBPFLSM, want: "SharedEngineUnavailable", message: "fake bpf-lsm failure"},
		{name: "ftrace off", btf: testBTF612, check: fullruntime.KernelCheckFtrace, want: "SharedEngineUnavailable", message: "fake ftrace failure"},
		{name: "livepatched", btf: testOtherBTF, check: fullruntime.KernelCheckLivepatch, want: "SharedEngineUnavailable", message: "fake livepatch failure"},
		// A proof kernel stays per-binding, whatever IG's gate says.
		{name: "per-binding proof kernel", btf: fullruntime.SupportedKernelBTF, want: "per-binding"},
		{name: "per-binding Kubernetes proof kernel", btf: fullruntime.SupportedKubernetesKernelBTF, want: "per-binding"},
		{name: "proof kernel the gate refuses", btf: fullruntime.SupportedKernelBTF, check: fullruntime.KernelCheckFtrace, want: "per-binding"},
		{name: "proof kernel, old shared config", btf: fullruntime.SupportedKubernetesKernelBTF, engine: config.SandboxPolicyEngineConfig{Engine: "shared", SharedImages: testProductImages()}, want: "per-binding"},
		// Old keys keep loading; the engine key is ignored.
		{name: "old full engine", btf: testBTF612, engine: config.SandboxPolicyEngineConfig{Engine: "full", SharedImages: testProductImages()}, want: "shared"},
		{name: "old shared engine", btf: testBTF612, engine: config.SandboxPolicyEngineConfig{Engine: "shared", SharedImages: testProductImages()}, want: "shared"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			fakeKernel(t, tc.btf, tc.check)
			engine, err := newFullEngine(ctx, nil, nil, nil, ServiceOptions{Engine: tc.engine, MaxOwners: fullruntime.LegacyOwnerHardCap + 1}, nil)
			switch tc.want {
			case "shared":
				if err == nil || !strings.Contains(err.Error(), reachedShared) {
					t.Fatalf("shared engine not selected: %T %v", engine, err)
				}
			case "per-binding":
				if !errors.Is(err, fullruntime.ErrLegacyOwnerCap) {
					t.Fatalf("per-binding engine not selected: %T %v", engine, err)
				}
			default:
				if err != nil {
					t.Fatal(err)
				}
				c := readyCondition(t, engine)
				if c.Status != metav1.ConditionFalse || c.Reason != tc.want || !strings.Contains(c.Message, tc.message) {
					t.Fatalf("ready %+v", c)
				}
				if h := engine.(*igbackend.SharedEngine).Health(); h.Started || !errors.Is(h.Unavailable, fullruntime.ErrSharedNativeUnavailable) {
					t.Fatalf("refused engine %+v", h)
				}
			}
		})
	}
}

// selectKernelEngine returns the identity IG's gate admitted; a refusal
// keeps the check, and an error that names no check is a control refusal
// (never KernelNotQualified, never the shared engine).
func TestSelectKernelEngine(t *testing.T) {
	fakeKernel(t, testOtherBTF, "")
	if engine, id, err := selectKernelEngine(); err != nil || engine != engineShared || id.Release != testRelease || id.BTF != testOtherBTF {
		t.Fatalf("admitted: %v %+v %v", engine, id, err)
	}
	sharedProductKernel = func() (fullruntime.KernelIdentity, error) {
		return fullruntime.KernelIdentity{}, errors.New("gate failed")
	}
	if engine, _, err := selectKernelEngine(); engine != engineRefused || err == nil || errors.Is(err, igbackend.ErrKernelNotQualified) {
		t.Fatalf("untyped refusal: %v %v", engine, err)
	}
	fakeKernel(t, fullruntime.SupportedKernelBTF, fullruntime.KernelCheckArch)
	if engine, _, err := selectKernelEngine(); err != nil || engine != enginePerBinding {
		t.Fatalf("proof kernel: %v %v", engine, err)
	}
}

// Configuration never selects the engine or the image: the old engine key
// and sandboxPolicySharedImages, even an entry for the running kernel, are
// reported once as ignored on the warning path, and a kernel IG refuses
// stays refused.
func TestDefaultEngineConfigIgnored(t *testing.T) {
	image := config.SandboxSharedImage{Image: "shared:product", ProfileFile: "/p.json", ManifestDigest: "sha256:" + strings.Repeat("b", 64)}
	for name, engine := range map[string]config.SandboxPolicyEngineConfig{
		"image entry":                {SharedImages: map[string]config.SandboxSharedImage{testOtherBTF: image}},
		"image entry, shared engine": {Engine: "shared", SharedImages: map[string]config.SandboxSharedImage{testOtherBTF: image}},
		"image entry, full engine":   {Engine: "full", SharedImages: map[string]config.SandboxSharedImage{testOtherBTF: image}},
		"undigested image entry":     {SharedImages: map[string]config.SandboxSharedImage{testOtherBTF: {Image: "x"}}},
	} {
		t.Run(name, func(t *testing.T) {
			fakeKernel(t, testOtherBTF, fullruntime.KernelCheckArch)
			var reported, errs []string
			options := ServiceOptions{Engine: engine, OnWarning: func(err error) { reported = append(reported, err.Error()) }}
			e, err := newFullEngine(context.Background(), local.New(), nil, memory.New(), options, func(err error) { errs = append(errs, err.Error()) })
			if err != nil {
				t.Fatal(err)
			}
			if c := readyCondition(t, e); c.Reason != "KernelNotQualified" {
				t.Fatalf("ready %+v", c)
			}
			ignored := slices.DeleteFunc(slices.Clone(reported), func(r string) bool {
				return !strings.Contains(r, "sandboxPolicySharedImages is ignored") || !strings.Contains(r, testOtherBTF) || !strings.Contains(r, compiledProductImage.Image)
			})
			if len(ignored) != 1 {
				t.Fatalf("ignored entries not reported once: %q", reported)
			}
			if engine.Engine != "" && !slices.ContainsFunc(reported, func(r string) bool { return strings.Contains(r, "deprecated and ignored") }) {
				t.Fatalf("deprecated engine key not reported: %q", reported)
			}
			// Warnings stay off the error path; the refusal itself is an error.
			if slices.ContainsFunc(errs, func(r string) bool { return strings.Contains(r, "ignored") }) || !slices.ContainsFunc(errs, func(r string) bool { return strings.Contains(r, "architecture or identity check") }) {
				t.Fatalf("error path %q", errs)
			}
		})
	}
	// Without the keys nothing is reported.
	fakeKernel(t, testOtherBTF, fullruntime.KernelCheckArch)
	var reported []error
	if _, err := newFullEngine(context.Background(), local.New(), nil, memory.New(), ServiceOptions{OnWarning: func(err error) { reported = append(reported, err) }}, nil); err != nil || len(reported) != 0 {
		t.Fatalf("%v %v", reported, err)
	}
}

// Edge cases: a proof host whose BTF cannot be read is not per-binding (IG's
// gate decides, here refusing the BTF), and the old shared key on a proof
// kernel names the engine that runs.
func TestDefaultEngineSelectionEdges(t *testing.T) {
	ctx := context.Background()
	for _, tc := range []struct {
		name    string
		setup   func(t *testing.T)
		engine  config.SandboxPolicyEngineConfig
		reason  string // Ready reason of a refused engine; "" for per-binding
		message string // in the Ready message
		warning string // in a warning
	}{
		{
			name: "proof host with unreadable BTF",
			setup: func(t *testing.T) {
				fakeKernel(t, fullruntime.SupportedKernelBTF, fullruntime.KernelCheckBTF)
				runningKernelBTF = func() (string, error) { return "", errors.New("read /sys/kernel/btf/vmlinux: permission denied") }
			},
			reason: "KernelNotQualified", message: "btf check",
		},
		{
			name:    "old shared key on a proof kernel",
			setup:   func(t *testing.T) { fakeKernel(t, fullruntime.SupportedKubernetesKernelBTF, "") },
			engine:  config.SandboxPolicyEngineConfig{Engine: "shared"},
			warning: "sandboxPolicyEngine \"shared\" is deprecated and ignored",
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			tc.setup(t)
			var warnings []string
			options := ServiceOptions{Engine: tc.engine, MaxOwners: fullruntime.LegacyOwnerHardCap + 1, OnWarning: func(err error) { warnings = append(warnings, err.Error()) }}
			engine, err := newFullEngine(ctx, nil, nil, nil, options, nil)
			if tc.reason == "" {
				if !errors.Is(err, fullruntime.ErrLegacyOwnerCap) {
					t.Fatalf("per-binding engine not selected: %T %v", engine, err)
				}
			} else {
				if err != nil {
					t.Fatal(err)
				}
				if c := readyCondition(t, engine); c.Status != metav1.ConditionFalse || c.Reason != tc.reason || !strings.Contains(c.Message, tc.message) {
					t.Fatalf("ready %+v", c)
				}
			}
			if tc.warning != "" && !slices.ContainsFunc(warnings, func(w string) bool { return strings.Contains(w, tc.warning) }) {
				t.Fatalf("warnings %q, want %q", warnings, tc.warning)
			}
		})
	}
}

// A configuration the default build cannot validate is refused before any
// kernel check (unchanged from the engine-key era).
func TestDefaultEngineConfigRefused(t *testing.T) {
	fakeKernel(t, testBTF612, "")
	for name, engine := range map[string]config.SandboxPolicyEngineConfig{
		"unknown engine":                            {Engine: "legacy"},
		"qualification profile":                     {Engine: "shared", SharedProfileFile: "/etc/config/sandbox-shared-profile.json"},
		"qualification profile, per-binding engine": {SharedProfileFile: "/etc/config/sandbox-shared-profile.json"},
		"relative image host root":                  {SharedImageHostRoot: "host"},
	} {
		if _, err := newFullEngine(context.Background(), nil, nil, nil, ServiceOptions{Engine: engine, MaxOwners: 1}, nil); err == nil || strings.Contains(err.Error(), "runtime and trusted") {
			t.Fatalf("%s: %v", name, err)
		}
	}
}

// Selection happens at agent start, from ServiceOptions.Engine only (never
// the global viper). The agent's gate admits the fake kernel; the engine
// then runs IG's real gate again and binds the compiled-in image, which the
// empty store lacks: the engine is built unavailable with IG's typed reason,
// not with KernelNotQualified.
func TestDefaultSharedEngineSelectedAtStart(t *testing.T) {
	t.Cleanup(viper.Reset)
	viper.Reset()
	viper.Set("sandboxPolicyEngine", "legacy")
	fakeKernel(t, testOtherBTF, "")
	var reported []error
	engine, err := newFullEngine(context.Background(), local.New(), nil, memory.New(), ServiceOptions{Engine: config.SandboxPolicyEngineConfig{SharedImages: testProductImages()}}, func(err error) { reported = append(reported, err) })
	if err != nil {
		t.Fatal(err)
	}
	shared, ok := engine.(*igbackend.SharedEngine)
	if !ok {
		t.Fatalf("engine %T", engine)
	}
	if h := shared.Health(); h.Started || !errors.Is(h.Unavailable, fullruntime.ErrSharedNativeUnavailable) || errors.Is(h.Unavailable, igbackend.ErrKernelNotQualified) || len(reported) != 1 {
		t.Fatalf("health %+v reported %v", h, reported)
	}
}

// The engine configuration always carries the compiled-in image, whatever
// sandboxPolicySharedImages says.
func TestSharedProductConfig(t *testing.T) {
	c := sharedProductConfig(config.SandboxSharedProduct{Images: testProductImages(), ImageProcRoot: "/host/proc", ImageHostRoot: "/host"}, nil, ServiceOptions{ContainerdSocket: "/run/containerd/containerd.sock"})
	if c.Image.Image != compiledProductImage.Image || c.Image.ManifestDigest != compiledProductImage.ManifestDigest || c.Image.Profile != compiledProductImage.Profile || c.ContainerdAddress != "/run/containerd/containerd.sock" || c.ImageProcRoot != "/host/proc" || c.ImageHostRoot != "/host" {
		t.Fatalf("config %+v", c)
	}
}
