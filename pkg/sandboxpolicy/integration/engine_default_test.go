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
	// testBTF and testOtherBTF are two fake kernels (any BTF: no kernel list
	// exists).
	testBTF      = "1111111111111111111111111111111111111111111111111111111111111111"
	testOtherBTF = "eeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeee"
	// testRelease is the release of the fake running kernel.
	testRelease = "6.1.0-test.x86_64"
)

func testProductImages() map[string]config.SandboxSharedImage {
	return map[string]config.SandboxSharedImage{testBTF: {Image: "shared:product", ProfileFile: "/etc/sandbox-shared-profiles/a.json", ManifestDigest: "sha256:" + strings.Repeat("b", 64)}}
}

// fakeKernel makes the running kernel btf: IG's product kernel gate admits it
// unless check names the check it fails (like fullruntime.SharedProductKernel,
// the refusal wraps the *KernelCheckError and ErrSharedNativeUnavailable).
func fakeKernel(t *testing.T, btf, check string) {
	t.Helper()
	gate := sharedProductKernel
	t.Cleanup(func() { sharedProductKernel = gate })
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
// store"), which proves it was reached.
func TestDefaultEngineSelection(t *testing.T) {
	ctx := context.Background()
	const reachedShared = "runtime and trusted shared image store"
	for _, tc := range []struct {
		name   string
		btf    string
		check  string // the check IG's gate fails
		engine config.SandboxPolicyEngineConfig
		// want: "shared" (constructor reached) or the Ready reason of a
		// refused engine.
		want, message string
	}{
		{name: "admitted kernel", btf: testOtherBTF, want: "shared"},
		{name: "another admitted kernel", btf: testBTF, want: "shared"},
		{name: "admitted kernel, ignored image entries", btf: testOtherBTF, engine: config.SandboxPolicyEngineConfig{SharedImages: testProductImages()}, want: "shared"},
		// The architecture or an identity check: KernelNotQualified.
		{name: "other architecture", btf: testOtherBTF, check: fullruntime.KernelCheckArch, want: "KernelNotQualified", message: "arch check"},
		{name: "unreadable BTF", btf: testOtherBTF, check: fullruntime.KernelCheckBTF, want: "KernelNotQualified", message: "btf check"},
		{name: "unreadable release", btf: testOtherBTF, check: fullruntime.KernelCheckRelease, want: "KernelNotQualified", message: "release check"},
		{name: "unreadable build-id", btf: testOtherBTF, check: fullruntime.KernelCheckBuildID, want: "KernelNotQualified", message: "build-id check"},
		// A control check: SharedEngineUnavailable with the check.
		{name: "no bpf LSM", btf: testOtherBTF, check: fullruntime.KernelCheckBPFLSM, want: "SharedEngineUnavailable", message: "fake bpf-lsm failure"},
		{name: "ftrace off", btf: testBTF, check: fullruntime.KernelCheckFtrace, want: "SharedEngineUnavailable", message: "fake ftrace failure"},
		{name: "livepatched", btf: testOtherBTF, check: fullruntime.KernelCheckLivepatch, want: "SharedEngineUnavailable", message: "fake livepatch failure"},
		// Old keys keep loading; the engine key is ignored.
		{name: "old full engine", btf: testBTF, engine: config.SandboxPolicyEngineConfig{Engine: "full", SharedImages: testProductImages()}, want: "shared"},
		{name: "old shared engine", btf: testBTF, engine: config.SandboxPolicyEngineConfig{Engine: "shared", SharedImages: testProductImages()}, want: "shared"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			fakeKernel(t, tc.btf, tc.check)
			engine, err := newFullEngine(ctx, nil, nil, nil, ServiceOptions{Engine: tc.engine, ImageName: "enforce_exec:old", MaxOwners: 3}, nil)
			switch tc.want {
			case "shared":
				if err == nil || !strings.Contains(err.Error(), reachedShared) {
					t.Fatalf("shared engine not selected: %T %v", engine, err)
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
	fakeKernel(t, testBTF, fullruntime.KernelCheckArch)
	if engine, _, err := selectKernelEngine(); engine != engineRefused || !errors.Is(err, igbackend.ErrKernelNotQualified) {
		t.Fatalf("arch refusal: %v %v", engine, err)
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
	// sandboxPolicyImage is a legacy key: reported once as ignored, never
	// used.
	reported = nil
	if _, err := newFullEngine(context.Background(), local.New(), nil, memory.New(), ServiceOptions{ImageName: "enforce_exec:old", OnWarning: func(err error) { reported = append(reported, err) }}, nil); err != nil || len(reported) != 1 || !strings.Contains(reported[0].Error(), "sandboxPolicyImage \"enforce_exec:old\" is ignored") {
		t.Fatalf("%v %v", reported, err)
	}
}

// Edge cases: a host whose BTF IG cannot read is refused
// (KernelNotQualified), and the old shared key is reported as ignored while
// the shared engine runs.
func TestDefaultEngineSelectionEdges(t *testing.T) {
	ctx := context.Background()
	for _, tc := range []struct {
		name    string
		setup   func(t *testing.T)
		engine  config.SandboxPolicyEngineConfig
		reason  string // Ready reason of a refused engine; "" for the shared engine
		message string // in the Ready message
		warning string // in a warning
	}{
		{
			name: "host with unreadable BTF",
			setup: func(t *testing.T) {
				fakeKernel(t, testBTF, fullruntime.KernelCheckBTF)
			},
			reason: "KernelNotQualified", message: "btf check",
		},
		{
			name:    "old shared key",
			setup:   func(t *testing.T) { fakeKernel(t, testBTF, "") },
			engine:  config.SandboxPolicyEngineConfig{Engine: "shared"},
			warning: "sandboxPolicyEngine \"shared\" is deprecated and ignored",
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			tc.setup(t)
			var warnings []string
			options := ServiceOptions{Engine: tc.engine, OnWarning: func(err error) { warnings = append(warnings, err.Error()) }}
			engine, err := newFullEngine(ctx, nil, nil, nil, options, nil)
			if tc.reason == "" {
				if err == nil || !strings.Contains(err.Error(), "runtime and trusted shared image store") {
					t.Fatalf("shared engine not selected: %T %v", engine, err)
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
	fakeKernel(t, testBTF, "")
	for name, engine := range map[string]config.SandboxPolicyEngineConfig{
		"unknown engine":                   {Engine: "legacy"},
		"qualification profile":            {Engine: "shared", SharedProfileFile: "/etc/config/sandbox-shared-profile.json"},
		"qualification profile, no engine": {SharedProfileFile: "/etc/config/sandbox-shared-profile.json"},
		"relative image host root":         {SharedImageHostRoot: "host"},
	} {
		if _, err := newFullEngine(context.Background(), nil, nil, nil, ServiceOptions{Engine: engine}, nil); err == nil || strings.Contains(err.Error(), "runtime and trusted") {
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
