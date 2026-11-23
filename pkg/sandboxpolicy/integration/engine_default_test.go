//go:build !sandbox_shared_qualification

package integration

import (
	"context"
	"errors"
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
	// testUnqualifiedBTF is a kernel in no table.
	testUnqualifiedBTF = "eeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeee"
)

func testProductImages() map[string]config.SandboxSharedImage {
	return map[string]config.SandboxSharedImage{testBTF612: {Image: "shared:product", ProfileFile: "/etc/sandbox-shared-profiles/a.json", ManifestDigest: "sha256:" + strings.Repeat("b", 64)}}
}

// testProbedRelease is the release of a fake kernel IG admits on its probes.
const testProbedRelease = "6.1.158-180.294.amzn2023.x86_64"

// fakeKernel makes the running kernel btf: VerifyKernel admits it only if it
// is in the list it is given (a release/build-id or control failure when
// check says so), like fullruntime.VerifyKernel. AdmitKernel admits any other
// kernel as probed unless check is a control check (see fakeProbe).
func fakeKernel(t *testing.T, btf, check string) {
	t.Helper()
	verify, admit, read := verifyKernel, admitKernel, runningKernelBTF
	t.Cleanup(func() { verifyKernel, admitKernel, runningKernelBTF = verify, admit, read })
	runningKernelBTF = func() (string, error) { return btf, nil }
	admitKernel = func(qualified []fullruntime.KernelIdentity) (fullruntime.KernelIdentity, fullruntime.KernelTier, error) {
		switch check {
		case fullruntime.KernelCheckBPFLSM, fullruntime.KernelCheckFtrace, fullruntime.KernelCheckLivepatch:
			return fullruntime.KernelIdentity{}, "", &fullruntime.KernelCheckError{Check: check, Err: errors.New("fake " + check + " failure")}
		}
		if i := slices.IndexFunc(qualified, func(id fullruntime.KernelIdentity) bool { return id.BTF == btf }); i >= 0 && check == "" {
			return qualified[i], fullruntime.KernelTierQualified, nil
		}
		return fullruntime.KernelIdentity{Arch: "amd64", Release: testProbedRelease, BTF: btf, BuildID: "00"}, fullruntime.KernelTierProbed, nil
	}
	verifyKernel = func(qualified []fullruntime.KernelIdentity) (fullruntime.KernelIdentity, error) {
		i := slices.IndexFunc(qualified, func(id fullruntime.KernelIdentity) bool { return id.BTF == btf })
		switch {
		case i < 0:
			return fullruntime.KernelIdentity{}, &fullruntime.KernelCheckError{Check: fullruntime.KernelCheckBTF, Err: errors.New("kernel BTF sha256 " + btf + " is not a qualified kernel build")}
		case check != "":
			return fullruntime.KernelIdentity{}, &fullruntime.KernelCheckError{Check: check, Err: errors.New("fake " + check + " failure")}
		}
		return qualified[i], nil
	}
}

// fakeProbe makes AdmitKernel refuse every kernel outside the list with
// check, as IG's probed admission does ("...; probed admission refused").
func fakeProbe(t *testing.T, check string) {
	t.Helper()
	admit := admitKernel
	t.Cleanup(func() { admitKernel = admit })
	admitKernel = func(qualified []fullruntime.KernelIdentity) (fullruntime.KernelIdentity, fullruntime.KernelTier, error) {
		return fullruntime.KernelIdentity{}, "", &fullruntime.KernelCheckError{Check: check, Err: errors.New("not a qualified kernel build; probed admission refused: fake " + check + " probe failure")}
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

// The compiled-in table is a subset of IG's qualified kernels (it can narrow,
// never widen, them) and every compiled-in image is pinned by digest.
func TestSharedProductKernelsQualified(t *testing.T) {
	qualified := fullruntime.QualifiedKernels()
	seen := map[string]struct{}{}
	for _, k := range sharedProductKernels {
		if !slices.Contains(qualified, k.Kernel) {
			t.Fatalf("%+v is not an IG qualified kernel %+v", k.Kernel, qualified)
		}
		if _, dup := seen[k.Kernel.BTF]; dup {
			t.Fatalf("BTF %s listed twice", k.Kernel.BTF)
		}
		seen[k.Kernel.BTF] = struct{}{}
		if k.Image == nil {
			continue
		}
		d, err := digest.Parse(k.Image.ManifestDigest)
		if err != nil || d.Algorithm() != digest.SHA256 || k.Image.Image == "" || k.Image.Profile == nil {
			t.Fatalf("%s: compiled-in image %+v must carry a name, a sha256 manifest digest and a profile (%v)", k.Kernel.Release, k.Image, err)
		}
		if _, err := k.Image.Profile.Validate(); err != nil {
			t.Fatalf("%s: profile: %v", k.Kernel.Release, err)
		}
	}
	if len(sharedProductKernels) == 0 {
		t.Fatal("empty kernel table")
	}
	for btf := range perBindingProofKernels {
		if _, ok := seen[btf]; ok {
			t.Fatalf("proof kernel %s is in the shared table", btf)
		}
	}
}

// Every kernel has its compiled-in g19pkg128 image, and the image, its
// manifest digest and its profile are IG's pin for that kernel: a pin
// rotation in IG fails here until the table is updated.
func TestCompiledInImagesMatchIGPins(t *testing.T) {
	pins := fullruntime.SharedProductImagePins()
	for _, k := range sharedProductKernels {
		if k.Image == nil {
			t.Fatalf("%s: no compiled-in image", k.Kernel.Release)
		}
		i := slices.IndexFunc(pins, func(p fullruntime.SharedProductImagePin) bool {
			return p.BTF == k.Kernel.BTF && p.Profile == sharedProductProfile
		})
		if i < 0 {
			t.Fatalf("%s: IG pins no %s image for BTF %s", k.Kernel.Release, sharedProductProfile, k.Kernel.BTF)
		}
		pin := pins[i]
		if pin.Release != k.Kernel.Release || k.Image.Image != pin.Image || k.Image.ManifestDigest != pin.ManifestDigest || k.Image.ProfileFile != "" {
			t.Fatalf("%s: compiled-in image %+v, IG pin %+v", k.Kernel.Release, *k.Image, pin)
		}
		if k.Image.Profile == nil || *k.Image.Profile != pin.SharedProfile {
			t.Fatalf("%s: compiled-in profile %+v, IG pin %+v", k.Kernel.Release, k.Image.Profile, pin.SharedProfile)
		}
	}
	if p := pinnedProductProfile(testBTF612, "g19pkg0"); p != nil {
		t.Fatalf("profile %+v for an unpinned image", p)
	}
}

// The engine comes from the kernel identity. A runtime-less service makes
// the shared product constructor fail ("runtime and trusted shared image
// store"), which proves it was reached; the per-binding engine is proven by
// its legacy budget cap.
func TestDefaultEngineSelection(t *testing.T) {
	ctx := context.Background()
	const reachedShared = "runtime and trusted shared image store"
	compiled := []sharedProductKernel{{Kernel: sharedProductKernels[0].Kernel, Image: &igbackend.SharedProductImage{Image: "shared:compiled", ManifestDigest: "sha256:" + strings.Repeat("c", 64), Profile: &fullruntime.SharedProfile{}}}}
	unpinned := []sharedProductKernel{{Kernel: sharedProductKernels[0].Kernel}}
	for _, tc := range []struct {
		name   string
		btf    string
		check  string // a failing kernel check of a table kernel
		probe  string // a failing probe of a kernel outside the table
		engine config.SandboxPolicyEngineConfig
		table  []sharedProductKernel
		// want: "shared" (constructor reached), "per-binding", or the
		// Ready reason of a refused engine.
		want, message string
	}{
		{name: "qualified kernel with a configured image", btf: testBTF612, table: unpinned, engine: config.SandboxPolicyEngineConfig{SharedImages: testProductImages()}, want: "shared"},
		{name: "qualified kernel with the shipped image", btf: testBTF612, want: "shared"},
		{name: "qualified kernel with a compiled-in image", btf: testBTF612, table: compiled, want: "shared"},
		{name: "compiled-in image beats configuration", btf: testBTF612, table: compiled, engine: config.SandboxPolicyEngineConfig{SharedImages: testProductImages()}, want: "shared"},
		{name: "qualified kernel without an image", btf: testBTF612, table: unpinned, want: "SharedEngineUnavailable", message: "no product image is pinned"},
		{name: "qualified kernel failing ftrace", btf: testBTF612, check: fullruntime.KernelCheckFtrace, engine: config.SandboxPolicyEngineConfig{SharedImages: testProductImages()}, want: "SharedEngineUnavailable", message: "fake ftrace failure"},
		// Any other kernel IG admits on its probes runs the shared engine on
		// the compiled-in image; a refused probe keeps the reason.
		{name: "qualified BTF with another build-id: probed", btf: testBTF612, check: fullruntime.KernelCheckBuildID, engine: config.SandboxPolicyEngineConfig{SharedImages: testProductImages()}, want: "shared"},
		{name: "unqualified kernel: probed", btf: testUnqualifiedBTF, want: "shared"},
		{name: "unqualified kernel, old shared config: probed", btf: testUnqualifiedBTF, engine: config.SandboxPolicyEngineConfig{Engine: "shared", SharedImages: testProductImages()}, want: "shared"},
		{name: "probed kernel without a compiled-in image", btf: testUnqualifiedBTF, table: unpinned, engine: config.SandboxPolicyEngineConfig{SharedImages: testProductImages()}, want: "KernelNotQualified", message: "no product image is compiled in"},
		{name: "unqualified kernel, other architecture", btf: testUnqualifiedBTF, probe: fullruntime.KernelCheckArch, want: "KernelNotQualified", message: "arch check"},
		{name: "unqualified kernel, unreadable build-id", btf: testUnqualifiedBTF, probe: fullruntime.KernelCheckBuildID, want: "KernelNotQualified", message: "build-id check"},
		{name: "unqualified kernel without the bpf LSM", btf: testUnqualifiedBTF, probe: fullruntime.KernelCheckBPFLSM, want: "SharedEngineUnavailable", message: "fake bpf-lsm probe failure"},
		{name: "unqualified kernel with ftrace off", btf: testUnqualifiedBTF, check: fullruntime.KernelCheckFtrace, want: "SharedEngineUnavailable", message: "fake ftrace failure"},
		{name: "per-binding proof kernel", btf: fullruntime.SupportedKernelBTF, want: "per-binding"},
		{name: "per-binding Kubernetes proof kernel", btf: fullruntime.SupportedKubernetesKernelBTF, want: "per-binding"},
		{name: "proof kernel, old shared config", btf: fullruntime.SupportedKubernetesKernelBTF, engine: config.SandboxPolicyEngineConfig{Engine: "shared", SharedImages: testProductImages()}, want: "per-binding"},
		// Old keys keep loading; the engine key is ignored.
		{name: "old full engine", btf: testBTF612, engine: config.SandboxPolicyEngineConfig{Engine: "full", SharedImages: testProductImages()}, want: "shared"},
		{name: "old shared engine", btf: testBTF612, engine: config.SandboxPolicyEngineConfig{Engine: "shared", SharedImages: testProductImages()}, want: "shared"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			fakeKernel(t, tc.btf, tc.check)
			if tc.probe != "" {
				fakeProbe(t, tc.probe)
			}
			table := sharedProductKernels
			if tc.table != nil {
				table = tc.table
			}
			engine, err := newKernelEngine(ctx, nil, nil, nil, ServiceOptions{Engine: tc.engine, MaxOwners: fullruntime.LegacyOwnerHardCap + 1}, nil, table)
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
			}
		})
	}
}

// Configuration never adds a kernel: an image entry, a compiled-in looking
// entry or the old engine key for the running kernel, which is not in the
// table and fails IG's probes, is never used, and the ignored entry is
// reported.
func TestDefaultEngineConfigCannotAddKernels(t *testing.T) {
	image := config.SandboxSharedImage{Image: "shared:product", ProfileFile: "/p.json", ManifestDigest: "sha256:" + strings.Repeat("b", 64)}
	for name, engine := range map[string]config.SandboxPolicyEngineConfig{
		"image entry":                {SharedImages: map[string]config.SandboxSharedImage{testUnqualifiedBTF: image}},
		"image entry, shared engine": {Engine: "shared", SharedImages: map[string]config.SandboxSharedImage{testUnqualifiedBTF: image}},
		"image entry, full engine":   {Engine: "full", SharedImages: map[string]config.SandboxSharedImage{testUnqualifiedBTF: image}},
	} {
		t.Run(name, func(t *testing.T) {
			fakeKernel(t, testUnqualifiedBTF, "")
			fakeProbe(t, fullruntime.KernelCheckArch)
			var reported, errs []string
			options := ServiceOptions{Engine: engine, OnWarning: func(err error) { reported = append(reported, err.Error()) }}
			e, err := newKernelEngine(context.Background(), local.New(), nil, memory.New(), options, func(err error) { errs = append(errs, err.Error()) }, sharedProductKernels)
			if err != nil {
				t.Fatal(err)
			}
			if c := readyCondition(t, e); c.Reason != "KernelNotQualified" {
				t.Fatalf("ready %+v", c)
			}
			if !slices.ContainsFunc(reported, func(r string) bool {
				return strings.Contains(r, "outside the agent's qualified table") && strings.Contains(r, testUnqualifiedBTF)
			}) {
				t.Fatalf("ignored entry not reported: %q", reported)
			}
			if engine.Engine != "" && !slices.ContainsFunc(reported, func(r string) bool { return strings.Contains(r, "deprecated and ignored") }) {
				t.Fatalf("deprecated engine key not reported: %q", reported)
			}
			// Warnings stay off the error path; the refusal itself is an error.
			if slices.ContainsFunc(errs, func(r string) bool { return strings.Contains(r, "ignored") }) || !slices.ContainsFunc(errs, func(r string) bool { return strings.Contains(r, "not a qualified kernel build") }) {
				t.Fatalf("error path %q", errs)
			}
		})
	}
}

// Edge cases of the kernel check: a proof host whose BTF cannot be read is
// refused (never per-binding), a malformed table fails closed through
// KernelCheckQualifiedList, and the warnings name what configuration was
// ignored and why.
func TestDefaultEngineSelectionEdges(t *testing.T) {
	ctx := context.Background()
	pinned := []sharedProductKernel{{Kernel: sharedProductKernels[0].Kernel, Image: &igbackend.SharedProductImage{Image: "shared:compiled", ManifestDigest: "sha256:" + strings.Repeat("c", 64), Profile: &fullruntime.SharedProfile{}}}}
	malformed := []sharedProductKernel{{Kernel: fullruntime.KernelIdentity{Arch: "x86_64", Release: "6.12", BTF: testBTF612, BuildID: "00"}}}
	for _, tc := range []struct {
		name    string
		setup   func(t *testing.T)
		table   []sharedProductKernel
		engine  config.SandboxPolicyEngineConfig
		reason  string // Ready reason of a refused engine; "" for per-binding
		message string // in the Ready message
		warning string // in a warning
	}{
		{
			name: "proof host with unreadable BTF",
			setup: func(t *testing.T) {
				fakeKernel(t, fullruntime.SupportedKernelBTF, "")
				fakeProbe(t, fullruntime.KernelCheckBTF)
				runningKernelBTF = func() (string, error) { return "", errors.New("read /sys/kernel/btf/vmlinux: permission denied") }
			},
			reason: "KernelNotQualified", message: "btf check",
		},
		{
			name: "malformed table",
			setup: func(t *testing.T) {
				verify, read := verifyKernel, runningKernelBTF
				t.Cleanup(func() { verifyKernel, runningKernelBTF = verify, read })
				verifyKernel = fullruntime.VerifyKernel // the real list check
				runningKernelBTF = func() (string, error) { return testUnqualifiedBTF, nil }
			},
			table: malformed, reason: "SharedEngineUnavailable", message: "malformed qualified kernel",
		},
		{
			name:  "config entry for a compiled-in image",
			setup: func(t *testing.T) { fakeKernel(t, testUnqualifiedBTF, ""); fakeProbe(t, fullruntime.KernelCheckArch) },
			table: pinned, engine: config.SandboxPolicyEngineConfig{SharedImages: testProductImages()},
			reason: "KernelNotQualified", warning: "kernels with a compiled-in image are ignored: " + testBTF612,
		},
		{
			name:    "old shared key on a proof kernel",
			setup:   func(t *testing.T) { fakeKernel(t, fullruntime.SupportedKubernetesKernelBTF, "") },
			engine:  config.SandboxPolicyEngineConfig{Engine: "shared"},
			warning: "per-binding engine selected on proof kernel; sandboxPolicyEngine \"shared\" ignored",
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			tc.setup(t)
			table := sharedProductKernels
			if tc.table != nil {
				table = tc.table
			}
			var warnings []string
			options := ServiceOptions{Engine: tc.engine, MaxOwners: fullruntime.LegacyOwnerHardCap + 1, OnWarning: func(err error) { warnings = append(warnings, err.Error()) }}
			engine, err := newKernelEngine(ctx, nil, nil, nil, options, nil, table)
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
		"undigested image":                          {SharedImages: map[string]config.SandboxSharedImage{testBTF612: {Image: "shared:product", ProfileFile: "/p.json"}}},
	} {
		if _, err := newKernelEngine(context.Background(), nil, nil, nil, ServiceOptions{Engine: engine, MaxOwners: 1}, nil, sharedProductKernels); err == nil || strings.Contains(err.Error(), "runtime and trusted") {
			t.Fatalf("%s: %v", name, err)
		}
	}
}

// Selection happens at agent start, from ServiceOptions.Engine only (never
// the global viper). The qualified kernel's image passes the agent's table;
// IG's own gate (SelectSharedProductImage) then refuses this host, which is
// not the pinned build: the engine is built unavailable with IG's typed
// reason, not with KernelNotQualified.
func TestDefaultSharedEngineSelectedAtStart(t *testing.T) {
	t.Cleanup(viper.Reset)
	viper.Reset()
	viper.Set("sandboxPolicyEngine", "legacy")
	fakeKernel(t, testBTF612, "")
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

func TestSharedProductConfig(t *testing.T) {
	image := igbackend.SharedProductImage{Image: "shared:product", ProfileFile: "/etc/sandbox-shared-profiles/a.json", ManifestDigest: "sha256:" + strings.Repeat("b", 64)}
	c := sharedProductConfig(config.SandboxSharedProduct{Images: testProductImages(), ImageProcRoot: "/host/proc", ImageHostRoot: "/host"}, testBTF612, fullruntime.KernelTierQualified, sharedProductKernels[0].Kernel, image, nil, ServiceOptions{ContainerdSocket: "/run/containerd/containerd.sock"})
	if len(c.Images) != 1 || c.Images[testBTF612] != image || c.Tier != fullruntime.KernelTierQualified || c.ContainerdAddress != "/run/containerd/containerd.sock" || c.ImageProcRoot != "/host/proc" || c.ImageHostRoot != "/host" {
		t.Fatalf("config %+v", c)
	}
	probedKernel := fullruntime.KernelIdentity{Arch: "amd64", Release: testProbedRelease, BTF: testUnqualifiedBTF, BuildID: "00"}
	c = sharedProductConfig(config.SandboxSharedProduct{}, fullruntime.SharedProbedKernelEntry, fullruntime.KernelTierProbed, probedKernel, image, nil, ServiceOptions{})
	if len(c.Images) != 1 || c.Images[fullruntime.SharedProbedKernelEntry] != image || c.Tier != fullruntime.KernelTierProbed || c.Kernel != probedKernel {
		t.Fatalf("probed config %+v", c)
	}
}

// A probed kernel runs on the compiled-in image, and that image is the same
// for every kernel of the table (IG stage 1: one CO-RE object per profile).
func TestProbedProductImageIsCommon(t *testing.T) {
	image := probedProductImage(sharedProductKernels)
	if image == nil {
		t.Fatal("no probed image")
	}
	for _, k := range sharedProductKernels {
		if k.Image == nil || k.Image.ManifestDigest != image.ManifestDigest || *k.Image.Profile != *image.Profile {
			t.Fatalf("%s: image %+v, probed image %+v", k.Kernel.Release, k.Image, image)
		}
	}
	if probedProductImage([]sharedProductKernel{{Kernel: sharedProductKernels[0].Kernel}}) != nil {
		t.Fatal("a table without images has a probed image")
	}
	// selectKernelEngine returns it with the running identity and Tier probed.
	fakeKernel(t, testUnqualifiedBTF, "")
	engine, k, err := selectKernelEngine(sharedProductKernels)
	if err != nil || engine != engineShared || k.Tier != fullruntime.KernelTierProbed || k.Kernel.BTF != testUnqualifiedBTF || k.Kernel.Release != testProbedRelease || k.Image == nil || *k.Image != *image {
		t.Fatalf("probed selection: %v %+v %v", engine, k, err)
	}
	// A qualified kernel is Tier qualified; a proof kernel stays per-binding.
	fakeKernel(t, testBTF612, "")
	if engine, k, err := selectKernelEngine(sharedProductKernels); err != nil || engine != engineShared || k.Tier != fullruntime.KernelTierQualified {
		t.Fatalf("qualified selection: %v %+v %v", engine, k, err)
	}
	fakeKernel(t, fullruntime.SupportedKernelBTF, "")
	if engine, _, err := selectKernelEngine(sharedProductKernels); err != nil || engine != enginePerBinding {
		t.Fatalf("proof kernel: %v %v", engine, err)
	}
}

// The KernelProbed message names the probed sections and the kernel; it is
// empty when nothing runs probed.
func TestProbedKernelNote(t *testing.T) {
	if note := probedKernelNote(nil, fullruntime.KernelIdentity{}); note != "" {
		t.Fatalf("nothing probed: %q", note)
	}
	note := probedKernelNote([]string{"exec", "privilege", "file"}, fullruntime.KernelIdentity{Release: testProbedRelease})
	for _, want := range []string{testProbedRelease, "not a qualified build", "exec, privilege, file", "probes"} {
		if !strings.Contains(note, want) {
			t.Fatalf("note %q lacks %q", note, want)
		}
	}
}

// The agent's table and IG's pins are the same builds: IG decides the tier
// again (SelectSharedProductImage), so a kernel IG pins that the table lacks
// would be sent as probed and refused by IG (fail closed, but enforcement
// off). A pin rotation in IG fails here until the table follows.
func TestSharedProductKernelsAreIGPins(t *testing.T) {
	var table []fullruntime.KernelIdentity
	for _, k := range sharedProductKernels {
		table = append(table, k.Kernel)
	}
	qualified := fullruntime.QualifiedKernels()
	slices.SortFunc(table, func(a, b fullruntime.KernelIdentity) int { return strings.Compare(a.Release, b.Release) })
	if !slices.Equal(table, qualified) {
		t.Fatalf("agent table %+v, IG pins %+v", table, qualified)
	}
}
