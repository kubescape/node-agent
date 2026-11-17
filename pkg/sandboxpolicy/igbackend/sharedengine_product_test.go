package igbackend

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	goruntime "runtime"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/inspektor-gadget/inspektor-gadget/gadgets/enforce_exec/fullruntime"
	"github.com/inspektor-gadget/inspektor-gadget/pkg/oci"
	"github.com/inspektor-gadget/inspektor-gadget/pkg/runtime/local"
	api "github.com/kubescape/storage/pkg/apis/sandbox/v1alpha1"
	"github.com/opencontainers/go-digest"
	"github.com/opencontainers/image-spec/specs-go"
	ocispec "github.com/opencontainers/image-spec/specs-go/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"oras.land/oras-go/v2/content/memory"
)

const testSharedProductProfile = `{"Version":1,"CandidateBytes":1048576,"Bindings":2,"PolicySlots":[4,2,1,1],"Tasks":20000,"Scratch":128,"InodeFacts":1024,"AcceptedUIDs":128,"Images":2,"CompileBytes":8388608,"CompileConcurrency":2,"TelemetryBytes":4096,"RolloutBytes":4096,"PossibleCPUs":64,"PerBinding":{"Tasks":10000,"Scratch":64,"InodeFacts":512,"AcceptedUIDs":64,"Images":1}}`

const testKernelBTF = "0d7b3abe2b50e1b252b167061fea565e78fb712b691d1c04dd5651872dafcd82"

// newProductFixture is a product engine whose fake receipts are attached.
func newProductFixture(t *testing.T) *sharedFixture {
	t.Helper()
	f := newEngineFixture(t, sharedProduct)
	f.node.onBind = func(s *fakeSharedSession) {
		s.status = func(st *fullruntime.SharedBindingStatus) { st.Attached = true }
	}
	return f
}

// Plan Q6/F4: a product binding is protected only when the node is Ready and
// IG reports it attached, published at the committed route generation, not
// WithdrawPending, with no refused adoption and no fault.
func TestSharedProductCheckContract(t *testing.T) {
	ctx := context.Background()
	f := newProductFixture(t)
	r, err := f.backend.Replace(ctx, f.binding, singlePlan())
	if err != nil || !r.Committed || r.ProtectionUnconfirmed {
		t.Fatalf("protected replace %+v %v", r, err)
	}
	if err := f.backend.Attest(ctx, f.binding, "combined-revision"); err != nil {
		t.Fatalf("attest: %v", err)
	}
	s := f.node.sessions[0]
	instance := f.backend.records[key(f.binding)].instance
	for _, tc := range []struct {
		name   string
		ready  error
		status func(*fullruntime.SharedBindingStatus)
		want   string
	}{
		{"node not ready", fmt.Errorf("receipt gone: %w", fullruntime.ErrSharedNodeNotReady), nil, "receipt gone"},
		{"not attached", nil, func(st *fullruntime.SharedBindingStatus) { st.Attached = false }, "not attached"},
		{"unpublished", nil, func(st *fullruntime.SharedBindingStatus) { st.RoutePublished = false }, "not published"},
		{"withdraw pending", nil, func(st *fullruntime.SharedBindingStatus) { st.WithdrawPending = true }, "withdrawal pending"},
		{"generation mismatch", nil, func(st *fullruntime.SharedBindingStatus) { st.Generation++ }, "generation"},
		{"adoption refused", nil, func(st *fullruntime.SharedBindingStatus) {
			st.Adoption = &fullruntime.SharedAdoptionStatus{Reason: "init outside cgroup"}
		}, "adoption refused"},
		{"fault", nil, func(st *fullruntime.SharedBindingStatus) { st.Fault = errors.New("route fault") }, "route fault"},
		{"removed", nil, func(st *fullruntime.SharedBindingStatus) { st.Removed = true }, "removed"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			f.node.ready = tc.ready
			s.status = func(st *fullruntime.SharedBindingStatus) {
				st.Attached = true
				if tc.status != nil {
					tc.status(st)
				}
			}
			err := instance.Check(ctx)
			if err == nil || !strings.Contains(err.Error(), tc.want) {
				t.Fatalf("check: %v", err)
			}
			if tc.ready != nil && !errors.Is(err, fullruntime.ErrSharedNodeNotReady) {
				t.Fatalf("node NotReady not typed: %v", err)
			}
			if err := f.backend.Attest(ctx, f.binding, "combined-revision"); err == nil {
				t.Fatal("attested an unprotected binding")
			}
		})
	}
	// Back to protected.
	f.node.ready = nil
	s.status = func(st *fullruntime.SharedBindingStatus) { st.Attached = true }
	if err := instance.Check(ctx); err != nil {
		t.Fatalf("restored check: %v", err)
	}
	// A reload is checked at its own committed route generation.
	next := singlePlan()
	next.Revision = "next"
	if r, err := f.backend.Replace(ctx, f.binding, next); err != nil || r.ProtectionUnconfirmed {
		t.Fatalf("reload %+v %v", r, err)
	}
	s.status = func(st *fullruntime.SharedBindingStatus) { st.Attached = true; st.Generation = 10 } // the previous route generation
	if err := instance.Check(ctx); err == nil {
		t.Fatal("protected at a superseded generation")
	}
}

func TestSharedProductCheckRequiresStartedNode(t *testing.T) {
	e := newSharedEngine(sharedProduct, nil, nil)
	if err := e.nodeReady(); !errors.Is(err, fullruntime.ErrSharedNativeUnavailable) {
		t.Fatalf("unstarted node ready: %v", err)
	}
}

func TestApplySharedNodeHealthProduct(t *testing.T) {
	now := metav1.Now()
	controllerReady := metav1.Condition{Type: "Ready", Status: metav1.ConditionTrue, Reason: "Reconciled", Message: "Selected containers have active enforcement"}
	apply := func(h SharedNodeHealth, conditions ...metav1.Condition) map[string]metav1.Condition {
		status := &api.NodeStatus{Conditions: append(conditions, metav1.Condition{Type: "ActiveRevision", Status: metav1.ConditionTrue})}
		ApplySharedNodeHealth(status, h, 4, now)
		out := map[string]metav1.Condition{}
		for _, c := range status.Conditions {
			out[c.Type] = c
		}
		if len(out) != 3 || out["ActiveRevision"].Status != metav1.ConditionTrue {
			t.Fatalf("conditions %+v", status.Conditions)
		}
		return out
	}
	healthy := SharedNodeHealth{Started: true, FailClosed: fullruntime.SharedFailClosedHealth{State: fullruntime.SharedFailClosedHealthy}}
	ledger := healthy
	ledger.Degraded = fmt.Errorf("image facts: %w", fullruntime.ErrSharedImageLedger)
	loss := healthy
	loss.Degraded = errors.Join(fmt.Errorf("lost=3: %w", fullruntime.ErrSharedVerdictEventLoss), fmt.Errorf("window: %w", fullruntime.ErrSharedFailClosedDegraded))
	adoption := healthy
	adoption.Degraded = errors.New("degraded: slot 1 cgroup 2 init 3 adoption refused")
	notReady := healthy
	notReady.Ready = fmt.Errorf("%w: reaper stopped", fullruntime.ErrSharedNodeNotReady)
	notReady.Degraded = adoption.Degraded
	witness := healthy
	witness.FailClosed.State = fullruntime.SharedFailClosedNotReady
	unavailable := SharedNodeHealth{Unavailable: fmt.Errorf("shared product engine unavailable: no image entry: %w", fullruntime.ErrSharedNativeUnavailable)}
	notQualified := SharedNodeHealth{Unavailable: fmt.Errorf("shared product engine unavailable: %w: btf check: %w", ErrKernelNotQualified, fullruntime.ErrSharedNativeUnavailable)}
	for _, tc := range []struct {
		name               string
		health             SharedNodeHealth
		controller         []metav1.Condition
		ready, readyReason string
		degradedReason     string
	}{
		{"unavailable at start", unavailable, []metav1.Condition{controllerReady}, "False", "SharedEngineUnavailable", ""},
		{"kernel not qualified", notQualified, []metav1.Condition{controllerReady}, "False", "KernelNotQualified", ""},
		{"not started", SharedNodeHealth{}, []metav1.Condition{controllerReady}, "False", "SharedNodeNotStarted", ""},
		{"ready keeps the controller's Ready", healthy, []metav1.Condition{controllerReady}, "True", "Reconciled", ""},
		{"ready keeps the controller's False", healthy, []metav1.Condition{{Type: "Ready", Status: metav1.ConditionFalse, Reason: "ProtectionUnconfirmed"}}, "False", "ProtectionUnconfirmed", ""},
		{"ready without controller Ready", healthy, nil, "False", "ReadyUnreported", ""},
		{"image ledger is Degraded only", ledger, []metav1.Condition{controllerReady}, "True", "Reconciled", "ImageLedger"},
		{"loss and fail-closed Degraded", loss, []metav1.Condition{controllerReady}, "True", "Reconciled", "FailClosedDegraded,VerdictEventLoss"},
		{"other Degraded", adoption, []metav1.Condition{controllerReady}, "True", "Reconciled", "SharedNodeDegraded"},
		{"node NotReady", notReady, []metav1.Condition{controllerReady}, "False", "SharedNodeNotReady", "SharedNodeDegraded"},
		{"fail-closed witness NotReady", witness, []metav1.Condition{controllerReady}, "False", "SharedNodeNotReady", ""},
	} {
		t.Run(tc.name, func(t *testing.T) {
			c := apply(tc.health, tc.controller...)
			ready, degraded := c["Ready"], c["Degraded"]
			if string(ready.Status) != tc.ready || ready.Reason != tc.readyReason {
				t.Fatalf("ready %+v", ready)
			}
			if (tc.degradedReason != "") != (degraded.Status == metav1.ConditionTrue) || tc.degradedReason != "" && degraded.Reason != tc.degradedReason {
				t.Fatalf("degraded %+v", degraded)
			}
		})
	}
	if c := apply(unavailable); !strings.Contains(c["Ready"].Message, "no image entry") {
		t.Fatalf("unavailable reason not reported: %+v", c["Ready"])
	}
	if c := apply(notReady, controllerReady); !strings.Contains(c["Ready"].Message, "reaper stopped") {
		t.Fatalf("NotReady reason not reported: %+v", c["Ready"])
	}
}

func TestSharedEngineHealthReadsProductDegraded(t *testing.T) {
	node := &fakeSharedNode{degraded: fullruntime.ErrSharedImageLedger}
	start := func(context.Context) (sharedNode, error) { return node, nil }
	e := newSharedEngine(sharedProduct, start, nil)
	if _, err := e.ensureNode(context.Background()); err != nil {
		t.Fatal(err)
	}
	if h := e.Health(); h.Qualification || h.Ready != nil || !errors.Is(h.Degraded, fullruntime.ErrSharedImageLedger) {
		t.Fatalf("health %+v", h)
	}
	e = newSharedEngine(sharedQualification, start, nil)
	if _, err := e.ensureNode(context.Background()); err != nil {
		t.Fatal(err)
	}
	if h := e.Health(); !h.Qualification || h.Degraded != nil {
		t.Fatalf("qualification health %+v", h)
	}
}

// testImageStore holds one image index tagged ref with the given platforms;
// it returns the store and the digest of the first manifest.
func testImageStore(t *testing.T, ref string, platforms ...*ocispec.Platform) (*memory.Store, string) {
	t.Helper()
	store, manifests := testImageStoreManifests(t, ref, platforms...)
	var first string
	if len(manifests) > 0 {
		first = manifests[0].Digest.String()
	}
	return store, first
}

// testImageStoreManifests is testImageStore returning every manifest
// descriptor; each manifest has its own config and layer.
func testImageStoreManifests(t *testing.T, ref string, platforms ...*ocispec.Platform) (*memory.Store, []ocispec.Descriptor) {
	t.Helper()
	ctx := context.Background()
	store := memory.New()
	push := func(mediaType string, data []byte) ocispec.Descriptor {
		desc := ocispec.Descriptor{MediaType: mediaType, Digest: digest.FromBytes(data), Size: int64(len(data))}
		if err := store.Push(ctx, desc, bytes.NewReader(data)); err != nil {
			t.Fatal(err)
		}
		return desc
	}
	var manifests []ocispec.Descriptor
	for i, platform := range platforms {
		config := push(ocispec.MediaTypeImageConfig, fmt.Appendf(nil, `{"manifest":%d}`, i))
		layer := push("application/vnd.gadget.ebpf.program.v1+binary", fmt.Appendf(nil, "elf-%d", i))
		data, err := json.Marshal(ocispec.Manifest{Versioned: specs.Versioned{SchemaVersion: 2}, MediaType: ocispec.MediaTypeImageManifest, Config: config, Layers: []ocispec.Descriptor{layer}})
		if err != nil {
			t.Fatal(err)
		}
		desc := push(ocispec.MediaTypeImageManifest, data)
		desc.Platform = platform
		manifests = append(manifests, desc)
	}
	data, err := json.Marshal(ocispec.Index{Versioned: specs.Versioned{SchemaVersion: 2}, MediaType: ocispec.MediaTypeImageIndex, Manifests: manifests})
	if err != nil {
		t.Fatal(err)
	}
	index := push(ocispec.MediaTypeImageIndex, data)
	if err := store.Tag(ctx, index, ref); err != nil {
		t.Fatal(err)
	}
	return store, manifests
}

func TestVerifySharedManifest(t *testing.T) {
	ctx := context.Background()
	host := &ocispec.Platform{OS: "linux", Architecture: goruntime.GOARCH}
	other := &ocispec.Platform{OS: "linux", Architecture: "s390x"}
	// IG normalizes a name without a registry to its default registry and
	// adds the tag latest; the store holds the normalized name.
	store, manifest := testImageStore(t, "ghcr.io/inspektor-gadget/gadget/shared:abi3-development", host, other)
	if err := verifySharedManifest(ctx, store, "shared:abi3-development", manifest); err != nil {
		t.Fatalf("matching manifest: %v", err)
	}
	if err := verifySharedManifest(ctx, store, "ghcr.io/inspektor-gadget/gadget/shared:abi3-development", manifest); err != nil {
		t.Fatalf("matching normalized manifest: %v", err)
	}
	mismatch := digest.FromString("another manifest").String()
	if err := verifySharedManifest(ctx, store, "shared:abi3-development", mismatch); !errors.Is(err, ErrSharedManifestMismatch) {
		t.Fatalf("mismatching manifest: %v", err)
	}
	if err := verifySharedManifest(ctx, store, "shared:other", manifest); err == nil {
		t.Fatal("unknown tag accepted")
	}
	twice, first := testImageStore(t, "ghcr.io/inspektor-gadget/gadget/shared:latest", host, host)
	if err := verifySharedManifest(ctx, twice, "shared", first); err == nil || !strings.Contains(err.Error(), "2 manifests") {
		t.Fatalf("ambiguous index: %v", err)
	}
	none, _ := testImageStore(t, "ghcr.io/inspektor-gadget/gadget/shared:latest", other)
	if err := verifySharedManifest(ctx, none, "shared", manifest); err == nil || !strings.Contains(err.Error(), "0 manifests") {
		t.Fatalf("no manifest for this architecture: %v", err)
	}
	noPlatform, first := testImageStore(t, "ghcr.io/inspektor-gadget/gadget/shared:latest", nil, host)
	if err := verifySharedManifest(ctx, noPlatform, "shared", first); err == nil || !strings.Contains(err.Error(), "no platform") {
		t.Fatalf("manifest without platform: %v", err)
	}
	// A tag on a manifest (not an index) is refused, as IG refuses it.
	direct, _ := testImageStore(t, "ghcr.io/inspektor-gadget/gadget/shared:latest", host)
	desc, err := direct.Resolve(ctx, "ghcr.io/inspektor-gadget/gadget/shared:latest")
	if err != nil {
		t.Fatal(err)
	}
	data, err := direct.Fetch(ctx, desc)
	if err != nil {
		t.Fatal(err)
	}
	var index ocispec.Index
	if err := json.NewDecoder(data).Decode(&index); err != nil {
		t.Fatal(err)
	}
	_ = data.Close()
	if err := direct.Tag(ctx, index.Manifests[0], "ghcr.io/inspektor-gadget/gadget/direct:latest"); err != nil {
		t.Fatal(err)
	}
	if err := verifySharedManifest(ctx, direct, "direct", index.Manifests[0].Digest.String()); err == nil || !strings.Contains(err.Error(), "not an image index") {
		t.Fatalf("manifest tag: %v", err)
	}
}

func writeTestProfile(t *testing.T, body string) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), "profile.json")
	if err := os.WriteFile(path, []byte(body), 0o600); err != nil {
		t.Fatal(err)
	}
	return path
}

func TestLoadSharedProfile(t *testing.T) {
	profile, err := LoadSharedProfile(writeTestProfile(t, testSharedProductProfile))
	if err != nil || profile.Bindings != 2 || profile.PerBinding.Tasks != 10000 {
		t.Fatalf("profile %+v %v", profile, err)
	}
	for name, body := range map[string]string{
		"unknown field": strings.Replace(testSharedProductProfile, `"Version":1`, `"Version":1,"Extra":1`, 1),
		"invalid":       strings.Replace(testSharedProductProfile, `"Bindings":2`, `"Bindings":0`, 1),
		"broken":        "{",
	} {
		if _, err := LoadSharedProfile(writeTestProfile(t, body)); err == nil || !strings.Contains(err.Error(), "shared profile") {
			t.Fatalf("%s accepted: %v", name, err)
		}
	}
	if _, err := LoadSharedProfile(filepath.Join(t.TempDir(), "missing.json")); err == nil {
		t.Fatal("missing profile accepted")
	}
}

// Selection happens at construction (agent start). Any refusal leaves an
// engine that never starts and reports the typed reason; nothing falls back.
func TestSharedProductEngineSelection(t *testing.T) {
	ctx := context.Background()
	const ref = "ghcr.io/inspektor-gadget/gadget/shared:abi3-development"
	store, manifest := testImageStore(t, ref, &ocispec.Platform{OS: "linux", Architecture: goruntime.GOARCH})
	profile := writeTestProfile(t, testSharedProductProfile)
	entry := SharedProductImage{Image: ref, ProfileFile: profile, ManifestDigest: manifest}
	config := SharedProductConfig{Images: map[string]SharedProductImage{testKernelBTF: entry}, Store: store, ContainerdAddress: "/run/containerd/containerd.sock"}
	selected := func(m map[string]SharedProductImage) (string, SharedProductImage, error) {
		e, ok := m[testKernelBTF]
		if !ok {
			return "", e, fmt.Errorf("fake: no entry: %w", fullruntime.ErrSharedNativeUnavailable)
		}
		return testKernelBTF, e, nil
	}
	refused := func(map[string]SharedProductImage) (string, SharedProductImage, error) {
		return "", SharedProductImage{}, fmt.Errorf("fake: kernel release refused: %w", fullruntime.ErrSharedNativeUnavailable)
	}
	untyped := func(map[string]SharedProductImage) (string, SharedProductImage, error) {
		return "", SharedProductImage{}, errors.New("fake: untyped")
	}
	if _, err := newSharedProductEngine(ctx, nil, config, nil, selected); err == nil {
		t.Fatal("engine without runtime")
	}
	withEntry := func(mutate func(*SharedProductImage)) SharedProductConfig {
		c := config
		e := entry
		mutate(&e)
		c.Images = map[string]SharedProductImage{testKernelBTF: e}
		return c
	}
	for _, tc := range []struct {
		name   string
		config SharedProductConfig
		sel    func(map[string]SharedProductImage) (string, SharedProductImage, error)
		want   string
	}{
		{"refused kernel", config, refused, "kernel release refused"},
		{"no entry for the running kernel", SharedProductConfig{Images: map[string]SharedProductImage{strings.Repeat("a", 64): entry}, Store: store}, selected, "no entry"},
		{"untyped selection error", config, untyped, "untyped"},
		{"manifest digest mismatch", withEntry(func(e *SharedProductImage) { e.ManifestDigest = digest.FromString("x").String() }), selected, "manifest digest mismatch"},
		{"missing image", withEntry(func(e *SharedProductImage) { e.Image = "ghcr.io/x/missing:latest" }), selected, "missing"},
		{"bad profile", withEntry(func(e *SharedProductImage) { e.ProfileFile = writeTestProfile(t, "{") }), selected, "shared profile"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			var reported []error
			e, err := newSharedProductEngine(ctx, local.New(), tc.config, func(err error) { reported = append(reported, err) }, tc.sel)
			if err != nil {
				t.Fatal(err)
			}
			h := e.Health()
			if h.Started || h.Qualification || !errors.Is(h.Unavailable, fullruntime.ErrSharedNativeUnavailable) || !strings.Contains(h.Unavailable.Error(), tc.want) {
				t.Fatalf("health %+v", h)
			}
			if tc.name == "manifest digest mismatch" && !errors.Is(h.Unavailable, ErrSharedManifestMismatch) {
				t.Fatalf("mismatch not typed: %v", h.Unavailable)
			}
			if len(reported) != 1 {
				t.Fatalf("reported %v", reported)
			}
			if _, err := e.ensureNode(ctx); !errors.Is(err, fullruntime.ErrSharedNativeUnavailable) {
				t.Fatalf("unavailable engine started: %v", err)
			}
			status := &api.NodeStatus{Conditions: []metav1.Condition{{Type: "Ready", Status: metav1.ConditionTrue}}}
			ApplySharedNodeHealth(status, h, 1, metav1.Now())
			if status.Conditions[0].Status != metav1.ConditionFalse || status.Conditions[0].Reason != "SharedEngineUnavailable" {
				t.Fatalf("ready %+v", status.Conditions[0])
			}
		})
	}
	e, err := newSharedProductEngine(ctx, local.New(), config, nil, selected)
	if err != nil || e.unavailable != nil || e.start == nil || e.mode != sharedProduct {
		t.Fatalf("selected engine %+v %v", e, err)
	}
	// A compiled-in entry carries its profile: no profile file is read.
	compiledProfile, err := LoadSharedProfile(writeTestProfile(t, testSharedProductProfile))
	if err != nil {
		t.Fatal(err)
	}
	compiled := withEntry(func(e *SharedProductImage) { e.ProfileFile, e.Profile = "/nonexistent", &compiledProfile })
	if e, err := newSharedProductEngine(ctx, local.New(), compiled, nil, selected); err != nil || e.unavailable != nil {
		t.Fatalf("compiled-in profile %+v %v", e, err)
	}
}

// An engine refused before selection (the agent's own kernel table) never
// starts, wraps ErrSharedNativeUnavailable, keeps a typed reason and is
// reported once.
func TestNewUnavailableSharedEngine(t *testing.T) {
	for name, tc := range map[string]struct {
		reason error
		want   string
	}{
		"kernel not qualified": {fmt.Errorf("%w: btf check: kernel BTF sha256 x", ErrKernelNotQualified), "KernelNotQualified"},
		"control check":        {errors.New("ftrace is not enabled"), "SharedEngineUnavailable"},
	} {
		t.Run(name, func(t *testing.T) {
			var reported []error
			e := NewUnavailableSharedEngine(tc.reason, func(err error) { reported = append(reported, err) })
			h := e.Health()
			if h.Started || h.Qualification || !errors.Is(h.Unavailable, fullruntime.ErrSharedNativeUnavailable) || !errors.Is(h.Unavailable, tc.reason) || len(reported) != 1 {
				t.Fatalf("health %+v reported %v", h, reported)
			}
			if _, err := e.ensureNode(context.Background()); !errors.Is(err, fullruntime.ErrSharedNativeUnavailable) {
				t.Fatalf("unavailable engine started: %v", err)
			}
			status := &api.NodeStatus{Conditions: []metav1.Condition{{Type: "Ready", Status: metav1.ConditionTrue}}}
			ApplySharedNodeHealth(status, h, 1, metav1.Now())
			if c := status.Conditions[0]; c.Status != metav1.ConditionFalse || c.Reason != tc.want || !strings.Contains(c.Message, tc.reason.Error()) {
				t.Fatalf("ready %+v", c)
			}
		})
	}
}

// The real selection on whatever kernel runs the test: no entry matches the
// running build (the table holds only an unrelated digest), so the engine is
// unavailable with IG's typed reason, whether the kernel is pinned or not.
func TestSharedProductEngineRealSelectionRefuses(t *testing.T) {
	store, manifest := testImageStore(t, "ghcr.io/inspektor-gadget/gadget/shared:latest", &ocispec.Platform{OS: "linux", Architecture: goruntime.GOARCH})
	config := SharedProductConfig{Images: map[string]SharedProductImage{strings.Repeat("f", 64): {Image: "shared", ProfileFile: "/nonexistent", ManifestDigest: manifest}}, Store: store}
	e, err := NewSharedProductEngine(context.Background(), local.New(), config, nil)
	if err != nil {
		t.Fatal(err)
	}
	if h := e.Health(); !errors.Is(h.Unavailable, fullruntime.ErrSharedNativeUnavailable) {
		t.Fatalf("health %+v", h)
	}
	empty, err := NewSharedProductEngine(context.Background(), local.New(), SharedProductConfig{Store: store}, nil)
	if err != nil || !errors.Is(empty.Health().Unavailable, fullruntime.ErrSharedNativeUnavailable) {
		t.Fatalf("empty table %v", err)
	}
}

// A commit whose receipt carries another generation than compiled, or a zero
// receipt scope, is committed with an error. The fault latches: Check fails
// after it and on every later re-attestation, and Health reports it, until a
// clean commit (the compiled generation, the registered nonzero scope).
func TestSharedProductLatchesCommitFaults(t *testing.T) {
	ctx := context.Background()
	for _, tc := range []struct {
		name   string
		induce func(*fakeSharedSession)
		fix    func(*fakeSharedSession)
		want   string
	}{
		{"zero receipt scope", func(s *fakeSharedSession) { s.receiptScope = new(uint64) }, func(s *fakeSharedSession) { s.receiptScope = nil }, "without a scope"},
		{"receipt generation", func(s *fakeSharedSession) { s.receiptGeneration = 1 }, func(s *fakeSharedSession) { s.receiptGeneration = 0 }, "committed generation"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			f := newProductFixture(t)
			var s *fakeSharedSession
			f.node.onBind = func(session *fakeSharedSession) {
				s = session
				session.status = func(st *fullruntime.SharedBindingStatus) { st.Attached = true }
				tc.induce(session)
			}
			r, err := f.backend.Replace(ctx, f.binding, singlePlan())
			if !r.Committed || err == nil || !strings.Contains(err.Error(), tc.want) {
				t.Fatalf("faulted commit %+v %v", r, err)
			}
			instance := f.backend.records[key(f.binding)].instance
			// IG reports the binding protected at its route generation: only
			// the latched fault fails Check.
			if err := s.Inspect().Protected(s.route); err != nil {
				t.Fatalf("fake not protected: %v", err)
			}
			for range 2 {
				if err := instance.Check(ctx); err == nil || !strings.Contains(err.Error(), "protocol fault") || !strings.Contains(err.Error(), tc.want) {
					t.Fatalf("check after fault: %v", err)
				}
				// A no-op re-Replace re-attests and stays unprotected.
				if r, err := f.backend.Replace(ctx, f.binding, singlePlan()); err == nil || !r.ProtectionUnconfirmed {
					t.Fatalf("re-replace %+v %v", r, err)
				}
			}
			if h := f.engine.Health(); !strings.Contains(fmt.Sprint(h.BindingFaults), tc.want) {
				t.Fatalf("health %+v", h)
			}
			status := &api.NodeStatus{}
			ApplySharedNodeHealth(status, f.engine.Health(), 1, metav1.Now())
			if status.Conditions[1].Status != metav1.ConditionTrue || !strings.Contains(status.Conditions[1].Reason, "BindingProtocolFault") {
				t.Fatalf("degraded %+v", status.Conditions[1])
			}
			// A clean commit clears it.
			tc.fix(s)
			next := singlePlan()
			next.Revision = "next"
			if r, err := f.backend.Replace(ctx, f.binding, next); err != nil || r.ProtectionUnconfirmed {
				t.Fatalf("clean commit %+v %v", r, err)
			}
			if err := instance.Check(ctx); err != nil {
				t.Fatalf("check after clean commit: %v", err)
			}
			if h := f.engine.Health(); h.BindingFaults != nil {
				t.Fatalf("health after clean commit %+v", h)
			}
		})
	}
}

// Health never waits on a node start in progress.
func TestSharedEngineHealthDuringStart(t *testing.T) {
	entered, release := make(chan struct{}), make(chan struct{})
	node := &fakeSharedNode{}
	e := newSharedEngine(sharedProduct, func(context.Context) (sharedNode, error) {
		close(entered)
		<-release
		return node, nil
	}, nil)
	var wg sync.WaitGroup
	wg.Add(1)
	go func() {
		defer wg.Done()
		_, _ = e.ensureNode(context.Background())
	}()
	<-entered
	done := make(chan SharedNodeHealth)
	go func() { done <- e.Health() }()
	select {
	case h := <-done:
		if h.Started {
			t.Fatalf("health %+v", h)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("Health waited on the start")
	}
	if err := e.nodeReady(); err == nil {
		t.Fatal("node Ready during its start")
	}
	close(release)
	wg.Wait()
	if h := e.Health(); !h.Started {
		t.Fatalf("health after start %+v", h)
	}
}

// A failed start is reported (SharedNodeStartFailed) and retried only after
// a growing backoff; a later successful start clears it.
func TestSharedEngineStartFailureBackoff(t *testing.T) {
	ctx := context.Background()
	clock := time.Unix(1000, 0)
	starts, startErr := 0, errors.New("collection refused")
	node := &fakeSharedNode{}
	e := newSharedEngine(sharedProduct, func(context.Context) (sharedNode, error) {
		starts++
		if startErr != nil {
			return nil, startErr
		}
		return node, nil
	}, nil)
	e.now = func() time.Time { return clock }
	if _, err := e.ensureNode(ctx); !errors.Is(err, startErr) || starts != 1 {
		t.Fatalf("first start %v (%d)", err, starts)
	}
	h := e.Health()
	if !errors.Is(h.StartErr, startErr) {
		t.Fatalf("health %+v", h)
	}
	status := &api.NodeStatus{}
	ApplySharedNodeHealth(status, h, 1, metav1.Now())
	if ready := status.Conditions[0]; ready.Status != metav1.ConditionFalse || ready.Reason != "SharedNodeStartFailed" || !strings.Contains(ready.Message, "collection refused") {
		t.Fatalf("ready %+v", ready)
	}
	// Within the backoff no start runs; the last error is returned.
	if _, err := e.ensureNode(ctx); !errors.Is(err, startErr) || !strings.Contains(err.Error(), "retry in") || starts != 1 {
		t.Fatalf("start within backoff %v (%d)", err, starts)
	}
	clock = clock.Add(sharedStartBackoffMin)
	if _, err := e.ensureNode(ctx); !errors.Is(err, startErr) || starts != 2 {
		t.Fatalf("start after backoff %v (%d)", err, starts)
	}
	// The backoff doubles: one minimum later is still too early.
	clock = clock.Add(sharedStartBackoffMin)
	if _, err := e.ensureNode(ctx); err == nil || starts != 2 {
		t.Fatalf("start within doubled backoff %v (%d)", err, starts)
	}
	for range 10 {
		clock = clock.Add(sharedStartBackoffMax)
		_, _ = e.ensureNode(ctx)
	}
	if e.startBackoff != sharedStartBackoffMax {
		t.Fatalf("backoff %s", e.startBackoff)
	}
	startErr = nil
	clock = clock.Add(sharedStartBackoffMax)
	if n, err := e.ensureNode(ctx); err != nil || n != node {
		t.Fatalf("recovered start %v", err)
	}
	if h := e.Health(); !h.Started || h.StartErr != nil {
		t.Fatalf("health %+v", h)
	}
}

// Close refuses while a Start holds a cgroup reservation (its Bind may run
// on the node), and no Start reserves a cgroup after Close found none.
func TestSharedEngineCloseStartRace(t *testing.T) {
	ctx := context.Background()
	f := newProductFixture(t)
	var closeErr error
	f.node.onBind = func(s *fakeSharedSession) {
		s.status = func(st *fullruntime.SharedBindingStatus) { st.Attached = true }
		closeErr = f.engine.Close(ctx) // races the Bind in progress
	}
	program, err := CompileFull(f.binding, singlePlan(), 1, nil)
	if err != nil {
		t.Fatal(err)
	}
	config := FullStartConfig{Binding: f.binding, Program: program, Plan: singlePlan(), Acquire: func(context.Context) (fullruntime.BindingLease, error) { return &fullTestLease{}, nil }}
	i, err := f.engine.Start(ctx, "x", config, nil)
	if err != nil || closeErr == nil || !strings.Contains(closeErr.Error(), "still owns") || f.node.stops != 0 {
		t.Fatalf("start %v, close during bind %v, stops %d", err, closeErr, f.node.stops)
	}
	if err := i.Stop(ctx); err != nil {
		t.Fatal(err)
	}
	// Close found no binding: a Start that already holds the node (it passed
	// ensureNode before Close) is refused at its reservation.
	f.node.onBind = nil
	if err := f.engine.Close(ctx); err != nil || f.node.stops != 1 {
		t.Fatalf("close %v stops %d", err, f.node.stops)
	}
	f.engine.nodeMu.Lock()
	f.engine.node = f.node // as if Start read it before Close
	f.engine.nodeMu.Unlock()
	f.engine.closed = false
	sessions := len(f.node.sessions)
	if _, err := f.engine.Start(ctx, "y", config, nil); err == nil || !strings.Contains(err.Error(), "closed") || len(f.node.sessions) != sessions {
		t.Fatalf("start after close %v sessions %d", err, len(f.node.sessions))
	}
}

// Drift guard: IG's own manifest selection (oci.GetManifestForHost, what the
// OCI handler loads) picks the manifest verifySharedManifest accepted, for a
// short name, a ghcr.io name and a registry with a port.
func TestVerifySharedManifestMatchesIG(t *testing.T) {
	ctx := context.Background()
	host := &ocispec.Platform{OS: "linux", Architecture: goruntime.GOARCH}
	other := &ocispec.Platform{OS: "linux", Architecture: "s390x"}
	for _, tc := range []struct{ image, stored string }{
		{"shared:abi3-development", "ghcr.io/inspektor-gadget/gadget/shared:abi3-development"},
		{"shared", "ghcr.io/inspektor-gadget/gadget/shared:latest"},
		{"ghcr.io/kubescape/shared:6.12", "ghcr.io/kubescape/shared:6.12"},
		{"localhost:5000/kubescape/shared:6.18", "localhost:5000/kubescape/shared:6.18"},
	} {
		t.Run(tc.image, func(t *testing.T) {
			store, manifests := testImageStoreManifests(t, tc.stored, other, host)
			accepted := manifests[1]
			if err := verifySharedManifest(ctx, store, tc.image, accepted.Digest.String()); err != nil {
				t.Fatalf("verify: %v", err)
			}
			data, err := store.Fetch(ctx, accepted)
			if err != nil {
				t.Fatal(err)
			}
			var want ocispec.Manifest
			if err := json.NewDecoder(data).Decode(&want); err != nil {
				t.Fatal(err)
			}
			_ = data.Close()
			got, err := oci.GetManifestForHost(ctx, store, tc.image)
			if err != nil {
				t.Fatalf("IG: %v", err)
			}
			if got.Config.Digest != want.Config.Digest || got.Layers[0].Digest != want.Layers[0].Digest {
				t.Fatalf("IG loads config %s, verified %s", got.Config.Digest, want.Config.Digest)
			}
		})
	}
}

// After an agent restart the new engine starts from nothing: the binding is
// not protected (ProtectionUnconfirmed, Attest fails) until the node is Ready
// and IG reports the binding attached and published at the committed
// generation; only then does the backend confirm protection (the controller
// reports Ready True only from confirmed bindings).
func TestSharedProductRestartUnprotectedUntilProtected(t *testing.T) {
	ctx := context.Background()
	f := newProductFixture(t)
	attached := false
	f.node.ready = fmt.Errorf("%w: capsule witness not yet sampled", fullruntime.ErrSharedNodeNotReady)
	f.node.onBind = func(s *fakeSharedSession) {
		s.status = func(st *fullruntime.SharedBindingStatus) { st.Attached = attached }
	}
	r, err := f.backend.Replace(ctx, f.binding, singlePlan())
	if !r.Committed || !r.ProtectionUnconfirmed || !errors.Is(err, fullruntime.ErrSharedNodeNotReady) {
		t.Fatalf("first replace after restart %+v %v", r, err)
	}
	// Node Ready, receipts not yet attached: still unprotected.
	f.node.ready = nil
	if r, err := f.backend.Replace(ctx, f.binding, singlePlan()); err == nil || !r.ProtectionUnconfirmed {
		t.Fatalf("unattached %+v %v", r, err)
	}
	if err := f.backend.Attest(ctx, f.binding, "combined-revision"); err == nil {
		t.Fatal("attested before the receipts")
	}
	attached = true
	if r, err := f.backend.Replace(ctx, f.binding, singlePlan()); err != nil || r.ProtectionUnconfirmed {
		t.Fatalf("protected %+v %v", r, err)
	}
	if err := f.backend.Attest(ctx, f.binding, "combined-revision"); err != nil {
		t.Fatalf("attest: %v", err)
	}
}
