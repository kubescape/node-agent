//go:build sandbox_shared_qualification

package integration

import (
	"context"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/inspektor-gadget/inspektor-gadget/gadgets/enforce_exec/fullruntime"
	"github.com/kubescape/node-agent/pkg/config"
	"github.com/kubescape/node-agent/pkg/sandboxpolicy"
	"github.com/kubescape/node-agent/pkg/sandboxpolicy/igbackend"
	api "github.com/kubescape/storage/pkg/apis/sandbox/v1alpha1"
	"github.com/spf13/viper"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

const testSharedProfile = `{"Version":1,"CandidateBytes":1048576,"Bindings":2,"PolicySlots":[4,2,1,1],"Tasks":20000,"Scratch":128,"InodeFacts":1024,"AcceptedUIDs":128,"Images":2,"CompileBytes":8388608,"CompileConcurrency":2,"TelemetryBytes":4096,"RolloutBytes":4096,"PossibleCPUs":64,"PerBinding":{"Tasks":10000,"Scratch":64,"InodeFacts":512,"AcceptedUIDs":64,"Images":1}}`

func TestLoadSharedProfile(t *testing.T) {
	dir := t.TempDir()
	write := func(name, body string) string {
		path := filepath.Join(dir, name)
		if err := os.WriteFile(path, []byte(body), 0o600); err != nil {
			t.Fatal(err)
		}
		return path
	}
	profile, err := loadSharedProfile(write("ok.json", testSharedProfile))
	if err != nil || profile.Bindings != 2 || profile.PerBinding.Tasks != 10000 {
		t.Fatalf("profile %+v %v", profile, err)
	}
	for name, body := range map[string]string{
		"unknown.json": strings.Replace(testSharedProfile, `"Version":1`, `"Version":1,"Extra":1`, 1),
		"invalid.json": strings.Replace(testSharedProfile, `"Bindings":2`, `"Bindings":0`, 1),
		"broken.json":  "{",
	} {
		if _, err := loadSharedProfile(write(name, body)); err == nil {
			t.Fatalf("%s accepted", name)
		}
	}
	if _, err := loadSharedProfile(filepath.Join(dir, "missing.json")); err == nil {
		t.Fatal("missing profile accepted")
	}
	c := sharedEngineConfig(config.SandboxSharedQualification{ImageProcRoot: "/host/proc", ImageHostRoot: "/host"}, profile, nil, ServiceOptions{ImageName: "sandbox:abi3-development", ContainerdSocket: "/run/containerd/containerd.sock"})
	if c.Image != "sandbox:abi3-development" || c.ContainerdAddress != "/run/containerd/containerd.sock" || c.ImageProcRoot != "/host/proc" || c.ImageHostRoot != "/host" || c.Profile.Bindings != 2 {
		t.Fatalf("engine config %+v", c)
	}
}

func TestNewFullEngineSelection(t *testing.T) {
	// Selection uses only ServiceOptions.Engine: a global viper holding
	// another file (EKS run 14: clusterData.json) must not change it.
	t.Cleanup(viper.Reset)
	viper.Reset()
	if _, err := newFullEngine(nil, nil, nil, ServiceOptions{Engine: config.SandboxPolicyEngineConfig{Engine: "legacy"}}, nil); err == nil {
		t.Fatal("accepted unknown engine")
	}
	shared := config.SandboxPolicyEngineConfig{Engine: "shared", SharedProfileFile: filepath.Join(t.TempDir(), "missing.json")}
	if _, err := newFullEngine(nil, nil, nil, ServiceOptions{Engine: shared}, nil); err == nil || !strings.Contains(err.Error(), "shared profile") {
		t.Fatalf("shared engine without profile: %v", err)
	}
	// The shared engine builds no legacy per-cgroup Owner budget: an owner
	// count IG's budget refuses does not block it (it fails later, on its
	// own missing runtime).
	profileFile := filepath.Join(t.TempDir(), "profile.json")
	if err := os.WriteFile(profileFile, []byte(testSharedProfile), 0o600); err != nil {
		t.Fatal(err)
	}
	shared.SharedProfileFile = profileFile
	for _, owners := range []uint64{0, fullruntime.LegacyOwnerHardCap + 1} {
		if _, err := newFullEngine(nil, nil, nil, ServiceOptions{MaxOwners: owners, Engine: shared}, nil); err == nil || strings.Contains(err.Error(), "budget") || !strings.Contains(err.Error(), "runtime and trusted shared candidate") {
			t.Fatalf("shared engine with %d owners: %v", owners, err)
		}
	}
	// The global viper is ignored, whatever it holds.
	viper.Set("sandboxPolicyEngine", "shared")
	viper.Set("sandboxPolicySharedProfileFile", profileFile)
	// The full engine stays the default, builds the legacy budget at the
	// cap (refusing above it) and validates its own inputs.
	if _, err := newFullEngine(nil, nil, nil, ServiceOptions{MaxOwners: fullruntime.LegacyOwnerHardCap + 1}, nil); !errors.Is(err, fullruntime.ErrLegacyOwnerCap) {
		t.Fatalf("default engine above the cap: %v", err)
	}
	if _, err := newFullEngine(nil, nil, nil, ServiceOptions{MaxOwners: fullruntime.LegacyOwnerHardCap}, nil); err == nil || !strings.Contains(err.Error(), "Kubernetes operator") {
		t.Fatalf("default engine: %v", err)
	}
}

type capturingStatusWriter struct{ got *api.SandboxPolicyNodeStatus }

func (w *capturingStatusWriter) WriteStatus(_ context.Context, r *api.SandboxPolicyNodeStatus) error {
	w.got = r
	return nil
}

type fakeSharedHealthEngine struct {
	igbackend.FullEngine
	health igbackend.SharedNodeHealth
}

func (e fakeSharedHealthEngine) Health() igbackend.SharedNodeHealth { return e.health }

func TestEngineStatusWriterAppliesSharedHealth(t *testing.T) {
	inner := &capturingStatusWriter{}
	// A non-shared engine's writes are unchanged.
	if w := engineStatusWriter(nil, inner); w != sandboxpolicy.StatusWriter(inner) {
		t.Fatalf("per-binding engine wrapped: %T", w)
	}
	health := igbackend.SharedNodeHealth{Started: true, Ready: fmt.Errorf("loss: %w", fullruntime.ErrSharedVerdictEventLoss), FailClosed: fullruntime.SharedFailClosedHealth{State: fullruntime.SharedFailClosedHealthy}}
	w := engineStatusWriter(fakeSharedHealthEngine{health: health}, inner)
	now := metav1.Now()
	report := &api.SandboxPolicyNodeStatus{Status: &api.NodeStatus{ObservedGeneration: 4, LastReported: now, Conditions: []metav1.Condition{{Type: "Ready", Status: metav1.ConditionTrue, Reason: "Reconciled"}, {Type: "ActiveRevision", Status: metav1.ConditionTrue}}}}
	if err := w.WriteStatus(context.Background(), report); err != nil {
		t.Fatal(err)
	}
	if report.Status.Conditions[0].Status != metav1.ConditionTrue {
		t.Fatal("caller's report mutated")
	}
	conditions := map[string]metav1.Condition{}
	for _, c := range inner.got.Status.Conditions {
		conditions[c.Type] = c
	}
	ready, degraded := conditions["Ready"], conditions["Degraded"]
	if ready.Status != metav1.ConditionFalse || ready.ObservedGeneration != 4 || degraded.Status != metav1.ConditionTrue || degraded.Reason != "VerdictEventLoss" || conditions["ActiveRevision"].Type == "" {
		t.Fatalf("conditions %+v", inner.got.Status.Conditions)
	}
}
