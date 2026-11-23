//go:build sandbox_shared_qualification

package integration

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/kubescape/node-agent/pkg/config"
	"github.com/kubescape/node-agent/pkg/sandboxpolicy/igbackend"
	"github.com/spf13/viper"
)

const testSharedProfile = `{"Version":1,"CandidateBytes":1048576,"Bindings":2,"PolicySlots":[4,2,1,1],"Tasks":20000,"Scratch":128,"InodeFacts":1024,"AcceptedUIDs":128,"Images":2,"CompileBytes":8388608,"CompileConcurrency":2,"TelemetryBytes":4096,"RolloutBytes":4096,"PossibleCPUs":64,"PerBinding":{"Tasks":10000,"Scratch":64,"InodeFacts":512,"AcceptedUIDs":64,"Images":1}}`

func writeSharedProfile(t *testing.T) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), "profile.json")
	if err := os.WriteFile(path, []byte(testSharedProfile), 0o600); err != nil {
		t.Fatal(err)
	}
	return path
}

// The product image map never selects the qualification engine.
func TestQualificationRefusesProductImages(t *testing.T) {
	product := config.SandboxPolicyEngineConfig{Engine: "shared", SharedProfileFile: writeSharedProfile(t), SharedImages: map[string]config.SandboxSharedImage{strings.Repeat("a", 64): {Image: "x", ProfileFile: "/p.json", ManifestDigest: "sha256:" + strings.Repeat("b", 64)}}}
	if _, err := newFullEngine(context.Background(), nil, nil, nil, ServiceOptions{Engine: product}, nil); err == nil || !strings.Contains(err.Error(), "sandboxPolicySharedImages") {
		t.Fatalf("qualification build took product images: %v", err)
	}
}

func TestSharedEngineConfig(t *testing.T) {
	profile, err := igbackend.LoadSharedProfile(writeSharedProfile(t))
	if err != nil {
		t.Fatal(err)
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
	if _, err := newFullEngine(context.Background(), nil, nil, nil, ServiceOptions{Engine: config.SandboxPolicyEngineConfig{Engine: "legacy"}}, nil); err == nil {
		t.Fatal("accepted unknown engine")
	}
	shared := config.SandboxPolicyEngineConfig{Engine: "shared", SharedProfileFile: filepath.Join(t.TempDir(), "missing.json")}
	if _, err := newFullEngine(context.Background(), nil, nil, nil, ServiceOptions{Engine: shared}, nil); err == nil || !strings.Contains(err.Error(), "shared profile") {
		t.Fatalf("shared engine without profile: %v", err)
	}
	// The legacy sandboxPolicyMaxOwners is ignored: any value reaches the engine's own
	// missing runtime.
	profileFile := writeSharedProfile(t)
	shared.SharedProfileFile = profileFile
	for _, owners := range []uint64{0, 3} {
		if _, err := newFullEngine(context.Background(), nil, nil, nil, ServiceOptions{MaxOwners: owners, Engine: shared, ImageName: "sandbox:abi3-development"}, nil); err == nil || !strings.Contains(err.Error(), "runtime and trusted shared candidate") {
			t.Fatalf("shared engine with %d owners: %v", owners, err)
		}
	}
	// The global viper is ignored, whatever it holds.
	viper.Set("sandboxPolicyEngine", "shared")
	viper.Set("sandboxPolicySharedProfileFile", profileFile)
	// Any engine but "shared" (none, or "full") is refused, fail-closed.
	for _, engine := range []string{"", config.SandboxPolicyEngineFull} {
		if _, err := newFullEngine(context.Background(), nil, nil, nil, ServiceOptions{Engine: config.SandboxPolicyEngineConfig{Engine: engine}, ImageName: "sandbox:abi3-development"}, nil); err == nil || !strings.Contains(err.Error(), "requires sandboxPolicyEngine") {
			t.Fatalf("engine %q: %v", engine, err)
		}
	}
}
