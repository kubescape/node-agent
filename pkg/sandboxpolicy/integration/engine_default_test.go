//go:build !sandbox_shared_qualification

package integration

import (
	"context"
	"errors"
	"strings"
	"testing"

	"github.com/inspektor-gadget/inspektor-gadget/gadgets/enforce_exec/fullruntime"
	"github.com/inspektor-gadget/inspektor-gadget/pkg/runtime/local"
	"github.com/kubescape/node-agent/pkg/config"
	"github.com/kubescape/node-agent/pkg/sandboxpolicy/igbackend"
	"github.com/spf13/viper"
	"oras.land/oras-go/v2/content/memory"
)

func testProductImages() map[string]config.SandboxSharedImage {
	return map[string]config.SandboxSharedImage{strings.Repeat("a", 64): {Image: "shared:product", ProfileFile: "/etc/sandbox-shared-profiles/a.json", ManifestDigest: "sha256:" + strings.Repeat("b", 64)}}
}

// The default build selects the product shared engine; a configuration it
// cannot validate is refused before anything is built.
func TestDefaultEngineSelection(t *testing.T) {
	ctx := context.Background()
	for name, engine := range map[string]config.SandboxPolicyEngineConfig{
		"unknown engine":                            {Engine: "legacy"},
		"qualification profile":                     {Engine: "shared", SharedProfileFile: "/etc/config/sandbox-shared-profile.json"},
		"qualification profile, per-binding engine": {SharedProfileFile: "/etc/config/sandbox-shared-profile.json"},
		"images without shared":                     {SharedImages: testProductImages()},
		"images with full":                          {Engine: "full", SharedImages: testProductImages()},
		"relative image host root":                  {Engine: "shared", SharedImageHostRoot: "host"},
	} {
		if _, err := newFullEngine(ctx, nil, nil, nil, ServiceOptions{Engine: engine, MaxOwners: 1}, nil); err == nil {
			t.Fatalf("%s accepted", name)
		}
	}
	// The per-binding engine stays the default and builds the legacy budget.
	for _, engine := range []string{"", "full"} {
		if _, err := newFullEngine(ctx, nil, nil, nil, ServiceOptions{Engine: config.SandboxPolicyEngineConfig{Engine: engine}, MaxOwners: fullruntime.LegacyOwnerHardCap + 1}, nil); !errors.Is(err, fullruntime.ErrLegacyOwnerCap) {
			t.Fatalf("engine %q above the owner cap: %v", engine, err)
		}
	}
	// The shared engine builds no legacy budget: it needs its runtime and store.
	shared := config.SandboxPolicyEngineConfig{Engine: "shared", SharedImages: testProductImages()}
	if _, err := newFullEngine(ctx, nil, nil, nil, ServiceOptions{Engine: shared}, nil); err == nil || strings.Contains(err.Error(), "budget") || !strings.Contains(err.Error(), "runtime and trusted shared image store") {
		t.Fatalf("shared engine without runtime: %v", err)
	}
}

// Selection happens at agent start, from ServiceOptions.Engine only (never
// the global viper). This kernel has no entry in the table, so the engine is
// built unavailable: its health carries the typed reason (that it never
// starts is igbackend's TestSharedProductEngineSelection).
func TestDefaultSharedEngineSelectedAtStart(t *testing.T) {
	t.Cleanup(viper.Reset)
	viper.Reset()
	viper.Set("sandboxPolicyEngine", "full")
	var reported []error
	engine, err := newFullEngine(context.Background(), local.New(), nil, memory.New(), ServiceOptions{Engine: config.SandboxPolicyEngineConfig{Engine: "shared", SharedImages: testProductImages()}}, func(err error) { reported = append(reported, err) })
	if err != nil {
		t.Fatal(err)
	}
	shared, ok := engine.(*igbackend.SharedEngine)
	if !ok {
		t.Fatalf("engine %T", engine)
	}
	if h := shared.Health(); h.Started || !errors.Is(h.Unavailable, fullruntime.ErrSharedNativeUnavailable) || len(reported) != 1 {
		t.Fatalf("health %+v reported %v", h, reported)
	}
}

func TestSharedProductConfig(t *testing.T) {
	c := sharedProductConfig(config.SandboxSharedProduct{Images: testProductImages(), ImageProcRoot: "/host/proc", ImageHostRoot: "/host"}, nil, ServiceOptions{ContainerdSocket: "/run/containerd/containerd.sock"})
	e := c.Images[strings.Repeat("a", 64)]
	if len(c.Images) != 1 || e.Image != "shared:product" || e.ProfileFile != "/etc/sandbox-shared-profiles/a.json" || e.ManifestDigest != "sha256:"+strings.Repeat("b", 64) || c.ContainerdAddress != "/run/containerd/containerd.sock" || c.ImageProcRoot != "/host/proc" || c.ImageHostRoot != "/host" {
		t.Fatalf("config %+v", c)
	}
}
