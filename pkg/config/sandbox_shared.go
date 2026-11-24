package config

import (
	"fmt"
	"path/filepath"
)

// Sandbox policy engines.
const (
	SandboxPolicyEngineFull   = "full"
	SandboxPolicyEngineShared = "shared"
)

// SandboxPolicyMaxOwnersDefault is the default of the ignored
// sandboxPolicyMaxOwners key (a legacy key nothing reads).
const SandboxPolicyMaxOwnersDefault = 2

// SandboxSharedImage is one entry of the deprecated
// sandboxPolicySharedImages key: an image reference, a profile file and a
// manifest digest. The default build ignores it (the product image is
// compiled in); it is still decoded so that older configurations load.
type SandboxSharedImage struct {
	Image          string `mapstructure:"image"`
	ProfileFile    string `mapstructure:"profileFile"`
	ManifestDigest string `mapstructure:"manifestDigest"`
}

// SandboxSharedProduct is the default build's shared-engine configuration.
type SandboxSharedProduct struct {
	// Engine is the deprecated sandboxPolicyEngine key: "", "full" or
	// "shared". The default build no longer selects the engine from it: the
	// agent selects it from the running kernel (IG's kernel gate). A
	// non-empty value is accepted for older charts and reported as ignored.
	Engine string
	// Images is the deprecated sandboxPolicySharedImages key. It can no
	// longer supply an image (the product image is compiled in): it is
	// neither validated nor used, and a non-empty value is reported as
	// ignored at agent start.
	Images map[string]SandboxSharedImage
	// ImageProcRoot and ImageHostRoot locate the host procfs and root as
	// mounted into the agent (empty: /host/proc and /host).
	ImageProcRoot, ImageHostRoot string
}

// SandboxSharedProductFrom validates the product keys LoadConfig decoded into
// Config.SandboxPolicyEngine. Like SandboxSharedQualificationFrom it never
// re-reads the global viper (main loads clusterData.json through it after
// LoadConfig). Selecting the engine and its image is not configuration: it
// happens at agent start from the running kernel, on the compiled-in image.
// Older configurations keep loading: sandboxPolicyEngine "", "full" or
// "shared", with or without sandboxPolicySharedImages, is accepted (both
// keys are ignored, so an entry is not validated); any other engine value is
// still refused.
func SandboxSharedProductFrom(e SandboxPolicyEngineConfig) (SandboxSharedProduct, error) {
	c := SandboxSharedProduct{Engine: e.Engine, Images: e.SharedImages, ImageProcRoot: e.SharedImageProcRoot, ImageHostRoot: e.SharedImageHostRoot}
	if e.SharedProfileFile != "" {
		// Whatever the engine: a qualification configuration never runs
		// silently as another engine in a default build.
		return c, fmt.Errorf("sandboxPolicySharedProfileFile is qualification-only; the product shared engine runs its compiled-in image and profile")
	}
	switch c.Engine {
	case "", SandboxPolicyEngineFull, SandboxPolicyEngineShared:
	default:
		return c, fmt.Errorf("sandboxPolicyEngine %q must be %q or %q (deprecated: the engine is selected from the running kernel)", c.Engine, SandboxPolicyEngineFull, SandboxPolicyEngineShared)
	}
	for name, path := range map[string]string{"sandboxPolicySharedImageProcRoot": c.ImageProcRoot, "sandboxPolicySharedImageHostRoot": c.ImageHostRoot} {
		if path != "" && !canonicalAbsolute(path) {
			return c, fmt.Errorf("%s %q is not an absolute clean path", name, path)
		}
	}
	return c, nil
}

func canonicalAbsolute(path string) bool {
	return filepath.IsAbs(path) && filepath.Clean(path) == path
}
