package config

import (
	"fmt"
	"path/filepath"
	"strings"

	"github.com/opencontainers/go-digest"
)

// Sandbox policy engines.
const (
	SandboxPolicyEngineFull   = "full"
	SandboxPolicyEngineShared = "shared"
)

// SandboxSharedImage is one kernel build's product shared-engine image: the
// image reference in the agent's read-only tracers archive, the
// fullruntime.SharedProfile JSON it was built with and the digest of its
// image manifest for the agent's architecture (the manifest the image
// reference's index selects). The agent refuses the image when the archive
// resolves it to another manifest.
type SandboxSharedImage struct {
	Image          string `mapstructure:"image"`
	ProfileFile    string `mapstructure:"profileFile"`
	ManifestDigest string `mapstructure:"manifestDigest"`
}

// SandboxSharedProduct is the default build's shared-engine configuration.
type SandboxSharedProduct struct {
	// Engine is "" or "full" (per-binding engine) or "shared" (node engine).
	Engine string
	// Images is keyed by kernel BTF sha256; the agent selects the running
	// kernel's entry at start (fullruntime.SelectSharedProductImage).
	Images map[string]SandboxSharedImage
	// ImageProcRoot and ImageHostRoot locate the host procfs and root as
	// mounted into the agent (empty: /host/proc and /host).
	ImageProcRoot, ImageHostRoot string
}

// SandboxSharedProductFrom validates the product keys LoadConfig decoded into
// Config.SandboxPolicyEngine. Like SandboxSharedQualificationFrom it never
// re-reads the global viper (main loads clusterData.json through it after
// LoadConfig). Selecting the running kernel's entry is not configuration: it
// happens at agent start, and a kernel without an entry is reported, not
// refused here.
func SandboxSharedProductFrom(e SandboxPolicyEngineConfig) (SandboxSharedProduct, error) {
	c := SandboxSharedProduct{Engine: e.Engine, Images: e.SharedImages, ImageProcRoot: e.SharedImageProcRoot, ImageHostRoot: e.SharedImageHostRoot}
	if e.SharedProfileFile != "" {
		// Whatever the engine: a qualification configuration never runs
		// silently as another engine in a default build.
		return c, fmt.Errorf("sandboxPolicySharedProfileFile is qualification-only; the product shared engine takes a profileFile per sandboxPolicySharedImages entry")
	}
	switch c.Engine {
	case "", SandboxPolicyEngineFull:
		if len(c.Images) != 0 {
			return c, fmt.Errorf("sandboxPolicySharedImages requires sandboxPolicyEngine %q", SandboxPolicyEngineShared)
		}
		return c, nil
	case SandboxPolicyEngineShared:
	default:
		return c, fmt.Errorf("sandboxPolicyEngine %q must be %q or %q", c.Engine, SandboxPolicyEngineFull, SandboxPolicyEngineShared)
	}
	for name, path := range map[string]string{"sandboxPolicySharedImageProcRoot": c.ImageProcRoot, "sandboxPolicySharedImageHostRoot": c.ImageHostRoot} {
		if path != "" && !canonicalAbsolute(path) {
			return c, fmt.Errorf("%s %q is not an absolute clean path", name, path)
		}
	}
	for btf, image := range c.Images {
		if err := image.validate(btf); err != nil {
			return c, fmt.Errorf("sandboxPolicySharedImages[%q]: %w", btf, err)
		}
	}
	return c, nil
}

func (i SandboxSharedImage) validate(btf string) error {
	if len(btf) != 64 || strings.Trim(btf, "0123456789abcdef") != "" {
		return fmt.Errorf("key must be a kernel BTF sha256 (64 lowercase hex characters)")
	}
	if i.Image == "" || strings.TrimSpace(i.Image) != i.Image {
		return fmt.Errorf("image is required")
	}
	if !canonicalAbsolute(i.ProfileFile) {
		return fmt.Errorf("profileFile %q is not an absolute clean path", i.ProfileFile)
	}
	d, err := digest.Parse(i.ManifestDigest)
	if err != nil {
		return fmt.Errorf("manifestDigest %q: %w", i.ManifestDigest, err)
	}
	if d.Algorithm() != digest.SHA256 {
		return fmt.Errorf("manifestDigest %q must be sha256", i.ManifestDigest)
	}
	return nil
}

func canonicalAbsolute(path string) bool {
	return filepath.IsAbs(path) && filepath.Clean(path) == path
}
