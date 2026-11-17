//go:build sandbox_shared_qualification

package config

import (
	"fmt"
	"path/filepath"
)

// SandboxSharedQualification is the G020 shared-engine configuration. Only
// binaries built with the sandbox_shared_qualification tag read these keys;
// the default build refuses sandboxPolicySharedProfileFile. The qualification
// shared engine never reports Ready.
type SandboxSharedQualification struct {
	// Engine is "" or "full" (per-binding engine) or "shared" (node engine).
	Engine string
	// ProfileFile is a JSON fullruntime.SharedProfile matching the geometry
	// the shared candidate image was built with (required for "shared").
	ProfileFile string
	// ImageProcRoot and ImageHostRoot locate the host procfs and root as
	// mounted into the agent (empty: /host/proc and /host).
	ImageProcRoot, ImageHostRoot string
}

// SandboxSharedQualificationFrom validates the qualification keys LoadConfig
// decoded into Config.SandboxPolicyEngine. It never re-reads the global
// viper: main loads clusterData.json through the same global instance after
// LoadConfig, which replaces config.json (EKS run 14 then silently selected
// the per-binding engine for the shared candidate image).
func SandboxSharedQualificationFrom(e SandboxPolicyEngineConfig) (SandboxSharedQualification, error) {
	c := SandboxSharedQualification{
		Engine:        e.Engine,
		ProfileFile:   e.SharedProfileFile,
		ImageProcRoot: e.SharedImageProcRoot,
		ImageHostRoot: e.SharedImageHostRoot,
	}
	if len(e.SharedImages) != 0 {
		// The product image map never selects the qualification engine.
		return c, fmt.Errorf("sandboxPolicySharedImages is the product shared engine's; a sandbox_shared_qualification build takes sandboxPolicySharedProfileFile")
	}
	return c, c.Validate()
}

func (c SandboxSharedQualification) Validate() error {
	switch c.Engine {
	case "", SandboxPolicyEngineFull:
		return nil
	case SandboxPolicyEngineShared:
	default:
		return fmt.Errorf("sandboxPolicyEngine %q must be %q or %q", c.Engine, SandboxPolicyEngineFull, SandboxPolicyEngineShared)
	}
	if c.ProfileFile == "" {
		return fmt.Errorf("sandboxPolicyEngine %q requires sandboxPolicySharedProfileFile", c.Engine)
	}
	for name, path := range map[string]string{"sandboxPolicySharedProfileFile": c.ProfileFile, "sandboxPolicySharedImageProcRoot": c.ImageProcRoot, "sandboxPolicySharedImageHostRoot": c.ImageHostRoot} {
		if path != "" && (!filepath.IsAbs(path) || filepath.Clean(path) != path) {
			return fmt.Errorf("%s %q is not an absolute clean path", name, path)
		}
	}
	return nil
}
