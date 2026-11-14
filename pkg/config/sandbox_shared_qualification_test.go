//go:build sandbox_shared_qualification

package config

import (
	"testing"

	"github.com/spf13/viper"
)

func TestSandboxSharedQualificationFrom(t *testing.T) {
	t.Cleanup(viper.Reset)
	for _, tc := range []struct {
		name string
		in   SandboxPolicyEngineConfig
		ok   bool
	}{
		{"default engine", SandboxPolicyEngineConfig{}, true},
		{"full", SandboxPolicyEngineConfig{Engine: "full"}, true},
		{"shared", SandboxPolicyEngineConfig{Engine: "shared", SharedProfileFile: "/etc/sandbox/profile.json", SharedImageProcRoot: "/host/proc", SharedImageHostRoot: "/host"}, true},
		{"shared without profile", SandboxPolicyEngineConfig{Engine: "shared"}, false},
		{"relative profile", SandboxPolicyEngineConfig{Engine: "shared", SharedProfileFile: "profile.json"}, false},
		{"unclean root", SandboxPolicyEngineConfig{Engine: "shared", SharedProfileFile: "/p.json", SharedImageHostRoot: "/host/"}, false},
		{"unknown engine", SandboxPolicyEngineConfig{Engine: "legacy"}, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			// The global viper is never consulted (it may hold clusterData).
			viper.Reset()
			viper.Set("sandboxPolicyEngine", "legacy")
			c, err := SandboxSharedQualificationFrom(tc.in)
			if (err == nil) != tc.ok {
				t.Fatalf("%+v: %v", c, err)
			}
			if tc.ok && (c.Engine != tc.in.Engine || c.ProfileFile != tc.in.SharedProfileFile || c.ImageProcRoot != tc.in.SharedImageProcRoot || c.ImageHostRoot != tc.in.SharedImageHostRoot) {
				t.Fatalf("decoded %+v from %+v", c, tc.in)
			}
		})
	}
}
