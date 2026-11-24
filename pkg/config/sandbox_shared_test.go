package config

import (
	"os"
	"strings"
	"testing"

	"github.com/armosec/utils-k8s-go/armometadata"
	"github.com/spf13/viper"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

const (
	testBTFA = "a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1"
	testBTFB = "b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2"
)

var testManifest = "sha256:" + strings.Repeat("ab", 32)

// The deprecated product image map still decodes from config.json with the
// other engine keys (struct decoding, not the global viper) and survives the
// clusterData load, so an older configuration loads; the agent ignores it.
func TestSandboxSharedImagesDecode(t *testing.T) {
	viper.Reset()
	t.Cleanup(viper.Reset)
	dir := t.TempDir()
	require.NoError(t, os.WriteFile(dir+"/config.json", []byte(`{
		"sandboxPolicyEngine": "shared",
		"sandboxPolicySharedImageProcRoot": "/host/proc",
		"sandboxPolicySharedImageHostRoot": "/host",
		"sandboxPolicySharedImages": {
			"`+testBTFA+`": {"image": "ghcr.io/kubescape/shared:kernel-a", "profileFile": "/etc/sandbox-shared-profiles/`+testBTFA+`.json", "manifestDigest": "`+testManifest+`"},
			"`+testBTFB+`": {"image": "ghcr.io/kubescape/shared:kernel-b", "profileFile": "/etc/sandbox-shared-profiles/`+testBTFB+`.json", "manifestDigest": "`+testManifest+`"}
		}
	}`), 0o600))
	require.NoError(t, os.WriteFile(dir+"/clusterData.json", []byte(`{"clusterName":"c"}`), 0o600))
	cfg, err := LoadConfigOptional(dir, false)
	require.NoError(t, err)
	_, err = armometadata.LoadConfig(dir + "/clusterData.json")
	require.NoError(t, err)
	assert.Empty(t, viper.Get("sandboxPolicySharedImages"), "global viper now holds clusterData.json")
	want := map[string]SandboxSharedImage{
		testBTFA: {Image: "ghcr.io/kubescape/shared:kernel-a", ProfileFile: "/etc/sandbox-shared-profiles/" + testBTFA + ".json", ManifestDigest: testManifest},
		testBTFB: {Image: "ghcr.io/kubescape/shared:kernel-b", ProfileFile: "/etc/sandbox-shared-profiles/" + testBTFB + ".json", ManifestDigest: testManifest},
	}
	assert.Equal(t, want, cfg.SandboxPolicyEngine.SharedImages)
	product, err := SandboxSharedProductFrom(cfg.SandboxPolicyEngine)
	require.NoError(t, err)
	assert.Equal(t, SandboxSharedProduct{Engine: "shared", Images: want, ImageProcRoot: "/host/proc", ImageHostRoot: "/host"}, product)
}

func TestSandboxSharedProductFrom(t *testing.T) {
	ok := SandboxSharedImage{Image: "ghcr.io/kubescape/shared:kernel-a", ProfileFile: "/etc/p.json", ManifestDigest: testManifest}
	with := func(mutate func(*SandboxSharedImage)) map[string]SandboxSharedImage {
		i := ok
		mutate(&i)
		return map[string]SandboxSharedImage{testBTFA: i}
	}
	for _, tc := range []struct {
		name string
		in   SandboxPolicyEngineConfig
		want string
	}{
		{"default", SandboxPolicyEngineConfig{}, ""},
		{"full", SandboxPolicyEngineConfig{Engine: "full"}, ""},
		{"shared", SandboxPolicyEngineConfig{Engine: "shared", SharedImages: with(func(*SandboxSharedImage) {})}, ""},
		{"shared without images", SandboxPolicyEngineConfig{Engine: "shared"}, ""},
		{"unknown engine", SandboxPolicyEngineConfig{Engine: "legacy"}, "must be"},
		// The engine key is deprecated (selection is by the running kernel):
		// images load without it, and with any of its old values.
		{"images without engine", SandboxPolicyEngineConfig{SharedImages: with(func(*SandboxSharedImage) {})}, ""},
		{"images with full", SandboxPolicyEngineConfig{Engine: "full", SharedImages: with(func(*SandboxSharedImage) {})}, ""},
		// sandboxPolicySharedImages is ignored (the image is compiled in), so
		// an entry that was once invalid no longer refuses the configuration.
		{"undigested image entry", SandboxPolicyEngineConfig{SharedImages: with(func(i *SandboxSharedImage) { i.ManifestDigest = "" })}, ""},
		{"malformed image entry", SandboxPolicyEngineConfig{Engine: "shared", SharedImages: map[string]SandboxSharedImage{"not-a-btf": {Image: " x", ProfileFile: "p.json", ManifestDigest: "sha512:" + strings.Repeat("ab", 64)}}}, ""},
		{"unclean root without engine", SandboxPolicyEngineConfig{SharedImageProcRoot: "proc"}, "absolute clean"},
		{"qualification profile", SandboxPolicyEngineConfig{Engine: "shared", SharedProfileFile: "/p.json"}, "qualification-only"},
		{"qualification profile, default engine", SandboxPolicyEngineConfig{SharedProfileFile: "/p.json"}, "qualification-only"},
		{"qualification profile, full engine", SandboxPolicyEngineConfig{Engine: "full", SharedProfileFile: "/p.json"}, "qualification-only"},
		{"unclean root", SandboxPolicyEngineConfig{Engine: "shared", SharedImageHostRoot: "/host/"}, "absolute clean"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			// The global viper is never consulted.
			viper.Reset()
			t.Cleanup(viper.Reset)
			viper.Set("sandboxPolicyEngine", "legacy")
			c, err := SandboxSharedProductFrom(tc.in)
			if tc.want == "" {
				require.NoError(t, err)
				assert.Equal(t, tc.in.Engine, c.Engine)
				assert.Equal(t, tc.in.SharedImages, c.Images)
				return
			}
			require.ErrorContains(t, err, tc.want)
		})
	}
}
