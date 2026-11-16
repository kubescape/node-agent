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
	testBTF612 = "0d7b3abe2b50e1b252b167061fea565e78fb712b691d1c04dd5651872dafcd82"
	testBTF618 = "d0b0dffa66e521cdfafccc4c640f530fc14fbcf9d459275d04cd9d5d481b15ee"
)

var testManifest = "sha256:" + strings.Repeat("ab", 32)

// The product image map decodes from config.json with the other engine keys
// (struct decoding, not the global viper) and survives the clusterData load.
func TestSandboxSharedImagesDecode(t *testing.T) {
	viper.Reset()
	t.Cleanup(viper.Reset)
	dir := t.TempDir()
	require.NoError(t, os.WriteFile(dir+"/config.json", []byte(`{
		"sandboxPolicyEngine": "shared",
		"sandboxPolicySharedImageProcRoot": "/host/proc",
		"sandboxPolicySharedImageHostRoot": "/host",
		"sandboxPolicySharedImages": {
			"`+testBTF612+`": {"image": "ghcr.io/kubescape/shared:6.12", "profileFile": "/etc/sandbox-shared-profiles/`+testBTF612+`.json", "manifestDigest": "`+testManifest+`"},
			"`+testBTF618+`": {"image": "ghcr.io/kubescape/shared:6.18", "profileFile": "/etc/sandbox-shared-profiles/`+testBTF618+`.json", "manifestDigest": "`+testManifest+`"}
		}
	}`), 0o600))
	require.NoError(t, os.WriteFile(dir+"/clusterData.json", []byte(`{"clusterName":"c"}`), 0o600))
	cfg, err := LoadConfigOptional(dir, false)
	require.NoError(t, err)
	_, err = armometadata.LoadConfig(dir + "/clusterData.json")
	require.NoError(t, err)
	assert.Empty(t, viper.Get("sandboxPolicySharedImages"), "global viper now holds clusterData.json")
	want := map[string]SandboxSharedImage{
		testBTF612: {Image: "ghcr.io/kubescape/shared:6.12", ProfileFile: "/etc/sandbox-shared-profiles/" + testBTF612 + ".json", ManifestDigest: testManifest},
		testBTF618: {Image: "ghcr.io/kubescape/shared:6.18", ProfileFile: "/etc/sandbox-shared-profiles/" + testBTF618 + ".json", ManifestDigest: testManifest},
	}
	assert.Equal(t, want, cfg.SandboxPolicyEngine.SharedImages)
	product, err := SandboxSharedProductFrom(cfg.SandboxPolicyEngine)
	require.NoError(t, err)
	assert.Equal(t, SandboxSharedProduct{Engine: "shared", Images: want, ImageProcRoot: "/host/proc", ImageHostRoot: "/host"}, product)
}

func TestSandboxSharedProductFrom(t *testing.T) {
	ok := SandboxSharedImage{Image: "ghcr.io/kubescape/shared:6.12", ProfileFile: "/etc/p.json", ManifestDigest: testManifest}
	with := func(mutate func(*SandboxSharedImage)) map[string]SandboxSharedImage {
		i := ok
		mutate(&i)
		return map[string]SandboxSharedImage{testBTF612: i}
	}
	for _, tc := range []struct {
		name string
		in   SandboxPolicyEngineConfig
		want string
	}{
		{"default", SandboxPolicyEngineConfig{}, ""},
		{"full", SandboxPolicyEngineConfig{Engine: "full"}, ""},
		{"shared", SandboxPolicyEngineConfig{Engine: "shared", SharedImages: with(func(*SandboxSharedImage) {})}, ""},
		// No entries is not a configuration error: selection at agent start
		// reports it (fullruntime.SelectSharedProductImage).
		{"shared without images", SandboxPolicyEngineConfig{Engine: "shared"}, ""},
		{"unknown engine", SandboxPolicyEngineConfig{Engine: "legacy"}, "must be"},
		{"images without shared", SandboxPolicyEngineConfig{SharedImages: with(func(*SandboxSharedImage) {})}, "requires sandboxPolicyEngine"},
		{"qualification profile", SandboxPolicyEngineConfig{Engine: "shared", SharedProfileFile: "/p.json"}, "qualification-only"},
		{"qualification profile, default engine", SandboxPolicyEngineConfig{SharedProfileFile: "/p.json"}, "qualification-only"},
		{"qualification profile, full engine", SandboxPolicyEngineConfig{Engine: "full", SharedProfileFile: "/p.json"}, "qualification-only"},
		{"unclean root", SandboxPolicyEngineConfig{Engine: "shared", SharedImageHostRoot: "/host/"}, "absolute clean"},
		{"uppercase key", SandboxPolicyEngineConfig{Engine: "shared", SharedImages: map[string]SandboxSharedImage{strings.ToUpper(testBTF612): ok}}, "BTF sha256"},
		{"short key", SandboxPolicyEngineConfig{Engine: "shared", SharedImages: map[string]SandboxSharedImage{testBTF612[:63]: ok}}, "BTF sha256"},
		{"no image", SandboxPolicyEngineConfig{Engine: "shared", SharedImages: with(func(i *SandboxSharedImage) { i.Image = "" })}, "image is required"},
		{"padded image", SandboxPolicyEngineConfig{Engine: "shared", SharedImages: with(func(i *SandboxSharedImage) { i.Image = " x" })}, "image is required"},
		{"relative profile", SandboxPolicyEngineConfig{Engine: "shared", SharedImages: with(func(i *SandboxSharedImage) { i.ProfileFile = "p.json" })}, "profileFile"},
		{"no digest", SandboxPolicyEngineConfig{Engine: "shared", SharedImages: with(func(i *SandboxSharedImage) { i.ManifestDigest = "" })}, "manifestDigest"},
		{"bad digest", SandboxPolicyEngineConfig{Engine: "shared", SharedImages: with(func(i *SandboxSharedImage) { i.ManifestDigest = "sha256:xyz" })}, "manifestDigest"},
		{"sha512 digest", SandboxPolicyEngineConfig{Engine: "shared", SharedImages: with(func(i *SandboxSharedImage) { i.ManifestDigest = "sha512:" + strings.Repeat("ab", 64) })}, "must be sha256"},
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
