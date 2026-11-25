package config

import (
	"os"
	"testing"
	"time"

	"github.com/spf13/viper"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func loadGatewayConfig(t *testing.T, json string) (Config, error) {
	t.Helper()
	viper.Reset()
	dir := t.TempDir()
	require.NoError(t, os.WriteFile(dir+"/config.json", []byte(json), 0644))
	return LoadConfigOptional(dir, false)
}

func TestSandboxGatewayDefaults(t *testing.T) {
	cfg, err := loadGatewayConfig(t, `{}`)
	require.NoError(t, err)
	assert.Equal(t, SandboxPolicyGatewayConfig{
		ListenPort: 18443, HealthPort: 18444, LookupSocket: "/run/kubescape-sandbox/lookup.sock",
		StaticAIAddresses: []string{}, ExemptCIDRs: []string{},
		ProbeInterval: 500 * time.Millisecond, ProbeTimeout: 400 * time.Millisecond, HealthyFor: 10 * time.Second, CertificateMargin: 5 * time.Minute,
	}, cfg.SandboxPolicyGateway)
}

// The two list keys are read from the environment when the file omits them.
func TestSandboxGatewayListsFromEnvironment(t *testing.T) {
	t.Setenv("SANDBOXPOLICYGATEWAYSTATICAIADDRESSES", "203.0.113.9,2001:db8::1")
	t.Setenv("SANDBOXPOLICYGATEWAYEXEMPTCIDRS", "100.64.0.0/10")
	cfg, err := loadGatewayConfig(t, `{}`)
	require.NoError(t, err)
	assert.Equal(t, []string{"203.0.113.9", "2001:db8::1"}, cfg.SandboxPolicyGateway.StaticAIAddresses)
	assert.Equal(t, []string{"100.64.0.0/10"}, cfg.SandboxPolicyGateway.ExemptCIDRs)
}

func TestSandboxGatewayKeys(t *testing.T) {
	cfg, err := loadGatewayConfig(t, `{"kubernetesMode": true, "sandboxPolicyEnabled": true, "sandboxPolicyContainerdSocket": "/run/containerd/containerd.sock",
		"sandboxPolicyGatewayEnabled": true, "sandboxPolicyGatewayListenPort": 28443, "sandboxPolicyGatewayHealthPort": 28444,
		"sandboxPolicyGatewayLookupSocket": "/run/other/lookup.sock", "sandboxPolicyGatewayTrustNamespace": "kubescape",
		"sandboxPolicyGatewayStaticAIAddresses": ["203.0.113.9", "2001:db8::1"], "sandboxPolicyGatewayExemptCIDRs": ["169.254.169.254", "100.64.0.0/10"],
		"sandboxPolicyGatewayProbeInterval": "1s", "sandboxPolicyGatewayProbeTimeout": "800ms", "sandboxPolicyGatewayHealthyFor": "30s", "sandboxPolicyGatewayCertificateMargin": "10m"}`)
	require.NoError(t, err)
	assert.Equal(t, SandboxPolicyGatewayConfig{
		Enabled: true, ListenPort: 28443, HealthPort: 28444, LookupSocket: "/run/other/lookup.sock", TrustNamespace: "kubescape",
		StaticAIAddresses: []string{"203.0.113.9", "2001:db8::1"}, ExemptCIDRs: []string{"169.254.169.254", "100.64.0.0/10"},
		ProbeInterval: time.Second, ProbeTimeout: 800 * time.Millisecond, HealthyFor: 30 * time.Second, CertificateMargin: 10 * time.Minute,
	}, cfg.SandboxPolicyGateway)
}

func TestSandboxGatewayRefusals(t *testing.T) {
	base := `"kubernetesMode": true, "sandboxPolicyEnabled": true, "sandboxPolicyContainerdSocket": "/run/containerd/containerd.sock", "sandboxPolicyGatewayEnabled": true`
	for name, tc := range map[string]struct{ json, want string }{
		"needs the sandbox policy feature": {`{"sandboxPolicyGatewayEnabled": true}`, "requires sandboxPolicyEnabled"},
		"port":                             {`{` + base + `, "sandboxPolicyGatewayListenPort": 0}`, "sandboxPolicyGatewayListenPort"},
		"socket path":                      {`{` + base + `, "sandboxPolicyGatewayLookupSocket": "run/lookup.sock"}`, "sandboxPolicyGatewayLookupSocket"},
		"timer":                            {`{` + base + `, "sandboxPolicyGatewayHealthyFor": "0s"}`, "sandboxPolicyGatewayHealthyFor"},
		"AI address":                       {`{` + base + `, "sandboxPolicyGatewayStaticAIAddresses": ["api.example.com"]}`, "is not an IP address"},
		"exempt range":                     {`{` + base + `, "sandboxPolicyGatewayExemptCIDRs": ["10.0.0.0/33"]}`, "is not a CIDR"},
	} {
		_, err := loadGatewayConfig(t, tc.json)
		if assert.Error(t, err, name) {
			assert.Contains(t, err.Error(), tc.want, name)
		}
	}
	// A disabled gateway is not validated: its keys are not in use.
	_, err := loadGatewayConfig(t, `{"sandboxPolicyGatewayListenPort": 0}`)
	assert.NoError(t, err)
}
