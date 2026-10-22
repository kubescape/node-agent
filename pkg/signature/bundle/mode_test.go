//go:build experimental_signing

package bundle

import (
	"encoding/json"
	"testing"

	"github.com/stretchr/testify/require"
)

// The demo root fingerprint constant must equal the fingerprint of the key
// DefaultRootPublicKeyPEM actually embeds, or enforce-mode's demo-key refusal
// silently protects the wrong key.
func TestDemoRootFingerprintMatchesDefault(t *testing.T) {
	fp, err := rootFingerprint()
	require.NoError(t, err)
	require.Equal(t, DemoRootFingerprint, fp,
		"DemoRootFingerprint is out of sync with DefaultRootPublicKeyPEM")
	require.True(t, IsDemoRoot(fp))
	require.False(t, IsDemoRoot("key:0000000000000000000000000000000000000000000000000000000000000000"))
}

func TestEffectiveMode(t *testing.T) {
	require.Equal(t, ModeEnforce, TrustPolicy{Mode: ModeEnforce}.EffectiveMode())
	require.True(t, TrustPolicy{Mode: ModeEnforce}.Enforcing())
	// A mounted policy is never silent: absent or unknown mode -> alert, not off.
	require.Equal(t, ModeAlert, TrustPolicy{}.EffectiveMode())
	require.Equal(t, ModeAlert, TrustPolicy{Mode: "wat"}.EffectiveMode())
	require.False(t, TrustPolicy{}.Enforcing())
}

func TestGuardRootAnchor(t *testing.T) {
	demo := DemoRootFingerprint
	real := "key:1111111111111111111111111111111111111111111111111111111111111111"

	// enforce + demo root + not mounted => refused.
	require.Error(t, GuardRootAnchor(&TrustPolicy{Mode: ModeEnforce}, demo, false))
	// enforce + demo root + mounted override => allowed (operator vouched for it).
	require.NoError(t, GuardRootAnchor(&TrustPolicy{Mode: ModeEnforce}, demo, true))
	// enforce + real root => allowed.
	require.NoError(t, GuardRootAnchor(&TrustPolicy{Mode: ModeEnforce}, real, false))
	// alert mode never refuses on the anchor (it only warns at the call site).
	require.NoError(t, GuardRootAnchor(&TrustPolicy{Mode: ModeAlert}, demo, false))
	require.NoError(t, GuardRootAnchor(&TrustPolicy{}, demo, false))
}

func TestResolveTrustedRootIgnoresConfigPath(t *testing.T) {
	// With no fixed mount present, the anchor is the compiled demo root — and it
	// takes no argument, so a config value can never influence it.
	fp, mounted, err := ResolveTrustedRootFingerprint()
	require.NoError(t, err)
	require.False(t, mounted)
	require.Equal(t, DemoRootFingerprint, fp)
}

func TestModeRoundTripsJSON(t *testing.T) {
	in := TrustPolicy{Mode: ModeEnforce, Classes: map[FragmentClass]ClassPolicy{}}
	b, err := json.Marshal(in)
	require.NoError(t, err)
	require.Contains(t, string(b), `"mode":"enforce"`)
	var out TrustPolicy
	require.NoError(t, json.Unmarshal(b, &out))
	require.Equal(t, ModeEnforce, out.Mode)

	// A policy without a mode omits the field and reads back as alert.
	b2, _ := json.Marshal(TrustPolicy{Classes: map[FragmentClass]ClassPolicy{}})
	require.NotContains(t, string(b2), `"mode"`)
}

func TestRuleAdmissionUnauthenticated(t *testing.T) {
	demo := DemoRootFingerprint
	real := "key:1111111111111111111111111111111111111111111111111111111111111111"
	withRules := &TrustPolicy{RuleClasses: map[RuleClass]RuleClassPolicy{
		RuleClassBase: {Signers: []string{real}, AllowedRuleIDs: []string{"*"}},
	}}
	withoutRules := &TrustPolicy{}

	require.True(t, RuleAdmissionUnauthenticated(withRules, demo))
	require.False(t, RuleAdmissionUnauthenticated(withRules, real))
	require.False(t, RuleAdmissionUnauthenticated(withoutRules, demo))
	require.False(t, RuleAdmissionUnauthenticated(nil, demo))
}
