//go:build experimental_signing

package bundle

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/require"
)

func writePolicyFile(t *testing.T, dir string, b []byte) string {
	t.Helper()
	p := filepath.Join(dir, "trust-policy.json")
	require.NoError(t, os.WriteFile(p, b, 0o600))
	return p
}

func newTestReloader(t *testing.T, path, fp string, initial []byte) *PolicyReloader {
	t.Helper()
	r := NewPolicyReloader(path, initial, 0)
	r.resolveRoot = func() (string, bool, error) { return fp, true, nil }
	return r
}

// A policy that changes and verifies is applied.
func TestPolicyReloader_AppliesVerifiedChange(t *testing.T) {
	dir := t.TempDir()
	key := genKey(t)
	first, fp := signPolicyWithFingerprint(t, demoPolicy(), key)
	path := writePolicyFile(t, dir, first)

	r := newTestReloader(t, path, fp, first)
	require.True(t, r.Poll().Unchanged, "identical content must be a no-op")

	// Ship a new policy (same root key) that adds a rule class.
	p2 := demoPolicy()
	p2.RuleClasses = map[RuleClass]RuleClassPolicy{
		RuleClassBase: {Signers: []string{"key:whoever"}, AllowedRuleIDs: []string{"*"}},
	}
	second, _ := signPolicyWithFingerprint(t, p2, key)
	require.NoError(t, os.WriteFile(path, second, 0o600))

	ev := r.Poll()
	require.NoError(t, ev.Err)
	require.NotNil(t, ev.Applied, "a verified change must be applied")
	require.True(t, ev.Applied.RuleSigningEnabled(), "the new policy's ruleClasses must take effect without a restart")
}

// A changed policy signed by the WRONG key is refused; the caller keeps its own.
func TestPolicyReloader_RefusesUnverifiedChange(t *testing.T) {
	dir := t.TempDir()
	good, fp := signPolicyWithFingerprint(t, demoPolicy(), genKey(t))
	path := writePolicyFile(t, dir, good)
	r := newTestReloader(t, path, fp, good)

	rogue, _ := signPolicyWithFingerprint(t, demoPolicy(), genKey(t)) // different key
	require.NoError(t, os.WriteFile(path, rogue, 0o600))

	ev := r.Poll()
	require.Error(t, ev.Err, "a policy not signed by the trusted root must be refused")
	require.Nil(t, ev.Applied, "nothing may be applied from an unverifiable artifact")

	// Reported once per distinct content, not every tick.
	require.True(t, r.Poll().Unchanged)
}

// enforce + demo root + no mount is refused on reload too, not just at boot.
func TestPolicyReloader_RefusesDemoRootUnderEnforce(t *testing.T) {
	dir := t.TempDir()
	key := genKey(t)
	p := demoPolicy()
	p.Mode = ModeEnforce
	signed, _ := signPolicyWithFingerprint(t, p, key)
	path := writePolicyFile(t, dir, signed)

	r := NewPolicyReloader(path, nil, 0)
	r.resolveRoot = func() (string, bool, error) { return DemoRootFingerprint, false, nil }
	ev := r.Poll()
	require.Error(t, ev.Err)
	require.Nil(t, ev.Applied)
}

// A reloader constructed after a boot-load failure (no initial artifact)
// recovers as soon as a verifiable policy is mounted: scream-and-poll, never
// a restart requirement.
func TestPolicyReloader_RecoversFromInvalidBoot(t *testing.T) {
	dir := t.TempDir()
	key := genKey(t)
	_, fp := signPolicyWithFingerprint(t, demoPolicy(), key)
	path := writePolicyFile(t, dir, []byte("{not a signed policy}"))

	r := newTestReloader(t, path, fp, nil)
	ev := r.Poll()
	require.Error(t, ev.Err, "the invalid boot artifact must be refused")
	require.Nil(t, ev.Applied)
	require.True(t, r.Poll().Unchanged, "the same invalid content must not re-report every tick")

	good, _ := signPolicyWithFingerprint(t, demoPolicy(), key)
	require.NoError(t, os.WriteFile(path, good, 0o600))
	ev = r.Poll()
	require.NoError(t, ev.Err)
	require.NotNil(t, ev.Applied, "a valid policy mounted after a bad boot must enable signing without a restart")
}

// An older, still-validly-signed policy is a rollback replay and is refused;
// hash dedup alone is not a rollback defense.
func TestPolicyReloader_RefusesVersionRollback(t *testing.T) {
	dir := t.TempDir()
	key := genKey(t)

	v2 := demoPolicy()
	v2.PolicyVersion = 2
	signedV2, fp := signPolicyWithFingerprint(t, v2, key)
	path := writePolicyFile(t, dir, signedV2)
	r := newTestReloader(t, path, fp, nil)

	ev := r.Poll()
	require.NoError(t, ev.Err)
	require.NotNil(t, ev.Applied)
	require.Equal(t, int64(2), ev.Applied.PolicyVersion)

	v1 := demoPolicy()
	v1.PolicyVersion = 1
	signedV1, _ := signPolicyWithFingerprint(t, v1, key)
	require.NoError(t, os.WriteFile(path, signedV1, 0o600))
	ev = r.Poll()
	require.ErrorIs(t, ev.Err, ErrPolicyRollback)
	require.Nil(t, ev.Applied, "an older validly-signed policy must not be applied")

	v3 := demoPolicy()
	v3.PolicyVersion = 3
	signedV3, _ := signPolicyWithFingerprint(t, v3, key)
	require.NoError(t, os.WriteFile(path, signedV3, 0o600))
	ev = r.Poll()
	require.NoError(t, ev.Err)
	require.NotNil(t, ev.Applied, "a higher version must apply after a refused rollback")
}

// Unversioned policies (absent = 0) keep the pre-version behavior: any
// verified change applies, so existing artifacts are unaffected.
func TestPolicyReloader_UnversionedPoliciesStillReload(t *testing.T) {
	dir := t.TempDir()
	key := genKey(t)
	first, fp := signPolicyWithFingerprint(t, demoPolicy(), key)
	path := writePolicyFile(t, dir, first)
	r := newTestReloader(t, path, fp, first)

	p2 := demoPolicy()
	p2.Mode = ModeAlert
	second, _ := signPolicyWithFingerprint(t, p2, key)
	require.NoError(t, os.WriteFile(path, second, 0o600))
	ev := r.Poll()
	require.NoError(t, ev.Err)
	require.NotNil(t, ev.Applied)
}

// Refusal events name BOTH digests so the enforced policy can be identified
// from the log alone; apply events move the in-force digest.
func TestPolicyReloader_EventsCarryDigests(t *testing.T) {
	dir := t.TempDir()
	key := genKey(t)
	first, fp := signPolicyWithFingerprint(t, demoPolicy(), key)
	path := writePolicyFile(t, dir, first)
	r := newTestReloader(t, path, fp, first)
	bootDigest := HashArtifact(first)

	rogue, _ := signPolicyWithFingerprint(t, demoPolicy(), genKey(t))
	require.NoError(t, os.WriteFile(path, rogue, 0o600))
	ev := r.Poll()
	require.Error(t, ev.Err)
	require.Equal(t, HashArtifact(rogue), ev.ArtifactDigest, "refusal must name the refused artifact")
	require.Equal(t, bootDigest, ev.InForceDigest, "refusal must keep naming the boot policy as in force")

	p2 := demoPolicy()
	p2.Mode = ModeAlert
	second, _ := signPolicyWithFingerprint(t, p2, key)
	require.NoError(t, os.WriteFile(path, second, 0o600))
	ev = r.Poll()
	require.NoError(t, ev.Err)
	require.NotNil(t, ev.Applied)
	require.Equal(t, HashArtifact(second), ev.ArtifactDigest)
	require.Equal(t, HashArtifact(second), ev.InForceDigest, "apply must move the in-force digest")
}
