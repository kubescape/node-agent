//go:build experimental_signing

package bundle

import (
	"os"
	"testing"

	"github.com/stretchr/testify/require"
)

func enforcePolicyV(t *testing.T, version int64, signers ...string) *TrustPolicy {
	t.Helper()
	p := demoPolicy()
	p.Mode = ModeEnforce
	p.PolicyVersion = version
	for class, cp := range p.Classes {
		cp.Signers = append([]string{}, signers...)
		p.Classes[class] = cp
	}
	return p
}

func TestPolicyReloader_RefusesModeDowngradeWhileRunning(t *testing.T) {
	dir := t.TempDir()
	key := genKey(t)
	enforce := enforcePolicyV(t, 2, "key:aaa")
	signed, fp := signPolicyWithFingerprint(t, enforce, key)
	path := writePolicyFile(t, dir, signed)
	r := newTestReloader(t, path, fp, nil)
	ev := r.Poll()
	require.NoError(t, ev.Err)
	require.NotNil(t, ev.Applied)
	require.True(t, ev.Applied.Enforcing())

	alert := enforcePolicyV(t, 3, "key:aaa")
	alert.Mode = ModeAlert
	signedAlert, _ := signPolicyWithFingerprint(t, alert, key)
	require.NoError(t, os.WriteFile(path, signedAlert, 0o600))
	ev = r.Poll()
	require.ErrorIs(t, ev.Err, ErrEnforceDowngrade)
	require.Nil(t, ev.Applied)

	unversioned := enforcePolicyV(t, 0, "key:aaa")
	unversioned.Mode = ""
	signedUnversioned, _ := signPolicyWithFingerprint(t, unversioned, key)
	require.NoError(t, os.WriteFile(path, signedUnversioned, 0o600))
	ev = r.Poll()
	require.ErrorIs(t, ev.Err, ErrEnforceDowngrade, "the one-way door is named before the version check")
	require.Nil(t, ev.Applied)

	still := enforcePolicyV(t, 3, "key:aaa", "key:bbb")
	signedStill, _ := signPolicyWithFingerprint(t, still, key)
	require.NoError(t, os.WriteFile(path, signedStill, 0o600))
	ev = r.Poll()
	require.NoError(t, ev.Err)
	require.NotNil(t, ev.Applied, "an enforce policy that only adds signers applies after the refusals")
}

func TestPolicyReloader_SignersAreAppendOnly(t *testing.T) {
	dir := t.TempDir()
	key := genKey(t)
	two := enforcePolicyV(t, 2, "key:aaa", "key:bbb")
	signed, fp := signPolicyWithFingerprint(t, two, key)
	path := writePolicyFile(t, dir, signed)
	r := newTestReloader(t, path, fp, nil)
	require.NotNil(t, r.Poll().Applied)

	one := enforcePolicyV(t, 3, "key:aaa")
	signedOne, _ := signPolicyWithFingerprint(t, one, key)
	require.NoError(t, os.WriteFile(path, signedOne, 0o600))
	ev := r.Poll()
	require.ErrorIs(t, ev.Err, ErrSignerRemoved)
	require.Contains(t, ev.Err.Error(), "key:bbb")
	require.Nil(t, ev.Applied)

	three := enforcePolicyV(t, 3, "key:aaa", "key:bbb", "key:ccc")
	signedThree, _ := signPolicyWithFingerprint(t, three, key)
	require.NoError(t, os.WriteFile(path, signedThree, 0o600))
	ev = r.Poll()
	require.NoError(t, ev.Err)
	require.NotNil(t, ev.Applied)

	two4 := enforcePolicyV(t, 4, "key:aaa", "key:bbb")
	signedTwo4, _ := signPolicyWithFingerprint(t, two4, key)
	require.NoError(t, os.WriteFile(path, signedTwo4, 0o600))
	ev = r.Poll()
	require.ErrorIs(t, ev.Err, ErrSignerRemoved, "the added signer is in force and cannot be taken back")
	require.Contains(t, ev.Err.Error(), "key:ccc")
}

func TestPolicyReloader_BootPolicyIsTheFirstInForce(t *testing.T) {
	dir := t.TempDir()
	key := genKey(t)
	boot := enforcePolicyV(t, 2, "key:aaa", "key:bbb")
	signed, fp := signPolicyWithFingerprint(t, boot, key)
	path := writePolicyFile(t, dir, signed)
	r := newTestReloader(t, path, fp, signed)
	r.NoteInForce(boot)

	one := enforcePolicyV(t, 3, "key:aaa")
	signedOne, _ := signPolicyWithFingerprint(t, one, key)
	require.NoError(t, os.WriteFile(path, signedOne, 0o600))
	require.ErrorIs(t, r.Poll().Err, ErrSignerRemoved)
}

func TestPolicyReloader_BindingSignersAreAppendOnly(t *testing.T) {
	for _, tc := range []struct {
		name    string
		classes map[FragmentClass]BindingClassPolicy
		refused bool
	}{
		{"remove signer", map[FragmentClass]BindingClassPolicy{"base": {Signers: []string{"key:aaa"}}}, true},
		{"remove class", nil, true},
		{"add signer", map[FragmentClass]BindingClassPolicy{"base": {Signers: []string{"key:aaa", "key:bbb", "key:ccc"}}}, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			key := genKey(t)
			boot := enforcePolicyV(t, 2, "key:profile")
			boot.BindingClasses = map[FragmentClass]BindingClassPolicy{"base": {Signers: []string{"key:aaa", "key:bbb"}}}
			signed, fp := signPolicyWithFingerprint(t, boot, key)
			path := writePolicyFile(t, t.TempDir(), signed)
			r := newTestReloader(t, path, fp, nil)
			require.NotNil(t, r.Poll().Applied)

			candidate := enforcePolicyV(t, 3, "key:profile")
			candidate.BindingClasses = tc.classes
			updated, _ := signPolicyWithFingerprint(t, candidate, key)
			require.NoError(t, os.WriteFile(path, updated, 0o600))
			ev := r.Poll()
			if tc.refused {
				require.ErrorIs(t, ev.Err, ErrSignerRemoved)
				require.Contains(t, ev.Err.Error(), "binding/base:key:bbb")
				require.Nil(t, ev.Applied)
				require.True(t, r.inForce.BindingSigningEnabled())
				require.Equal(t, int64(2), r.inForceVersion)
			} else {
				require.NoError(t, ev.Err)
				require.NotNil(t, ev.Applied)
				require.True(t, ev.Applied.BindingClasses["base"].allowsSigner("key:ccc"))
			}
		})
	}
}
