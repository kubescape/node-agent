//go:build experimental_signing

package containerprofilecache

import (
	"testing"

	"github.com/kubescape/node-agent/pkg/signature/bundle"
	"github.com/stretchr/testify/require"
)

func leaf(class, name string, version int64) bundle.LeafRef {
	return bundle.LeafRef{Class: bundle.FragmentClass(class), Name: name, Version: version}
}

func TestRollbackGuard_MonotonicPerSlot(t *testing.T) {
	c := &ContainerProfileCacheImpl{}
	ns, b := "redis", "redis"

	// v1 accepted.
	require.NoError(t, c.checkAndAdvanceVersions(ns, b, []bundle.LeafRef{leaf("overlay", "ops", 1)}))
	// v2 accepted (advance).
	require.NoError(t, c.checkAndAdvanceVersions(ns, b, []bundle.LeafRef{leaf("overlay", "ops", 2)}))
	// replay of v1 refused.
	err := c.checkAndAdvanceVersions(ns, b, []bundle.LeafRef{leaf("overlay", "ops", 1)})
	require.ErrorIs(t, err, bundle.ErrFragmentRollback)
	// same version (v2) is allowed — reassembly of the current fragment is not a rollback.
	require.NoError(t, c.checkAndAdvanceVersions(ns, b, []bundle.LeafRef{leaf("overlay", "ops", 2)}))
}

func TestRollbackGuard_RejectsWholeSet(t *testing.T) {
	c := &ContainerProfileCacheImpl{}
	ns, b := "redis", "redis"

	// Establish base v5, overlay v3.
	require.NoError(t, c.checkAndAdvanceVersions(ns, b, []bundle.LeafRef{
		leaf("base", "redis-base", 5), leaf("overlay", "ops", 3),
	}))
	// A set with a current base but a rolled-back overlay must reject ENTIRELY,
	// and must NOT advance the base high-water-mark.
	err := c.checkAndAdvanceVersions(ns, b, []bundle.LeafRef{
		leaf("base", "redis-base", 6), leaf("overlay", "ops", 2),
	})
	require.ErrorIs(t, err, bundle.ErrFragmentRollback)
	// base hwm must still be 5 (not advanced to 6), so a later legit base v5 is fine.
	require.NoError(t, c.checkAndAdvanceVersions(ns, b, []bundle.LeafRef{leaf("base", "redis-base", 5)}))
	// and base v4 (a rollback of base) is refused.
	require.ErrorIs(t, c.checkAndAdvanceVersions(ns, b, []bundle.LeafRef{leaf("base", "redis-base", 4)}), bundle.ErrFragmentRollback)
}

func TestRollbackGuard_SlotsAreIndependent(t *testing.T) {
	c := &ContainerProfileCacheImpl{}
	// Same name, different class/namespace/bundle are distinct slots.
	require.NoError(t, c.checkAndAdvanceVersions("ns1", "b", []bundle.LeafRef{leaf("overlay", "x", 9)}))
	require.NoError(t, c.checkAndAdvanceVersions("ns2", "b", []bundle.LeafRef{leaf("overlay", "x", 1)}))
	require.NoError(t, c.checkAndAdvanceVersions("ns1", "other", []bundle.LeafRef{leaf("overlay", "x", 1)}))
	require.NoError(t, c.checkAndAdvanceVersions("ns1", "b", []bundle.LeafRef{leaf("base", "x", 1)}))
	// but rolling back the original ns1/b/overlay/x slot is refused.
	require.ErrorIs(t, c.checkAndAdvanceVersions("ns1", "b", []bundle.LeafRef{leaf("overlay", "x", 8)}), bundle.ErrFragmentRollback)
}

// Unversioned fragments are version 0 and coexist until a versioned one appears.
func TestRollbackGuard_UnversionedIsZero(t *testing.T) {
	c := &ContainerProfileCacheImpl{}
	ns, b := "redis", "redis"
	require.NoError(t, c.checkAndAdvanceVersions(ns, b, []bundle.LeafRef{leaf("base", "redis-base", 0)}))
	require.NoError(t, c.checkAndAdvanceVersions(ns, b, []bundle.LeafRef{leaf("base", "redis-base", 0)}))
	// once a v1 is shipped, an unversioned (0) replacement is a rollback.
	require.NoError(t, c.checkAndAdvanceVersions(ns, b, []bundle.LeafRef{leaf("base", "redis-base", 1)}))
	require.ErrorIs(t, c.checkAndAdvanceVersions(ns, b, []bundle.LeafRef{leaf("base", "redis-base", 0)}), bundle.ErrFragmentRollback)
}

func TestSigningEnforced_FoldsFlagAndMode(t *testing.T) {
	enforce := &bundle.TrustPolicy{Mode: bundle.ModeEnforce}
	alert := &bundle.TrustPolicy{Mode: bundle.ModeAlert}

	// enforce-mode policy enforces regardless of the legacy flag.
	c := &ContainerProfileCacheImpl{}
	c.SetBundleConfig(enforce)
	require.True(t, c.signingEnforced())

	// alert-mode policy does not enforce (unless the legacy flag says so).
	c = &ContainerProfileCacheImpl{}
	c.SetBundleConfig(alert)
	require.False(t, c.signingEnforced())

	// legacy requireSignedObjects still enforces with no/alert policy (back-compat).
	c = &ContainerProfileCacheImpl{}
	c.cfg.EnableSignatureVerification = true
	require.True(t, c.signingEnforced())

	// nothing set → not enforced.
	c = &ContainerProfileCacheImpl{}
	require.False(t, c.signingEnforced())
}
