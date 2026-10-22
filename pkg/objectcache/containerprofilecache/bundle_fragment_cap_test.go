//go:build experimental_signing

package containerprofilecache

import (
	"fmt"
	"testing"

	"github.com/kubescape/node-agent/pkg/signature/bundle"
	"github.com/kubescape/node-agent/pkg/storage"
	"github.com/kubescape/storage/pkg/apis/softwarecomposition/v1beta1"
	"github.com/stretchr/testify/require"
)

// W8: the per-bundle fragment cap — maxBundleFragments verified members
// assemble and enforce; ONE fragment over the cap fails the WHOLE bundle
// closed (assembly aborts, nothing is enforced from a stack an attacker can
// inflate). Multi-stacking has a hard, tested ceiling.
func TestBundleFragmentCap_BoundaryAndOverflow(t *testing.T) {
	vendor := bkey(t)

	build := func(n int) []*v1beta1.ContainerProfile {
		frags := make([]*v1beta1.ContainerProfile, 0, n)
		for i := 0; i < n; i++ {
			frags = append(frags, bfragIn(t, fmt.Sprintf("cap-frag-%03d", i), "base", "default", "capped",
				v1beta1.ContainerProfileSpec{
					Execs: []v1beta1.ExecCalls{{Path: fmt.Sprintf("/bin/tool-%03d", i)}},
				}, vendor))
		}
		return frags
	}
	policyFor := func(frag *v1beta1.ContainerProfile) *bundle.TrustPolicy {
		id, err := bundle.SignerID(frag)
		require.NoError(t, err)
		return &bundle.TrustPolicy{Classes: map[bundle.FragmentClass]bundle.ClassPolicy{
			bundle.ClassBase: {Signers: []string{id}, AllowedSpecPaths: []string{"execs"}},
		}}
	}

	t.Run("at_the_cap_the_stack_enforces", func(t *testing.T) {
		frags := build(maxBundleFragments)
		mock := &storage.StorageHttpClientMock{ContainerProfiles: frags}
		c, k8s := newTestCache(t, mock)
		c.SetBundleConfig(policyFor(frags[0]))
		primeSharedData(t, k8s, "container-cap-ok", "wlid://cluster-a/namespace-default/deployment-cap")
		bindToProfile(t, c, "container-cap-ok", "capped")
		require.True(t, execEnforced(c, "container-cap-ok", "/bin/tool-000"),
			"a stack of exactly maxBundleFragments members must assemble and enforce")
		require.True(t, execEnforced(c, "container-cap-ok", fmt.Sprintf("/bin/tool-%03d", maxBundleFragments-1)),
			"the last member's grant must be part of the union")
	})

	t.Run("one_over_the_cap_fails_the_whole_bundle_closed", func(t *testing.T) {
		frags := build(maxBundleFragments + 1)
		mock := &storage.StorageHttpClientMock{ContainerProfiles: frags}
		c, k8s := newTestCache(t, mock)
		c.SetBundleConfig(policyFor(frags[0]))
		primeSharedData(t, k8s, "container-cap-over", "wlid://cluster-a/namespace-default/deployment-cap")
		bindToProfile(t, c, "container-cap-over", "capped")
		require.False(t, execEnforced(c, "container-cap-over", "/bin/tool-000"),
			"an inflated stack must not enforce ANY member — the cap fails the bundle closed")
	})
}
