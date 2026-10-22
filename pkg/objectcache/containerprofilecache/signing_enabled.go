//go:build experimental_signing

package containerprofilecache

import (
	"context"
	"sync"
	"sync/atomic"

	"github.com/kubescape/node-agent/pkg/exporters"
	"github.com/kubescape/node-agent/pkg/signature/bundle"
	"github.com/kubescape/storage/pkg/apis/softwarecomposition/v1beta1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

// Experimental signing state is absent from normal builds. It has no rogue
// artifact writer or governance-alert dependency.
type signingState struct {
	tamperAlertExporter exporters.Exporter
	tamperEmitted       sync.Map
	bundleTrustPolicy   atomic.Pointer[bundle.TrustPolicy]
	bundleRoots         sync.Map
	bundleTampered      sync.Map
	bundleVersions      sync.Map
	bundleNonMembers    sync.Map
	specDivergence      sync.Map
}

// signingProvenance records the immutable policy used to verify a composite.
// A replacement policy requires fresh verification before retaining it on error.
type signingProvenance struct {
	verifiedBundlePolicy *bundle.TrustPolicy
}

func (c *ContainerProfileCacheImpl) loadSignedBundle(ctx context.Context, ns, name, wlid string) (*v1beta1.ContainerProfile, bool, signingProvenance, error) {
	policy := c.bundleTrustPolicy.Load()
	cp, err := c.assembleUserBundleWithPolicy(ctx, ns, name, wlid, policy)
	provenance := signingProvenance{}
	if cp != nil && err == nil {
		provenance.verifiedBundlePolicy = policy
	}
	return cp, cp != nil || err != nil, provenance, err
}

func (c *ContainerProfileCacheImpl) handleBundleError(id string, entry *CachedContainerProfile) {
	if entry.verifiedBundlePolicy == nil || entry.verifiedBundlePolicy != c.bundleTrustPolicy.Load() {
		c.refuseSignedProfile(id, entry)
	}
}

func (c *ContainerProfileCacheImpl) requiresSignedProfile() bool { return c.signingEnforced() }

// Verify the fetched document before flattening grouped sections. Verification
// can restore its embedded signed spec, so never mutate the storage client's copy.
func (c *ContainerProfileCacheImpl) admitSignedProfile(cp *v1beta1.ContainerProfile, wlid string) (*v1beta1.ContainerProfile, bool) {
	if cp == nil {
		return nil, false
	}
	cp = cp.DeepCopy()
	verdict := c.verifyUserContainerProfileVerdict(cp, wlid)
	c.noteUnsignedGoverns(verdict, cp, wlid)
	if verdict == verifyInvalidEmbedded || (c.signingEnforced() && verdict != verifyOK) {
		return nil, true
	}
	return cp, false
}

// Refusal removes the previously admitted content from enforcement immediately
// without importing rogue-state classification or RogueArtifact persistence.
// Retain the reference so the next reconciliation can recover after re-signing.
func (c *ContainerProfileCacheImpl) refuseSignedProfile(id string, entry *CachedContainerProfile) {
	name := entry.CPName
	if entry.UserCPRef != nil {
		name = entry.UserCPRef.Name
	}
	empty := &v1beta1.ContainerProfile{ObjectMeta: metav1.ObjectMeta{Name: name, Namespace: entry.Namespace}}
	c.rebuildEntryFromSources(id, entry, empty, nil, signingProvenance{})
}
