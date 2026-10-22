//go:build experimental_signing

package containerprofilecache

import (
	"context"
	"crypto/sha256"
	"encoding/json"
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

// signingProvenance records admission of the adopted profile. Bundles require
// fresh verification under a replacement policy before retention on errors;
// flat profiles use policy-independent signature verification.
type signingProvenance struct {
	verifiedBundlePolicy *bundle.TrustPolicy
	verifiedFlat         bool
	unsigned             bool
	refused              bool
	// sourceSpecHash binds admission provenance to the content used for projection.
	sourceSpecHash [sha256.Size]byte
}

// signingBinding preserves the pod label separately from the resolved flat CP.
type signingBinding struct{ bundleName string }

func (*ContainerProfileCacheImpl) setSigningBinding(entry *CachedContainerProfile, name string) {
	entry.bundleName = name
}
func (*ContainerProfileCacheImpl) signingBundleName(entry *CachedContainerProfile) string {
	if entry.bundleName != "" {
		return entry.bundleName
	}
	if entry.UserCPRef != nil {
		return entry.UserCPRef.Name
	}
	return ""
}

// Flat signatures use cryptographic verification independently of bundle policy.
func (c *ContainerProfileCacheImpl) handleProfileFetchError(id string, entry *CachedContainerProfile) {
	if c.requiresSignedProfile() && !entry.verifiedFlat &&
		(entry.verifiedBundlePolicy == nil || entry.verifiedBundlePolicy != c.bundleTrustPolicy.Load()) {
		c.refuseSignedProfile(id, entry)
	}
}

func (c *ContainerProfileCacheImpl) noteAdoptedProfile(provenance signingProvenance, cp *v1beta1.ContainerProfile, wlid string) {
	if provenance.unsigned {
		c.noteUnsignedGoverns(verifyUnsigned, cp, wlid)
	}
}

func (c *ContainerProfileCacheImpl) loadSignedBundle(ctx context.Context, ns, name, wlid string) (*v1beta1.ContainerProfile, bool, signingProvenance, error) {
	policy := c.bundleTrustPolicy.Load()
	cp, err := c.assembleUserBundleWithPolicy(ctx, ns, name, wlid, policy)
	provenance := signingProvenance{}
	if cp != nil && err == nil {
		provenance.sourceSpecHash, err = profileSpecHash(cp)
		if err != nil {
			return nil, true, signingProvenance{}, err
		}
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
func (c *ContainerProfileCacheImpl) admitSignedProfile(cp *v1beta1.ContainerProfile, wlid string) (*v1beta1.ContainerProfile, bool, signingProvenance) {
	if cp == nil {
		return nil, false, signingProvenance{}
	}
	cp = cp.DeepCopy()
	verdict := c.verifyUserContainerProfileVerdict(cp, wlid)
	if verdict == verifyInvalidEmbedded || (c.signingEnforced() && verdict != verifyOK) {
		return nil, true, signingProvenance{}
	}
	specHash, err := profileSpecHash(cp)
	if err != nil {
		return nil, true, signingProvenance{}
	}
	return cp, false, signingProvenance{verifiedFlat: verdict == verifyOK, unsigned: verdict == verifyUnsigned, sourceSpecHash: specHash}
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
	c.rebuildEntryFromSources(id, entry, empty, nil, signingProvenance{refused: true})
}

func (*ContainerProfileCacheImpl) preserveSignedBundleReference(entry, prev *CachedContainerProfile) {
	if entry.verifiedBundlePolicy != nil && prev.UserCPRef != nil {
		entry.UserCPRef = prev.UserCPRef
	}
}

// Hash the admitted spec, after embedded signed content has been restored.
// Grouped documents may cause a conservative rebuild for another section's edit,
// but unchanged resource versions can never attach new trust to old grants.
func profileSpecHash(cp *v1beta1.ContainerProfile) ([sha256.Size]byte, error) {
	content, err := json.Marshal(cp.Spec)
	if err != nil {
		return [sha256.Size]byte{}, err
	}
	return sha256.Sum256(content), nil
}

func (*ContainerProfileCacheImpl) canSkipSignedRefresh(entry *CachedContainerProfile, provenance signingProvenance) bool {
	return !entry.refused && entry.sourceSpecHash == provenance.sourceSpecHash
}
