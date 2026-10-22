//go:build experimental_signing

package containerprofilecache

import (
	"context"
	"errors"
	"fmt"
	"strings"

	"github.com/kubescape/go-logger"
	"github.com/kubescape/go-logger/helpers"
	helpersv1 "github.com/kubescape/k8s-interface/instanceidhandler/v1/helpers"
	"github.com/kubescape/node-agent/pkg/signature/bundle"
	"github.com/kubescape/storage/pkg/apis/softwarecomposition/v1beta1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

// SetBundleConfig enables signed-bundle overlays. node-agent only needs the
// trust policy (the public-key fingerprints per fragment class): it VERIFIES
// fragment signatures, it never signs. No private key exists on the cluster.
// When the trust policy is set bundle assembly runs; otherwise the cache uses
// the single-CP overlay path. Wired from cmd/main.go after config load.
// maxBundleFragments caps the fragments assembled per bundle per reconcile tick.
const maxBundleFragments = 64

func (c *ContainerProfileCacheImpl) SetBundleConfig(policy *bundle.TrustPolicy) {
	c.bundleTrustPolicy.Store(policy)
}

func (c *ContainerProfileCacheImpl) bundlesEnabled() bool {
	return c.bundleTrustPolicy.Load() != nil
}

// signingEnforced reports whether unsigned/unverifiable user objects must be
// refused. Enforce mode enforces; the legacy requireSignedObjects flag still
// enforces for deployments that set it.
func (c *ContainerProfileCacheImpl) signingEnforced() bool {
	if p := c.bundleTrustPolicy.Load(); p != nil && p.Enforcing() {
		return true
	}
	return c.cfg.EnableSignatureVerification
}

// assembleUserBundle resolves a user-defined-profile label that names a signed
// bundle: it lists the bundle's fragments, verifies each against the trust
// policy, and deterministically assembles the admissible fragments into an
// in-memory composite. The composite is assembled from the just-verified
// fragments and is trusted in-process by the reconciler (no on-cluster
// signing).
//
// Returns:
//   - (composite, nil) when a bundle was assembled — use it as the overlay;
//   - (nil, nil)        when bundles are disabled, or no class-labeled fragments
//     exist for this name (fall back to the single-CP path);
//   - (nil, err)        when fragments exist but fail verification/assembly. A
//     tampered fragment additionally raises R1016 (deduped).
func (c *ContainerProfileCacheImpl) assembleUserBundle(ctx context.Context, ns, bundleName, wlid string) (*v1beta1.ContainerProfile, error) {
	policy := c.bundleTrustPolicy.Load()
	if policy == nil || bundleName == "" {
		return nil, nil
	}

	var (
		list *v1beta1.ContainerProfileList
		lerr error
	)
	_ = c.refreshRPC(ctx, func(rctx context.Context) error {
		lister, ok := c.storageClient.(interface {
			ListContainerProfiles(context.Context, string, metav1.ListOptions) (*v1beta1.ContainerProfileList, error)
		})
		if !ok {
			lerr = fmt.Errorf("profile client does not support signed bundle listing")
			return lerr
		}
		list, lerr = lister.ListContainerProfiles(rctx, ns, metav1.ListOptions{
			LabelSelector: bundle.LabelBundle + "=" + bundleName,
		})
		return lerr
	})
	if lerr != nil || list == nil {
		return nil, lerr
	}

	// The storage server's List serves items from its metadata table WITHOUT
	// loading the payload — the returned objects are spec-stripped. Hashing those
	// would flag every signed fragment as tampered. Use the List only to discover
	// the fragment set (names + labels round-trip fine) and GET each fragment for
	// its full spec.
	//
	// The storage server also IGNORES the List label selector, returning every
	// CP in the namespace — so the bundle membership MUST be re-checked here.
	// Without this, any user-defined-profile name would assemble ALL fragments
	// in the namespace (observed live: a client workload's profile lookup
	// assembled the server's fragments).
	var frags []*v1beta1.ContainerProfile
	for i := range list.Items {
		item := &list.Items[i]
		if item.Labels[bundle.LabelBundle] != bundleName {
			continue
		}
		if _, ok := item.Labels[bundle.LabelFragmentClass]; !ok {
			continue
		}
		// Bound the fragment count: assembly runs every reconcile tick (cosign
		// verify + gunzip + JSON per fragment), so an attacker who can create CPs
		// in the namespace could otherwise drive per-tick CPU/RPC without limit.
		if len(frags) >= maxBundleFragments {
			return nil, fmt.Errorf("bundle %q exceeds %d fragments", bundleName, maxBundleFragments)
		}
		var (
			full *v1beta1.ContainerProfile
			gerr error
		)
		_ = c.refreshRPC(ctx, func(rctx context.Context) error {
			full, gerr = c.storageClient.GetContainerProfile(rctx, ns, item.Name)
			return gerr
		})
		if gerr != nil || full == nil {
			// Transient fetch failure: fail this assembly attempt as operational
			// (NOT tamper — no R1016); the caller retries on the next tick.
			return nil, fmt.Errorf("fetch bundle fragment %q: %w", item.Name, gerr)
		}
		frags = append(frags, full)
	}
	if len(frags) == 0 {
		return nil, nil // not a bundle — single-CP path handles it
	}
	for _, f := range frags {
		c.reportSpecDivergence("bundle/"+ns+"/"+bundleName+"/"+f.Name, f, bundleName, ns)
	}

	bundleKey := ns + "/" + bundleName
	composite, manifest, dropped, err := bundle.AssembleAndVerifyPartial(bundleName, ns, frags, *policy)

	// Invariant: only a slot that was ever an admitted member (present in
	// bundleVersions) can be a genuine tamper — a non-verifying object's cert is
	// attacker-suppliable. Never-admitted drop = non-member, skip. Known slot now
	// failing = member tamper, fail closed.
	var knownBad []bundle.DroppedFragment
	nonMembers := 0
	for _, d := range dropped {
		slot := ns + "/" + bundleName + "/" + string(d.Class) + "/" + d.Name
		if _, known := c.bundleVersions.Load(slot); known {
			knownBad = append(knownBad, d)
		} else {
			nonMembers++
		}
	}

	if len(knownBad) > 0 {
		tamper := false
		for _, d := range knownBad {
			if errors.Is(d.Reason, bundle.ErrFragmentTampered) {
				tamper = true
			}
		}
		if tamper {
			// Edge-triggered per bundle: alert once per observed clean→tamper
			// transition, re-arm on the next clean assembly (below).
			if _, was := c.bundleTampered.LoadOrStore(bundleKey, struct{}{}); !was {
				c.emitTamperAlert(bundleName, ns, wlid, "ContainerProfile bundle", knownBad[0].Reason)
			}
		}
		names := make([]string, 0, len(knownBad))
		for _, d := range knownBad {
			names = append(names, d.Name)
		}
		logger.L().Warning("signed bundle overlay refused: a verified member no longer verifies; keeping the last verified composite",
			helpers.String("bundle", bundleName),
			helpers.String("namespace", ns),
			helpers.String("members", strings.Join(names, ",")),
			helpers.Error(knownBad[0].Reason))
		return nil, knownBad[0].Reason
	}

	// Non-members are dropped, not fatal. Dedup the alert per BUNDLE (never per
	// object), so a spamming writer cannot flood.
	if nonMembers > 0 {
		if _, was := c.bundleNonMembers.LoadOrStore(bundleKey, struct{}{}); !was {
			logger.L().Warning("signed bundle overlay: dropped non-member object(s) labelled into the bundle by an unauthorised writer",
				helpers.String("bundle", bundleName),
				helpers.String("namespace", ns),
				helpers.Int("dropped", nonMembers))
		}
	} else {
		c.bundleNonMembers.Delete(bundleKey)
	}

	if err != nil {
		// Nothing admissible remained (ErrEmptyBundle) or an internal assembly
		// error — not a member-tamper, so no R1016.
		logger.L().Warning("signed bundle overlay not assembled",
			helpers.String("bundle", bundleName),
			helpers.String("namespace", ns),
			helpers.Int("fragments", len(frags)),
			helpers.Error(err))
		return nil, err
	}
	// Rollback guard: a replayed older-but-valid fragment is refused (not a
	// tamper, no R1016), keeping the last verified composite.
	if verr := c.checkAndAdvanceVersions(ns, bundleName, manifest.Leaves); verr != nil {
		logger.L().Warning("signed bundle overlay refused: fragment rollback",
			helpers.String("bundle", bundleName),
			helpers.String("namespace", ns),
			helpers.Error(verr))
		return nil, verr
	}

	// A clean assembly re-arms the edge-trigger so a later tamper alerts again.
	c.bundleTampered.Delete(bundleKey)

	// The composite is in-memory only (never stored), so it has no server
	// ResourceVersion. Use the Merkle root as its RV: it is a stable content hash
	// of the admissible leaf set, so the reconciler's RV fast-skip naturally
	// skips rebuilds while the fragments are unchanged and rebuilds when any
	// fragment (and hence the root) changes.
	composite.ResourceVersion = manifest.Root
	if composite.Annotations == nil {
		composite.Annotations = map[string]string{}
	}
	composite.Annotations[helpersv1.SyncChecksumMetadataKey] = manifest.Root

	// The composite is NOT signed on-cluster: node-agent only verifies fragment
	// signatures (offline vendor/operator keys). The composite is verified by
	// construction from the just-verified fragments and is trusted in-process by
	// the reconciler (it bypasses the flat verifyUserContainerProfile path).

	// Log root TRANSITIONS at Info (first assembly, fragment-set change) so the
	// bundle lifecycle is visible at default log level without drowning the log
	// in per-tick lines; unchanged re-assemblies stay at Debug.
	rootKey := ns + "/" + bundleName
	if prev, _ := c.bundleRoots.Load(rootKey); prev != manifest.Root {
		c.bundleRoots.Store(rootKey, manifest.Root)
		logger.L().Info("assembled signed bundle overlay",
			helpers.String("bundle", bundleName),
			helpers.String("namespace", ns),
			helpers.Int("fragments", len(frags)),
			helpers.String("root", manifest.Root))
		c.reportShadowedProfile(ctx, ns, bundleName, len(frags))
	} else {
		logger.L().Debug("assembled signed bundle overlay",
			helpers.String("bundle", bundleName),
			helpers.String("namespace", ns),
			helpers.Int("fragments", len(frags)),
			helpers.String("root", manifest.Root))
	}
	return composite, nil
}

// reportShadowedProfile makes outcome 2 of user-defined-profile resolution
// visible: a verifying bundle shadows the identically named classical
// ContainerProfile, which is otherwise silent — kubectl shows both objects
// with nothing indicating which is in force. Runs only on root transitions
// (the caller's gate), so steady state costs no storage reads. A same-named
// object that is itself a bundle member is not shadowed. Observability only:
// lookup errors report nothing.
func (c *ContainerProfileCacheImpl) reportShadowedProfile(ctx context.Context, ns, bundleName string, fragments int) {
	var shadowed *v1beta1.ContainerProfile
	_ = c.refreshRPC(ctx, func(rctx context.Context) error {
		cp, err := c.storageClient.GetContainerProfile(rctx, ns, bundleName)
		if err == nil {
			shadowed = cp
		}
		return nil
	})
	if shadowed == nil || shadowed.Labels[bundle.LabelBundle] == bundleName {
		return
	}
	logger.L().Info("signed bundle overlay shadows a ContainerProfile of the same name: the bundle is enforced, the named profile is not",
		helpers.String("bundle", bundleName),
		helpers.String("namespace", ns),
		helpers.String("profile", bundleName),
		helpers.Int("fragments", fragments))
}

// checkAndAdvanceVersions enforces per-slot monotonic versions, slot =
// (namespace, bundle, class, name). A rollback anywhere rejects the whole
// assembly before any high-water-mark advances. Marks are in-memory and reset on
// restart (a rollback right after restart is not caught).
func (c *ContainerProfileCacheImpl) checkAndAdvanceVersions(ns, bundleName string, leaves []bundle.LeafRef) error {
	slot := func(lf bundle.LeafRef) string {
		return ns + "/" + bundleName + "/" + string(lf.Class) + "/" + lf.Name
	}
	for _, lf := range leaves {
		if prev, ok := c.bundleVersions.Load(slot(lf)); ok && lf.Version < prev.(int64) {
			return fmt.Errorf("%w: %s version %d < accepted %d", bundle.ErrFragmentRollback, slot(lf), lf.Version, prev.(int64))
		}
	}
	for _, lf := range leaves {
		key := slot(lf)
		for {
			prev, loaded := c.bundleVersions.LoadOrStore(key, lf.Version)
			if !loaded || lf.Version <= prev.(int64) {
				break
			}
			if c.bundleVersions.CompareAndSwap(key, prev, lf.Version) {
				break
			}
		}
	}
	return nil
}
