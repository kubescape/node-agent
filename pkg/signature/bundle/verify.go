//go:build experimental_signing

package bundle

import (
	"encoding/json"
	"errors"
	"fmt"
	"sort"
	"strconv"

	"github.com/kubescape/node-agent/pkg/signature"
	"github.com/kubescape/node-agent/pkg/signature/profiles"
	"github.com/kubescape/storage/pkg/apis/softwarecomposition/v1beta1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

// Admissibility failure sentinels. ErrFragmentTampered is the one the caller
// should surface as an R1016 tamper alert; the rest are policy rejections.
var (
	ErrNoClass          = errors.New("fragment has no fragment-class label")
	ErrClassNotAllowed  = errors.New("fragment class not present in trust policy")
	ErrFragmentUnsigned = errors.New("fragment is not signed")
	ErrFragmentTampered = errors.New("fragment signature does not verify (tampered)")
	ErrSignerNotTrusted = errors.New("signer not permitted for this fragment class")
	ErrPathNotAllowed   = errors.New("fragment sets a spec path not permitted for its class")
	ErrEmptyBundle      = errors.New("bundle has no fragments")
	ErrGroupedFragment  = errors.New("grouped container profiles are not supported as bundle fragments")
	// ErrFragmentRollback is a replay of an older, still-validly-signed fragment:
	// its version is below the highest already accepted for its slot. It is NOT a
	// tamper (the signature verifies), so it does not raise R1016; it is refused
	// and the workload keeps its last verified composite.
	ErrFragmentRollback = errors.New("fragment version is below the highest already accepted (rollback)")
)

type verifiedFragment struct {
	name    string
	spec    v1beta1.ContainerProfileSpec
	class   FragmentClass
	signer  string
	digest  string
	version int64
}

// fragmentVersion reads the monotonic version from the verified labels. Absent
// is version 0 (back-compatible); a present-but-unparseable value is an error,
// since it appears inside signed content and must not be silently ignored.
func fragmentVersion(labels map[string]string) (int64, error) {
	raw, ok := labels[LabelVersion]
	if !ok || raw == "" {
		return 0, nil
	}
	v, err := strconv.ParseInt(raw, 10, 64)
	if err != nil {
		return 0, fmt.Errorf("parse %s=%q: %w", LabelVersion, raw, err)
	}
	if v < 0 {
		return 0, fmt.Errorf("%s=%d must not be negative", LabelVersion, v)
	}
	return v, nil
}

// embeddedView is the canonical signed content layout produced by the
// ContainerProfile adapter's GetContent.
type embeddedView struct {
	Metadata struct {
		Name   string            `json:"name"`
		Labels map[string]string `json:"labels"`
	} `json:"metadata"`
	Spec v1beta1.ContainerProfileSpec `json:"spec"`
}

// admitFragment runs the full admissibility check on one fragment: it must be
// class-labeled, signed, verify cleanly, be signed by a class-trusted signer,
// and set only spec paths its class is allowed to contribute.
//
// When the fragment carries embedded signed content (vendor-shipped artifacts,
// signed with --embed-content), the EMBEDDED bytes are the verified source of
// truth: labels (class + bundle membership), spec, name, and the leaf digest
// all come from them — the stored object is just a carrier whose spec the
// server may have normalised. Without embedded content the stored form is
// verified directly (legacy sign-after-roundtrip artifacts).
func admitFragment(cp *v1beta1.ContainerProfile, bundleName string, policy TrustPolicy) (verifiedFragment, error) {
	adapter := profiles.NewContainerProfileAdapter(cp)
	if !signature.IsSigned(adapter) {
		return verifiedFragment{}, fmt.Errorf("%w: %q", ErrFragmentUnsigned, cp.Name)
	}
	if err := signature.VerifyObjectAllowUntrusted(adapter); err != nil {
		if errors.Is(err, signature.ErrSignatureMismatch) {
			return verifiedFragment{}, fmt.Errorf("%w: %q: %v", ErrFragmentTampered, cp.Name, err)
		}
		return verifiedFragment{}, fmt.Errorf("verify fragment %q: %w", cp.Name, err)
	}

	// Establish the verified view: embedded content when present, else the
	// stored object.
	name := cp.Name
	labels := cp.Labels
	spec := cp.Spec
	var digest string
	if embedded, present, embErr := signature.EmbeddedContent(adapter); present {
		if embErr != nil {
			return verifiedFragment{}, fmt.Errorf("embedded content of %q: %w", cp.Name, embErr)
		}
		var view embeddedView
		if err := json.Unmarshal(embedded, &view); err != nil {
			return verifiedFragment{}, fmt.Errorf("parse embedded content of %q: %w", cp.Name, err)
		}
		name = view.Metadata.Name
		labels = view.Metadata.Labels
		spec = view.Spec
		h, err := signature.HashBytes(embedded)
		if err != nil {
			return verifiedFragment{}, fmt.Errorf("digest of %q: %w", cp.Name, err)
		}
		digest = h
	} else {
		h, err := contentDigest(cp)
		if err != nil {
			return verifiedFragment{}, fmt.Errorf("digest of %q: %w", cp.Name, err)
		}
		digest = h
	}

	// Bundle membership from the VERIFIED labels: a signed fragment cannot be
	// re-labeled into another bundle, because the labels are inside the signed
	// content.
	if labels[LabelBundle] != bundleName {
		return verifiedFragment{}, fmt.Errorf("%w: fragment %q belongs to bundle %q, not %q", ErrNoClass, name, labels[LabelBundle], bundleName)
	}
	class := FragmentClass(labels[LabelFragmentClass])
	if class == "" {
		return verifiedFragment{}, fmt.Errorf("%w: %q", ErrNoClass, name)
	}
	cpol, ok := policy.Classes[class]
	if !ok {
		return verifiedFragment{}, fmt.Errorf("%w: class %q (fragment %q)", ErrClassNotAllowed, class, name)
	}

	sig, err := signature.GetObjectSignature(adapter)
	if err != nil {
		return verifiedFragment{}, fmt.Errorf("read signature of %q: %w", name, err)
	}
	signer, err := signerIdentity(sig)
	if err != nil {
		return verifiedFragment{}, fmt.Errorf("signer identity of %q: %w", name, err)
	}
	if !cpol.allowsSigner(signer) {
		return verifiedFragment{}, fmt.Errorf("%w: signer %q, class %q (fragment %q)", ErrSignerNotTrusted, signer, class, name)
	}

	// Assembly and class-path restrictions currently support flat specs only.
	// Reject grouped grants from the verified view rather than silently dropping
	// them while producing a seemingly valid composite and manifest.
	if len(spec.Containers) > 0 || len(spec.InitContainers) > 0 || len(spec.EphemeralContainers) > 0 {
		return verifiedFragment{}, fmt.Errorf("%w: %q", ErrGroupedFragment, name)
	}

	for _, p := range setSpecPaths(&spec) {
		if !cpol.allowsPath(p) {
			return verifiedFragment{}, fmt.Errorf("%w: class %q may not set spec.%s (fragment %q)", ErrPathNotAllowed, class, p, name)
		}
	}

	version, err := fragmentVersion(labels)
	if err != nil {
		return verifiedFragment{}, fmt.Errorf("version of %q: %w", name, err)
	}

	return verifiedFragment{name: name, spec: spec, class: class, signer: signer, digest: digest, version: version}, nil
}

// AssembleAndVerify verifies every fragment against the trust policy,
// deterministically assembles the admissible fragments into one composite
// ContainerProfile, and stamps the composite with a Merkle-bound bundle
// manifest. It fails closed: a single inadmissible or tampered fragment rejects
// the whole bundle (the returned error wraps the relevant sentinel).
//
// The composite is NOT signed on-cluster: node-agent only verifies fragment
// signatures. The composite is verified by construction from the just-verified
// fragments and is trusted in-process by the caller.
func AssembleAndVerify(name, namespace string, fragments []*v1beta1.ContainerProfile, policy TrustPolicy) (*v1beta1.ContainerProfile, *BundleManifest, error) {
	if len(fragments) == 0 {
		return nil, nil, ErrEmptyBundle
	}

	verified := make([]verifiedFragment, 0, len(fragments))
	for _, f := range fragments {
		vf, err := admitFragment(f, name, policy)
		if err != nil {
			return nil, nil, err
		}
		verified = append(verified, vf)
	}
	return assembleVerified(name, namespace, verified)
}

// DroppedFragment is a fragment AssembleAndVerifyPartial refused as a member,
// with the error that excluded it.
type DroppedFragment struct {
	Name   string
	Bundle string
	Class  FragmentClass
	Reason error
}

// AssembleAndVerifyPartial verifies each fragment, SKIPS every inadmissible one
// (returned in dropped), and assembles the admissible remainder. Membership is
// authenticated (only class-trusted signers count), so an injected non-member
// cannot deny the bundle. ErrEmptyBundle when nothing admissible remains; the
// caller uses its own known-good state to decide if a drop is a member tamper.
func AssembleAndVerifyPartial(name, namespace string, fragments []*v1beta1.ContainerProfile, policy TrustPolicy) (*v1beta1.ContainerProfile, *BundleManifest, []DroppedFragment, error) {
	verified := make([]verifiedFragment, 0, len(fragments))
	var dropped []DroppedFragment
	for _, f := range fragments {
		vf, err := admitFragment(f, name, policy)
		if err != nil {
			dropped = append(dropped, DroppedFragment{
				Name:   f.Name,
				Bundle: name,
				Class:  FragmentClass(f.Labels[LabelFragmentClass]),
				Reason: err,
			})
			continue
		}
		verified = append(verified, vf)
	}
	if len(verified) == 0 {
		return nil, nil, dropped, ErrEmptyBundle
	}
	composite, manifest, err := assembleVerified(name, namespace, verified)
	return composite, manifest, dropped, err
}

// assembleVerified deterministically assembles already-verified fragments into
// the composite + Merkle-bound manifest. Shared by AssembleAndVerify (fail
// closed) and AssembleAndVerifyPartial (skip non-members).
func assembleVerified(name, namespace string, verified []verifiedFragment) (*v1beta1.ContainerProfile, *BundleManifest, error) {
	// Canonical order: class precedence, then signer, then content digest. This
	// makes the composite (and its Merkle root) independent of input order.
	sort.SliceStable(verified, func(i, j int) bool {
		if pi, pj := classPrecedence(verified[i].class), classPrecedence(verified[j].class); pi != pj {
			return pi < pj
		}
		if verified[i].signer != verified[j].signer {
			return verified[i].signer < verified[j].signer
		}
		return verified[i].digest < verified[j].digest
	})

	spec := assembleSpec(verified)

	leaves := make([]LeafRef, len(verified))
	for i, vf := range verified {
		leaves[i] = LeafRef{Class: vf.class, Signer: vf.signer, Name: vf.name, ContentDigest: vf.digest, Version: vf.version}
	}
	manifest := &BundleManifest{Root: rootFromLeaves(leaves), Leaves: leaves}
	if verr := VerifyManifestRoot(manifest); verr != nil {
		return nil, nil, fmt.Errorf("internal: %w", verr)
	}
	mb, err := json.Marshal(manifest)
	if err != nil {
		return nil, nil, fmt.Errorf("marshal manifest: %w", err)
	}

	composite := &v1beta1.ContainerProfile{
		TypeMeta: metav1.TypeMeta{
			APIVersion: "spdx.softwarecomposition.kubescape.io/v1beta1",
			Kind:       "ContainerProfile",
		},
		ObjectMeta: metav1.ObjectMeta{
			Name:        name,
			Namespace:   namespace,
			Labels:      map[string]string{LabelBundle: name},
			Annotations: map[string]string{ManifestAnnotation: string(mb)},
		},
		Spec: spec,
	}
	return composite, manifest, nil
}

// VerifyManifestRoot recomputes the Merkle root from a manifest's own leaves and
// checks it against the committed Root. A mismatch means the manifest's leaf set
// was altered (a fragment added/dropped/reordered) — a composite-tamper event.
func VerifyManifestRoot(manifest *BundleManifest) error {
	if manifest == nil {
		return fmt.Errorf("nil manifest")
	}
	if got := rootFromLeaves(manifest.Leaves); got != manifest.Root {
		return fmt.Errorf("bundle manifest root mismatch: committed %s, recomputed %s", manifest.Root, got)
	}
	return nil
}

// ManifestFromComposite extracts and parses the bundle manifest annotation.
func ManifestFromComposite(composite *v1beta1.ContainerProfile) (*BundleManifest, error) {
	if composite == nil || composite.Annotations == nil {
		return nil, fmt.Errorf("composite has no annotations")
	}
	raw, ok := composite.Annotations[ManifestAnnotation]
	if !ok {
		return nil, fmt.Errorf("composite has no %s annotation", ManifestAnnotation)
	}
	var m BundleManifest
	if err := json.Unmarshal([]byte(raw), &m); err != nil {
		return nil, fmt.Errorf("parse bundle manifest: %w", err)
	}
	return &m, nil
}
