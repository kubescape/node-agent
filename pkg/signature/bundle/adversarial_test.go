//go:build experimental_signing

package bundle

// Adversarial tests: an attacker with full kubectl on ContainerProfiles tries to
// get malicious content enforced through the bundle path. node-agent only
// VERIFIES fragment signatures against the trust policy (public-key
// fingerprints) — it holds no signing key — so every one of these must fail
// closed. Each test is one attack vector.

import (
	"crypto/ecdsa"
	"errors"
	"testing"

	"github.com/kubescape/node-agent/pkg/signature"
	"github.com/kubescape/storage/pkg/apis/softwarecomposition/v1beta1"
)

// redisTrust builds the demo trust policy and returns it alongside the vendor
// (base) and operator (admission) keys. The attacker key is deliberately NOT in
// the policy.
func redisTrust(t *testing.T) (policy TrustPolicy, vendor, operator *ecdsa.PrivateKey) {
	t.Helper()
	vendor, operator = genKey(t), genKey(t)
	vendorID := signerIDOf(t, fragment(t, "id-base", string(ClassBase), baseSpec(), vendor))
	operatorID := signerIDOf(t, fragment(t, "id-adm", string(ClassAdmission), admissionSpec(), operator))
	return redisPolicy(vendorID, operatorID), vendor, operator
}

// Attack 1 — the scenario from the design review: an attacker injects an extra
// admission "client" fragment signed with their OWN key. Even though it is a
// syntactically valid, signed, correctly-classed fragment, the signer is not
// trusted for the class, so the whole bundle is rejected.
func TestAdversarial_ClientInjection_SelfSignedKeyRejected(t *testing.T) {
	policy, vendor, operator := redisTrust(t)
	attacker := genKey(t)

	base := fragment(t, "redis-base", string(ClassBase), baseSpec(), vendor)
	legit := fragment(t, "redis-client", string(ClassAdmission), admissionSpec(), operator)
	evil := fragment(t, "evil-client", string(ClassAdmission), admissionSpec(), attacker)

	_, _, err := AssembleAndVerify("redis", "redis", []*v1beta1.ContainerProfile{base, legit, evil}, policy)
	if !errors.Is(err, ErrSignerNotTrusted) {
		t.Fatalf("attacker-signed client fragment must be rejected as untrusted signer, got: %v", err)
	}
}

// Attack 2 — cross-class key confusion: the vendor key IS trusted, but only for
// the base class. Using it to sign an admission fragment (to smuggle ingress)
// must still be rejected: trust is bound per class, not per key.
func TestAdversarial_CrossClassKeyConfusion_VendorKeyOnAdmission(t *testing.T) {
	policy, vendor, _ := redisTrust(t)

	base := fragment(t, "redis-base", string(ClassBase), baseSpec(), vendor)
	// vendor (a trusted key) signs an admission-class fragment it is not
	// permitted to sign.
	crossClass := fragment(t, "sneaky-admission", string(ClassAdmission), admissionSpec(), vendor)

	_, _, err := AssembleAndVerify("redis", "redis", []*v1beta1.ContainerProfile{base, crossClass}, policy)
	if !errors.Is(err, ErrSignerNotTrusted) {
		t.Fatalf("a key trusted for base must not sign admission fragments, got: %v", err)
	}
}

// Attack 3 — signature stripping: take a validly-signed fragment and delete its
// signature annotation, hoping an unsigned fragment slips through. It must be
// rejected as unsigned (signing is not optional inside a bundle).
func TestAdversarial_SignatureStripped_Rejected(t *testing.T) {
	policy, vendor, operator := redisTrust(t)

	base := fragment(t, "redis-base", string(ClassBase), baseSpec(), vendor)
	adm := fragment(t, "redis-client", string(ClassAdmission), admissionSpec(), operator)
	delete(adm.Annotations, signature.AnnotationSignature)

	_, _, err := AssembleAndVerify("redis", "redis", []*v1beta1.ContainerProfile{base, adm}, policy)
	if !errors.Is(err, ErrFragmentUnsigned) {
		t.Fatalf("signature-stripped fragment must be rejected as unsigned, got: %v", err)
	}
}

// Attack 4 — forged identity via certificate swap: the attacker signs a
// malicious fragment with their own key, then overwrites the certificate
// annotation with the trusted operator's certificate to *claim* the operator's
// identity. The signature was made by the attacker's key, so it does not verify
// against the operator's certificate → tamper. You cannot borrow an identity by
// copying its public certificate.
func TestAdversarial_CertificateSwap_ForgedIdentityRejected(t *testing.T) {
	policy, vendor, operator := redisTrust(t)
	attacker := genKey(t)

	base := fragment(t, "redis-base", string(ClassBase), baseSpec(), vendor)
	legit := fragment(t, "redis-client", string(ClassAdmission), admissionSpec(), operator)
	evil := fragment(t, "redis-client", string(ClassAdmission), admissionSpec(), attacker)
	// Claim the operator's identity by stapling their certificate onto the
	// attacker-signed object.
	evil.Annotations[signature.AnnotationCertificate] = legit.Annotations[signature.AnnotationCertificate]

	_, _, err := AssembleAndVerify("redis", "redis", []*v1beta1.ContainerProfile{base, evil}, policy)
	if !errors.Is(err, ErrFragmentTampered) {
		t.Fatalf("attacker signature under a swapped operator certificate must fail verification, got: %v", err)
	}
}

// Attack 5 — a fragment whose class is not present in the trust policy at all
// (e.g. a made-up class) is rejected: the policy is an allowlist of classes.
func TestAdversarial_UnknownClassRejected(t *testing.T) {
	policy, vendor, operator := redisTrust(t)

	base := fragment(t, "redis-base", string(ClassBase), baseSpec(), vendor)
	// operator is a trusted key, but "overlay" is not a class in this policy.
	unknown := fragment(t, "mystery", "overlay", baseSpec(), operator)

	_, _, err := AssembleAndVerify("redis", "redis", []*v1beta1.ContainerProfile{base, unknown}, policy)
	if !errors.Is(err, ErrClassNotAllowed) {
		t.Fatalf("fragment of a class absent from the policy must be rejected, got: %v", err)
	}
}

// Attack 6 — rollback / replay. KNOWN GAP, asserted so the limitation is
// visible and any future fix flips this test.
//
// Each fragment is signed independently with no monotonic version bound into the
// signed content. So an attacker who possesses an OLDER, more-permissive but
// still validly-signed version of a fragment (e.g. one the operator later
// tightened) can substitute it, and it verifies cleanly — node-agent has no way
// to know it was superseded. This test documents that today the rollback is
// ACCEPTED. Closing it requires a monotonic version/nonce inside the signed
// content (and rejecting a lower version than last seen). See the design notes
// on trust-policy hardening + fragment versioning.
// TestAdversarial_RollbackReplay_GuardedByVersion documents WHERE the rollback
// defense lives. AssembleAndVerify is deliberately STATELESS: an older,
// validly-signed fragment still verifies and assembles here, because a signature
// alone cannot report that it has been superseded. The monotonic guard is one
// layer up, in the cache (checkAndAdvanceVersions), keyed on LeafRef.Version —
// which admitFragment parses from the SIGNED labels (LabelVersion). This test
// pins that the signed version reaches the leaf, so the cache guard has an
// unforgeable value to enforce against its per-slot high-water-mark.
func TestAdversarial_RollbackReplay_GuardedByVersion(t *testing.T) {
	policy, vendor, operator := redisTrust(t)

	base := fragment(t, "redis-base", string(ClassBase), baseSpec(), vendor)
	oldPermissive := fragment(t, "redis-client", string(ClassAdmission), admissionSpec(), operator)

	_, manifest, err := AssembleAndVerify("redis", "redis", []*v1beta1.ContainerProfile{base, oldPermissive}, policy)
	if err != nil {
		t.Fatalf("stateless assembly must still accept a validly-signed fragment: %v", err)
	}
	// Unversioned fragments surface as version 0 on the leaves; the cache guard
	// treats 0 as the floor, so once a versioned fragment is shipped an
	// unversioned replay is a rollback (see TestRollbackGuard_UnversionedIsZero).
	for _, lf := range manifest.Leaves {
		if lf.Version != 0 {
			t.Fatalf("unversioned fragment %q should carry version 0, got %d", lf.Name, lf.Version)
		}
	}
}
