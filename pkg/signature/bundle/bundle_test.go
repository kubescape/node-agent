//go:build experimental_signing

package bundle

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"errors"
	"testing"

	"github.com/kubescape/node-agent/pkg/signature"
	"github.com/kubescape/node-agent/pkg/signature/profiles"
	"github.com/kubescape/storage/pkg/apis/softwarecomposition/v1beta1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

func genKey(t *testing.T) *ecdsa.PrivateKey {
	t.Helper()
	k, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("gen key: %v", err)
	}
	return k
}

// fragment builds a class-labeled ContainerProfile and signs it with key.
// Labels are set BEFORE signing because they are part of the signed content
// (metadata.labels), so the signature binds the fragment's class.
func fragment(t *testing.T, name, class string, spec v1beta1.ContainerProfileSpec, key *ecdsa.PrivateKey) *v1beta1.ContainerProfile {
	t.Helper()
	cp := &v1beta1.ContainerProfile{
		ObjectMeta: metav1.ObjectMeta{
			Name:      name,
			Namespace: "redis",
			Labels: map[string]string{
				LabelBundle:        "redis",
				LabelFragmentClass: class,
			},
		},
		Spec: spec,
	}
	if err := signature.SignObject(profiles.NewContainerProfileAdapter(cp), signature.WithPrivateKey(key)); err != nil {
		t.Fatalf("sign %s: %v", name, err)
	}
	return cp
}

func signerIDOf(t *testing.T, cp *v1beta1.ContainerProfile) string {
	t.Helper()
	sig, err := signature.GetObjectSignature(profiles.NewContainerProfileAdapter(cp))
	if err != nil {
		t.Fatalf("get signature: %v", err)
	}
	id, err := signerIdentity(sig)
	if err != nil {
		t.Fatalf("signer identity: %v", err)
	}
	return id
}

// baseSpec is a vendor default: execs/opens, no ingress (cp-redis.yaml shape).
func baseSpec() v1beta1.ContainerProfileSpec {
	return v1beta1.ContainerProfileSpec{
		Architectures: []string{"amd64"},
		Execs:         []v1beta1.ExecCalls{{Path: "/opt/bitnami/redis/bin/redis-server", Args: []string{"redis-server"}}},
		Opens:         []v1beta1.OpenCalls{{Path: "/data/dump.rdb", Flags: []string{"O_RDWR"}}},
	}
}

// admissionSpec is the "allowlist a client later" ingress fragment (DEMO.md §5).
func admissionSpec() v1beta1.ContainerProfileSpec {
	port := int32(6379)
	return v1beta1.ContainerProfileSpec{
		Ingress: []v1beta1.NetworkNeighbor{{
			Identifier:        "allowed-client",
			Type:              "internal",
			PodSelector:       &metav1.LabelSelector{MatchLabels: map[string]string{"app": "redis-client"}},
			NamespaceSelector: &metav1.LabelSelector{MatchLabels: map[string]string{"kubernetes.io/metadata.name": "redis"}},
			Ports:             []v1beta1.NetworkPort{{Name: "TCP-6379", Port: &port, Protocol: "TCP"}},
		}},
	}
}

func redisPolicy(vendorID, operatorID string) TrustPolicy {
	return TrustPolicy{Classes: map[FragmentClass]ClassPolicy{
		ClassBase:      {Signers: []string{vendorID}, AllowedSpecPaths: []string{"architectures", "capabilities", "execs", "opens", "syscalls", "rulePolicies", "endpoints", "seccompProfile", "imageID", "imageTag", "identifiedCallStacks", "labelSelector"}},
		ClassAdmission: {Signers: []string{operatorID}, AllowedSpecPaths: []string{"ingress", "egress"}},
	}}
}

func TestAssembleAndVerify_HappyPath(t *testing.T) {
	vendor, operator := genKey(t), genKey(t)
	base := fragment(t, "redis", "base", baseSpec(), vendor)
	adm := fragment(t, "redis-ingress-client", "admission", admissionSpec(), operator)
	policy := redisPolicy(signerIDOf(t, base), signerIDOf(t, adm))

	composite, manifest, err := AssembleAndVerify("redis", "redis", []*v1beta1.ContainerProfile{base, adm}, policy)
	if err != nil {
		t.Fatalf("AssembleAndVerify: %v", err)
	}
	// Composite carries the base's execs AND the admission's ingress.
	if len(composite.Spec.Execs) != 1 || composite.Spec.Execs[0].Path != "/opt/bitnami/redis/bin/redis-server" {
		t.Errorf("composite missing base execs: %+v", composite.Spec.Execs)
	}
	if len(composite.Spec.Ingress) != 1 || composite.Spec.Ingress[0].Identifier != "allowed-client" {
		t.Errorf("composite missing admission ingress: %+v", composite.Spec.Ingress)
	}
	if len(manifest.Leaves) != 2 {
		t.Fatalf("manifest has %d leaves; want 2", len(manifest.Leaves))
	}
	if err := VerifyManifestRoot(manifest); err != nil {
		t.Errorf("manifest root: %v", err)
	}
	// Round-trip the manifest from the composite annotation.
	got, err := ManifestFromComposite(composite)
	if err != nil {
		t.Fatalf("ManifestFromComposite: %v", err)
	}
	if got.Root != manifest.Root {
		t.Errorf("round-tripped root %s != %s", got.Root, manifest.Root)
	}
	// The composite is NOT signed on-cluster: node-agent only verifies fragments.
	// It is verified by construction and carries the assembled spec directly.
}

func TestAssembleAndVerify_OrderIndependent(t *testing.T) {
	vendor, operator := genKey(t), genKey(t)
	base := fragment(t, "redis", "base", baseSpec(), vendor)
	adm := fragment(t, "redis-ingress-client", "admission", admissionSpec(), operator)
	policy := redisPolicy(signerIDOf(t, base), signerIDOf(t, adm))

	_, m1, err := AssembleAndVerify("redis", "redis", []*v1beta1.ContainerProfile{base, adm}, policy)
	if err != nil {
		t.Fatal(err)
	}
	_, m2, err := AssembleAndVerify("redis", "redis", []*v1beta1.ContainerProfile{adm, base}, policy)
	if err != nil {
		t.Fatal(err)
	}
	if m1.Root != m2.Root {
		t.Errorf("root depends on input order: %s vs %s", m1.Root, m2.Root)
	}
}

func TestAssembleAndVerify_Tampered(t *testing.T) {
	vendor, operator := genKey(t), genKey(t)
	base := fragment(t, "redis", "base", baseSpec(), vendor)
	adm := fragment(t, "redis-ingress-client", "admission", admissionSpec(), operator)
	policy := redisPolicy(signerIDOf(t, base), signerIDOf(t, adm))

	// Tamper the base fragment's spec after signing.
	base.Spec.Execs[0].Path = "/bin/evil"

	_, _, err := AssembleAndVerify("redis", "redis", []*v1beta1.ContainerProfile{base, adm}, policy)
	if !errors.Is(err, ErrFragmentTampered) {
		t.Errorf("want ErrFragmentTampered, got %v", err)
	}
}

func TestAssembleAndVerify_UntrustedSigner(t *testing.T) {
	vendor, operator, attacker := genKey(t), genKey(t), genKey(t)
	base := fragment(t, "redis", "base", baseSpec(), vendor)
	// Policy trusts the operator for admission fragments.
	operatorID := signerIDOf(t, fragment(t, "op-probe", "admission", admissionSpec(), operator))
	policy := redisPolicy(signerIDOf(t, base), operatorID)
	// But the admission fragment is signed by an attacker key not in the policy.
	adm := fragment(t, "redis-ingress-client", "admission", admissionSpec(), attacker)

	_, _, err := AssembleAndVerify("redis", "redis", []*v1beta1.ContainerProfile{base, adm}, policy)
	if !errors.Is(err, ErrSignerNotTrusted) {
		t.Errorf("want ErrSignerNotTrusted, got %v", err)
	}
}

func TestAssembleAndVerify_ClassConfinement(t *testing.T) {
	vendor, operator := genKey(t), genKey(t)
	base := fragment(t, "redis", "base", baseSpec(), vendor)
	// An admission-class fragment that illegally sets execs (server-side code),
	// signed by the trusted operator key — must still be rejected on path.
	badSpec := admissionSpec()
	badSpec.Execs = []v1beta1.ExecCalls{{Path: "/bin/backdoor", Args: []string{"backdoor"}}}
	adm := fragment(t, "redis-ingress-client", "admission", badSpec, operator)
	policy := redisPolicy(signerIDOf(t, base), signerIDOf(t, adm))

	_, _, err := AssembleAndVerify("redis", "redis", []*v1beta1.ContainerProfile{base, adm}, policy)
	if !errors.Is(err, ErrPathNotAllowed) {
		t.Errorf("want ErrPathNotAllowed, got %v", err)
	}
}

func TestAssembleAndVerify_Unsigned(t *testing.T) {
	vendor := genKey(t)
	base := fragment(t, "redis", "base", baseSpec(), vendor)
	// Unsigned admission fragment.
	adm := &v1beta1.ContainerProfile{
		ObjectMeta: metav1.ObjectMeta{Name: "redis-ingress-client", Namespace: "redis",
			Labels: map[string]string{LabelBundle: "redis", LabelFragmentClass: "admission"}},
		Spec: admissionSpec(),
	}
	policy := redisPolicy(signerIDOf(t, base), "unused")

	_, _, err := AssembleAndVerify("redis", "redis", []*v1beta1.ContainerProfile{base, adm}, policy)
	if !errors.Is(err, ErrFragmentUnsigned) {
		t.Errorf("want ErrFragmentUnsigned, got %v", err)
	}
}

// efrag signs a fragment WITH embedded content — the vendor-artifact flow.
func efrag(t *testing.T, name, class string, spec v1beta1.ContainerProfileSpec, key *ecdsa.PrivateKey) *v1beta1.ContainerProfile {
	t.Helper()
	cp := &v1beta1.ContainerProfile{
		ObjectMeta: metav1.ObjectMeta{
			Name:      name,
			Namespace: "redis",
			Labels: map[string]string{
				LabelBundle:        "redis",
				LabelFragmentClass: class,
			},
		},
		Spec: spec,
	}
	if err := signature.SignObject(profiles.NewContainerProfileAdapter(cp), signature.WithPrivateKey(key), signature.WithEmbedContent(true)); err != nil {
		t.Fatalf("sign %s: %v", name, err)
	}
	return cp
}

// TestAssembleAndVerify_EmbeddedContent_SurvivesStoredSpecDrift pins the
// vendor-artifact chain: the server may normalise the STORED spec arbitrarily;
// verification + assembly bind the embedded signed content.
func TestAssembleAndVerify_EmbeddedContent_SurvivesStoredSpecDrift(t *testing.T) {
	vendor, operator := genKey(t), genKey(t)
	base := efrag(t, "redis", "base", baseSpec(), vendor)
	adm := efrag(t, "redis-ingress-client", "admission", admissionSpec(), operator)
	policy := redisPolicy(signerIDOf(t, base), signerIDOf(t, adm))

	// simulate server-side deflate: stored spec drifts AND is even maliciously
	// altered — both are irrelevant, the embedded content is the truth
	base.Spec.Execs = []v1beta1.ExecCalls{{Path: "/bin/evil-not-signed"}}
	adm.Spec.Ingress = nil

	composite, manifest, err := AssembleAndVerify("redis", "redis", []*v1beta1.ContainerProfile{base, adm}, policy)
	if err != nil {
		t.Fatalf("AssembleAndVerify must bind embedded content: %v", err)
	}
	if len(composite.Spec.Execs) != 1 || composite.Spec.Execs[0].Path != "/opt/bitnami/redis/bin/redis-server" {
		t.Errorf("composite must contain the SIGNED exec, got %+v", composite.Spec.Execs)
	}
	if len(composite.Spec.Ingress) != 1 || composite.Spec.Ingress[0].Identifier != "allowed-client" {
		t.Errorf("composite must contain the SIGNED ingress, got %+v", composite.Spec.Ingress)
	}
	if err := VerifyManifestRoot(manifest); err != nil {
		t.Error(err)
	}
}

// TestAssembleAndVerify_EmbeddedContent_StoredLabelFlipIgnored: an attacker
// flipping the STORED class label cannot escalate — class comes from the
// signed embedded labels.
func TestAssembleAndVerify_EmbeddedContent_StoredLabelFlipIgnored(t *testing.T) {
	vendor, operator := genKey(t), genKey(t)
	base := efrag(t, "redis", "base", baseSpec(), vendor)
	// admission fragment signed with class=admission — attacker flips the
	// STORED label to base (whose policy would allow execs)
	adm := efrag(t, "redis-ingress-client", "admission", admissionSpec(), operator)
	adm.Labels[LabelFragmentClass] = "base"
	policy := redisPolicy(signerIDOf(t, base), signerIDOf(t, adm))

	_, m, err := AssembleAndVerify("redis", "redis", []*v1beta1.ContainerProfile{base, adm}, policy)
	if err != nil {
		t.Fatalf("assembly: %v", err)
	}
	for _, l := range m.Leaves {
		if l.Name == "redis-ingress-client" && l.Class != ClassAdmission {
			t.Errorf("class must come from the signed content, got %q", l.Class)
		}
	}
}

// TestAssembleAndVerify_EmbeddedContent_ForeignBundleRejected: the signed
// bundle label is authoritative — a fragment signed for another bundle cannot
// be pulled in by relabeling the stored object.
func TestAssembleAndVerify_EmbeddedContent_ForeignBundleRejected(t *testing.T) {
	vendor, operator := genKey(t), genKey(t)
	base := efrag(t, "redis", "base", baseSpec(), vendor)
	foreign := &v1beta1.ContainerProfile{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "other-frag",
			Namespace: "redis",
			Labels: map[string]string{
				LabelBundle:        "other",
				LabelFragmentClass: "admission",
			},
		},
		Spec: admissionSpec(),
	}
	if err := signature.SignObject(profiles.NewContainerProfileAdapter(foreign), signature.WithPrivateKey(operator), signature.WithEmbedContent(true)); err != nil {
		t.Fatal(err)
	}
	// attacker relabels the STORED object into the redis bundle
	foreign.Labels[LabelBundle] = "redis"
	policy := redisPolicy(signerIDOf(t, base), signerIDOf(t, foreign))

	_, _, err := AssembleAndVerify("redis", "redis", []*v1beta1.ContainerProfile{base, foreign}, policy)
	if err == nil {
		t.Fatal("a fragment signed for another bundle must be rejected")
	}
}

// TestSignerIdentity_IgnoresSpoofableOIDCAnnotations pins that the signer
// identity is the public-key fingerprint, NOT the attacker-controlled
// identity/issuer annotations — else a trust-policy signer bypass (V1/C3).
func TestSignerIdentity_IgnoresSpoofableOIDCAnnotations(t *testing.T) {
	attacker := genKey(t)
	cp := fragment(t, "redis", "base", baseSpec(), attacker)
	// attacker stamps a trusted vendor's OIDC identity on the annotations
	cp.Annotations[signature.AnnotationIssuer] = "https://accounts.google.com"
	cp.Annotations[signature.AnnotationIdentity] = "trusted-vendor@example.com"

	id, err := SignerID(cp)
	if err != nil {
		t.Fatal(err)
	}
	if id == "oidc:https://accounts.google.com#trusted-vendor@example.com" {
		t.Fatal("signer identity trusted spoofable OIDC annotations — trust bypass")
	}
	if id[:4] != "key:" {
		t.Errorf("signer identity must be a public-key fingerprint, got %q", id)
	}
}

// TestSeccompConfinement_EmptyDefaultAction: a seccomp payload with empty
// DefaultAction must still confine to its class (V3).
func TestSeccompConfinement_EmptyDefaultAction(t *testing.T) {
	vendor, operator := genKey(t), genKey(t)
	base := fragment(t, "redis", "base", baseSpec(), vendor)
	// admission fragment that smuggles seccomp content with empty DefaultAction
	badSpec := admissionSpec()
	badSpec.SeccompProfile.Spec.Architectures = []v1beta1.Arch{"amd64"}
	adm := fragment(t, "redis-ingress-client", "admission", badSpec, operator)
	policy := redisPolicy(signerIDOf(t, base), signerIDOf(t, adm))

	_, _, err := AssembleAndVerify("redis", "redis", []*v1beta1.ContainerProfile{base, adm}, policy)
	if !errors.Is(err, ErrPathNotAllowed) {
		t.Errorf("seccomp with empty DefaultAction must still be class-confined; got %v", err)
	}
}
