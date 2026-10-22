//go:build experimental_signing

package bundle

import (
	"crypto/ecdsa"
	"errors"
	"testing"

	rulebindingtypesv1 "github.com/kubescape/node-agent/pkg/rulebindingmanager/types/v1"
	"github.com/kubescape/node-agent/pkg/signature"
	"github.com/kubescape/node-agent/pkg/signature/profiles"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

func bindingObject(name, namespace, class string, ruleIDs []string) *rulebindingtypesv1.RuntimeAlertRuleBinding {
	labels := map[string]string{}
	if class != "" {
		labels[LabelFragmentClass] = class
	}
	rules := make([]rulebindingtypesv1.RuntimeAlertRuleBindingRule, 0, len(ruleIDs))
	for _, id := range ruleIDs {
		rules = append(rules, rulebindingtypesv1.RuntimeAlertRuleBindingRule{RuleID: id})
	}
	return &rulebindingtypesv1.RuntimeAlertRuleBinding{
		TypeMeta: metav1.TypeMeta{APIVersion: "kubescape.io/v1", Kind: "RuntimeRuleAlertBinding"},
		ObjectMeta: metav1.ObjectMeta{
			Name:      name,
			Namespace: namespace,
			Labels:    labels,
		},
		Spec: rulebindingtypesv1.RuntimeAlertRuleBindingSpec{
			Rules:       rules,
			PodSelector: metav1.LabelSelector{MatchLabels: map[string]string{"app": "redis"}},
		},
	}
}

func signedBinding(t *testing.T, name, namespace, class string, ruleIDs []string, key *ecdsa.PrivateKey) *rulebindingtypesv1.RuntimeAlertRuleBinding {
	t.Helper()
	b := bindingObject(name, namespace, class, ruleIDs)
	if err := signature.SignObject(profiles.NewRuleBindingAdapter(b), signature.WithPrivateKey(key)); err != nil {
		t.Fatalf("sign %s: %v", name, err)
	}
	return b
}

func signedBindingEmbedded(t *testing.T, name, namespace, class string, ruleIDs []string, key *ecdsa.PrivateKey) *rulebindingtypesv1.RuntimeAlertRuleBinding {
	t.Helper()
	b := bindingObject(name, namespace, class, ruleIDs)
	if err := signature.SignObject(profiles.NewRuleBindingAdapter(b), signature.WithPrivateKey(key), signature.WithEmbedContent(true)); err != nil {
		t.Fatalf("sign %s: %v", name, err)
	}
	return b
}

func bindingSignerIDOf(t *testing.T, b *rulebindingtypesv1.RuntimeAlertRuleBinding) string {
	t.Helper()
	id, err := BindingSignerID(b)
	if err != nil {
		t.Fatalf("signer identity: %v", err)
	}
	return id
}

func bindingPolicy(class FragmentClass, signer string) TrustPolicy {
	return TrustPolicy{BindingClasses: map[FragmentClass]BindingClassPolicy{
		class: {Signers: []string{signer}},
	}}
}

func TestBindingSigningEnabled(t *testing.T) {
	if (TrustPolicy{}).BindingSigningEnabled() {
		t.Error("empty policy must report binding signing disabled")
	}
	profileOnly := TrustPolicy{Classes: map[FragmentClass]ClassPolicy{ClassBase: {}}}
	if profileOnly.BindingSigningEnabled() {
		t.Error("policy without bindingClasses must report binding signing disabled")
	}
	rulesOnly := TrustPolicy{RuleClasses: map[RuleClass]RuleClassPolicy{RuleClassBase: {}}}
	if rulesOnly.BindingSigningEnabled() {
		t.Error("policy with only ruleClasses must report binding signing disabled")
	}
	withBindings := TrustPolicy{BindingClasses: map[FragmentClass]BindingClassPolicy{ClassBase: {}}}
	if !withBindings.BindingSigningEnabled() {
		t.Error("policy with bindingClasses must report binding signing enabled")
	}
}

func TestAdmitBinding_HappyPath(t *testing.T) {
	key := genKey(t)
	b := signedBinding(t, "redis-binding", "redis", string(ClassOverlay), []string{"R0001"}, key)
	policy := bindingPolicy(ClassOverlay, bindingSignerIDOf(t, b))

	got, err := AdmitBinding(b, policy)
	if err != nil {
		t.Fatalf("AdmitBinding: %v", err)
	}
	if got.Class != ClassOverlay {
		t.Errorf("class = %q, want %q", got.Class, ClassOverlay)
	}
	if got.Signer != bindingSignerIDOf(t, b) {
		t.Errorf("signer = %q", got.Signer)
	}
}

func TestAdmitBinding_Unsigned(t *testing.T) {
	b := bindingObject("redis-binding", "redis", string(ClassOverlay), []string{"R0001"})
	policy := bindingPolicy(ClassOverlay, "key:whatever")

	_, err := AdmitBinding(b, policy)
	if !errors.Is(err, ErrFragmentUnsigned) {
		t.Fatalf("want ErrFragmentUnsigned, got %v", err)
	}
}

func TestAdmitBinding_Tampered(t *testing.T) {
	key := genKey(t)
	b := signedBinding(t, "redis-binding", "redis", string(ClassOverlay), []string{"R0001"}, key)
	policy := bindingPolicy(ClassOverlay, bindingSignerIDOf(t, b))
	if _, err := AdmitBinding(b, policy); err != nil {
		t.Fatalf("precondition: binding must admit before tampering: %v", err)
	}

	b.Spec.PodSelector = metav1.LabelSelector{MatchLabels: map[string]string{"app": "nothing-matches-this"}}

	_, err := AdmitBinding(b, policy)
	if !errors.Is(err, ErrFragmentTampered) {
		t.Fatalf("want ErrFragmentTampered after unbinding every pod, got %v", err)
	}
}

func TestAdmitBinding_TamperedRuleListEmptied(t *testing.T) {
	key := genKey(t)
	b := signedBinding(t, "redis-binding", "redis", string(ClassOverlay), []string{"R0001", "R0002"}, key)
	policy := bindingPolicy(ClassOverlay, bindingSignerIDOf(t, b))
	if _, err := AdmitBinding(b, policy); err != nil {
		t.Fatalf("precondition: binding must admit before tampering: %v", err)
	}

	b.Spec.Rules = nil

	_, err := AdmitBinding(b, policy)
	if !errors.Is(err, ErrFragmentTampered) {
		t.Fatalf("want ErrFragmentTampered after stripping every bound rule, got %v", err)
	}
}

func TestAdmitBinding_UntrustedSigner(t *testing.T) {
	vendor, attacker := genKey(t), genKey(t)
	trusted := signedBinding(t, "redis-binding", "redis", string(ClassOverlay), []string{"R0001"}, vendor)
	rogue := signedBinding(t, "redis-binding", "redis", string(ClassOverlay), []string{"R0001"}, attacker)
	policy := bindingPolicy(ClassOverlay, bindingSignerIDOf(t, trusted))

	_, err := AdmitBinding(rogue, policy)
	if !errors.Is(err, ErrSignerNotTrusted) {
		t.Fatalf("want ErrSignerNotTrusted, got %v", err)
	}
}

func TestAdmitBinding_ClassNotAllowed(t *testing.T) {
	key := genKey(t)
	b := signedBinding(t, "redis-binding", "redis", string(ClassOverlay), []string{"R0001"}, key)
	policy := bindingPolicy(ClassBase, bindingSignerIDOf(t, b))

	_, err := AdmitBinding(b, policy)
	if !errors.Is(err, ErrBindingClassNotAllowed) {
		t.Fatalf("want ErrBindingClassNotAllowed, got %v", err)
	}
}

func TestAdmitBinding_NoClassLabel(t *testing.T) {
	key := genKey(t)
	b := signedBinding(t, "unclassed-binding", "redis", "", []string{"R0001"}, key)
	policy := bindingPolicy(ClassOverlay, bindingSignerIDOf(t, b))

	_, err := AdmitBinding(b, policy)
	if !errors.Is(err, ErrNoClass) {
		t.Fatalf("want ErrNoClass, got %v", err)
	}
}

func TestAdmitBinding_NamespaceIsNotSigned(t *testing.T) {
	key := genKey(t)
	b := signedBinding(t, "redis-binding", "redis", string(ClassOverlay), []string{"R0001"}, key)
	policy := bindingPolicy(ClassOverlay, bindingSignerIDOf(t, b))

	for _, ns := range []string{"payments", "team-a", ""} {
		b.Namespace = ns

		got, err := AdmitBinding(b, policy)
		if err != nil {
			t.Fatalf("a signed binding must admit in any namespace (%q), got %v", ns, err)
		}
		if got.Class != ClassOverlay {
			t.Fatalf("installed in %q: class = %q, want %q", ns, got.Class, ClassOverlay)
		}
	}
}

func TestAdmitBinding_ClassComesFromSignedLabels(t *testing.T) {
	key := genKey(t)
	b := signedBindingEmbedded(t, "redis-binding", "redis", string(ClassOverlay), []string{"R0001"}, key)
	policy := bindingPolicy(ClassOverlay, bindingSignerIDOf(t, b))

	if _, present, _ := signature.EmbeddedContent(profiles.NewRuleBindingAdapter(b)); !present {
		t.Fatal("binding must carry embedded content for this test to mean anything")
	}

	b.Labels[LabelFragmentClass] = string(ClassBase)

	got, err := AdmitBinding(b, policy)
	if err != nil {
		t.Fatalf("AdmitBinding: %v", err)
	}
	if got.Class != ClassOverlay {
		t.Fatalf("class = %q, want the SIGNED class %q", got.Class, ClassOverlay)
	}
}

func TestAdmitBinding_Nil(t *testing.T) {
	_, err := AdmitBinding(nil, bindingPolicy(ClassOverlay, "key:whatever"))
	if err == nil {
		t.Fatal("nil binding must not admit")
	}
}

func TestBindingClassPolicy_AllowsSigner(t *testing.T) {
	p := BindingClassPolicy{Signers: []string{"key:a"}}
	if !p.allowsSigner("key:a") || p.allowsSigner("key:b") {
		t.Error("allowsSigner mismatch")
	}
	w := BindingClassPolicy{Signers: []string{"*"}}
	if !w.allowsSigner("*") || w.allowsSigner("key:a") {
		t.Error("signers must be matched literally, no wildcard")
	}
}
