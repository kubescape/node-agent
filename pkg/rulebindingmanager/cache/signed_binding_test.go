//go:build experimental_signing

package cache

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"reflect"
	"testing"

	"github.com/kubescape/k8s-interface/k8sinterface"
	"github.com/kubescape/node-agent/mocks"
	typesv1 "github.com/kubescape/node-agent/pkg/rulebindingmanager/types/v1"
	rulemanagertypesv1 "github.com/kubescape/node-agent/pkg/rulemanager/types/v1"
	"github.com/kubescape/node-agent/pkg/signature"
	"github.com/kubescape/node-agent/pkg/signature/bundle"
	"github.com/kubescape/node-agent/pkg/signature/profiles"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	k8sfake "k8s.io/client-go/kubernetes/fake"
)

const signedBindingPodID = "default/nginx-77b4fdf86c-hp4x5"

func bindingTestKey(t *testing.T) *ecdsa.PrivateKey {
	t.Helper()
	k, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("gen key: %v", err)
	}
	return k
}

func bindingTestCache(t *testing.T) *RBCache {
	t.Helper()
	defer func() { mocks.NAMESPACE = "" }()

	k8sClient := k8sinterface.NewKubernetesApiMock()
	var r []runtime.Object
	mocks.NAMESPACE = "default"
	r = append(r, &corev1.Namespace{ObjectMeta: metav1.ObjectMeta{Name: mocks.NAMESPACE, Labels: map[string]string{"app": mocks.NAMESPACE}}})
	r = append(r, mocks.GetRuntime(mocks.TestKindPod, mocks.TestNginx))
	k8sClient.KubernetesClient = k8sfake.NewClientset(r...)

	c := NewCacheMock("")
	c.k8sClient = k8sClient
	return c
}

func bindingFor(name, class string) *typesv1.RuntimeAlertRuleBinding {
	labels := map[string]string{}
	if class != "" {
		labels[bundle.LabelFragmentClass] = class
	}
	return &typesv1.RuntimeAlertRuleBinding{
		TypeMeta: metav1.TypeMeta{APIVersion: "kubescape.io/v1", Kind: "RuntimeRuleAlertBinding"},
		ObjectMeta: metav1.ObjectMeta{
			Name:   name,
			Labels: labels,
		},
		Spec: typesv1.RuntimeAlertRuleBindingSpec{
			Rules: []typesv1.RuntimeAlertRuleBindingRule{{RuleID: "R0001"}},
		},
	}
}

func signBinding(t *testing.T, b *typesv1.RuntimeAlertRuleBinding, key *ecdsa.PrivateKey) *typesv1.RuntimeAlertRuleBinding {
	t.Helper()
	if err := signature.SignObject(profiles.NewRuleBindingAdapter(b), signature.WithPrivateKey(key)); err != nil {
		t.Fatalf("sign %s: %v", b.Name, err)
	}
	return b
}

func policyTrusting(t *testing.T, b *typesv1.RuntimeAlertRuleBinding) *bundle.TrustPolicy {
	t.Helper()
	signer, err := bundle.BindingSignerID(b)
	if err != nil {
		t.Fatalf("signer identity: %v", err)
	}
	return &bundle.TrustPolicy{BindingClasses: map[bundle.FragmentClass]bundle.BindingClassPolicy{
		bundle.ClassOverlay: {Signers: []string{signer}},
	}}
}

func TestRBCache_BindingSigningEnabledFlag(t *testing.T) {
	c := NewCacheMock("")
	if c.bindingSigningEnabled() {
		t.Error("a cache with no trust policy must report binding signing disabled")
	}
	c.SetTrustPolicy(nil)
	if c.bindingSigningEnabled() {
		t.Error("a nil trust policy must report binding signing disabled")
	}
	c.SetTrustPolicy(&bundle.TrustPolicy{RuleClasses: map[bundle.RuleClass]bundle.RuleClassPolicy{bundle.RuleClassBase: {}}})
	if c.bindingSigningEnabled() {
		t.Error("a policy with only ruleClasses must report binding signing disabled")
	}
	c.SetTrustPolicy(&bundle.TrustPolicy{BindingClasses: map[bundle.FragmentClass]bundle.BindingClassPolicy{bundle.ClassOverlay: {}}})
	if !c.bindingSigningEnabled() {
		t.Error("a policy with bindingClasses must report binding signing enabled")
	}
}

func TestRBCache_SignedBindingAdmitted(t *testing.T) {
	key := bindingTestKey(t)
	b := signBinding(t, bindingFor("rb-signed", string(bundle.ClassOverlay)), key)

	c := bindingTestCache(t)
	c.SetTrustPolicy(policyTrusting(t, b))
	c.addRuleBinding(b)

	rbName := uniqueName(b)
	if !c.rbNameToRB.Has(rbName) {
		t.Fatal("a validly signed binding by a trusted signer must be added to the cache")
	}
	if !c.podToRBNames.Has(signedBindingPodID) {
		t.Fatalf("pod %s must be bound to the admitted binding", signedBindingPodID)
	}
	if got := c.ListRulesForPod("default", "nginx-77b4fdf86c-hp4x5"); len(got) != 1 || got[0].ID != "R0001" {
		t.Fatalf("ListRulesForPod = %+v, want the single bound rule R0001", got)
	}
}

func TestRBCache_TamperedBindingIsRefused(t *testing.T) {
	key := bindingTestKey(t)
	b := signBinding(t, bindingFor("rb-tampered", string(bundle.ClassOverlay)), key)
	policy := policyTrusting(t, b)

	b.Spec.Rules = nil

	c := bindingTestCache(t)
	c.SetTrustPolicy(policy)
	rbs := c.addRuleBinding(b)

	rbName := uniqueName(b)
	if c.rbNameToRB.Has(rbName) {
		t.Error("a binding whose spec was edited after signing must not enter the cache")
	}
	if c.rbNameToRules.Has(rbName) || c.rbNameToPods.Has(rbName) {
		t.Error("a refused binding must leave no rules or pod bookkeeping behind")
	}
	if c.podToRBNames.Has(signedBindingPodID) {
		t.Errorf("pod %s must not be bound to a refused binding", signedBindingPodID)
	}
	if len(rbs) != 0 {
		t.Errorf("a refused binding must notify nobody, got %d notifications", len(rbs))
	}
	if got := c.ListRulesForPod("default", "nginx-77b4fdf86c-hp4x5"); len(got) != 0 {
		t.Errorf("a refused binding must produce no rules for its pods, got %+v", got)
	}
}

func TestRBCache_UnsignedBindingIsRefused(t *testing.T) {
	key := bindingTestKey(t)
	trusted := signBinding(t, bindingFor("rb-trusted", string(bundle.ClassOverlay)), key)
	policy := policyTrusting(t, trusted)

	unsigned := bindingFor("rb-unsigned", string(bundle.ClassOverlay))

	c := bindingTestCache(t)
	c.SetTrustPolicy(policy)
	c.addRuleBinding(unsigned)

	if c.rbNameToRB.Has(uniqueName(unsigned)) {
		t.Error("an unsigned binding must not enter the cache when binding signing is enabled")
	}
	if c.podToRBNames.Has(signedBindingPodID) {
		t.Errorf("pod %s must not be bound to an unsigned binding", signedBindingPodID)
	}
	if got := c.ListRulesForPod("default", "nginx-77b4fdf86c-hp4x5"); len(got) != 0 {
		t.Errorf("an unsigned binding must produce no rules for its pods, got %+v", got)
	}
}

func TestRBCache_UntrustedSignerBindingIsRefused(t *testing.T) {
	vendor, attacker := bindingTestKey(t), bindingTestKey(t)
	trusted := signBinding(t, bindingFor("rb-trusted", string(bundle.ClassOverlay)), vendor)
	rogue := signBinding(t, bindingFor("rb-rogue", string(bundle.ClassOverlay)), attacker)

	c := bindingTestCache(t)
	c.SetTrustPolicy(policyTrusting(t, trusted))
	c.addRuleBinding(rogue)

	if c.rbNameToRB.Has(uniqueName(rogue)) {
		t.Error("a binding signed by an untrusted key must not enter the cache")
	}
	if c.podToRBNames.Has(signedBindingPodID) {
		t.Errorf("pod %s must not be bound to a binding from an untrusted signer", signedBindingPodID)
	}
}

func TestRBCache_ModifyToTamperedBindingUnbindsPods(t *testing.T) {
	key := bindingTestKey(t)
	b := signBinding(t, bindingFor("rb-modified", string(bundle.ClassOverlay)), key)
	policy := policyTrusting(t, b)

	c := bindingTestCache(t)
	c.SetTrustPolicy(policy)
	c.addRuleBinding(b)
	if !c.podToRBNames.Has(signedBindingPodID) {
		t.Fatalf("precondition: pod %s must be bound before the tampering update", signedBindingPodID)
	}

	tampered := *b
	tampered.Spec.Rules = []typesv1.RuntimeAlertRuleBindingRule{{RuleID: "R9999"}}
	c.modifiedRuleBinding(&tampered)

	if c.rbNameToRB.Has(uniqueName(&tampered)) {
		t.Error("an update that fails admission must not leave the binding in the cache")
	}
	if c.podToRBNames.Has(signedBindingPodID) {
		t.Errorf("pod %s must be unbound after a refused update", signedBindingPodID)
	}
	if got := c.ListRulesForPod("default", "nginx-77b4fdf86c-hp4x5"); len(got) != 0 {
		t.Errorf("a refused update must produce no rules for its pods, got %+v", got)
	}
}

func TestRBCache_SigningDisabledAddsBindingUnchanged(t *testing.T) {
	key := bindingTestKey(t)
	rbName := ""

	snapshot := func(c *RBCache) (typesv1.RuntimeAlertRuleBinding, []rulemanagertypesv1.Rule, []string, []rulemanagertypesv1.Rule) {
		rb := c.rbNameToRB.Get(rbName)
		rules := c.rbNameToRules.Get(rbName)
		pods := c.rbNameToPods.Get(rbName).ToSlice()
		return rb, rules, pods, c.ListRulesForPod("default", "nginx-77b4fdf86c-hp4x5")
	}

	unsigned := bindingFor("rb-nopolicy", string(bundle.ClassOverlay))
	rbName = uniqueName(unsigned)

	base := bindingTestCache(t)
	base.addRuleBinding(unsigned)
	baseRB, baseRules, basePods, basePodRules := snapshot(base)

	if !base.rbNameToRB.Has(rbName) {
		t.Fatal("precondition: with no trust policy the unsigned binding must be cached")
	}

	for _, tc := range []struct {
		name   string
		policy *bundle.TrustPolicy
	}{
		{name: "nil policy", policy: nil},
		{name: "profile-only policy", policy: &bundle.TrustPolicy{Classes: map[bundle.FragmentClass]bundle.ClassPolicy{bundle.ClassBase: {Signers: []string{"key:none"}}}}},
		{name: "rules-only policy", policy: &bundle.TrustPolicy{RuleClasses: map[bundle.RuleClass]bundle.RuleClassPolicy{bundle.RuleClassBase: {Signers: []string{"key:none"}}}}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			c := bindingTestCache(t)
			c.SetTrustPolicy(tc.policy)
			c.addRuleBinding(bindingFor("rb-nopolicy", string(bundle.ClassOverlay)))

			gotRB, gotRules, gotPods, gotPodRules := snapshot(c)
			if !reflect.DeepEqual(gotRB, baseRB) {
				t.Errorf("cached binding differs from the no-policy path:\n got %+v\nwant %+v", gotRB, baseRB)
			}
			if !reflect.DeepEqual(gotRules, baseRules) {
				t.Errorf("cached rules differ from the no-policy path:\n got %+v\nwant %+v", gotRules, baseRules)
			}
			if !reflect.DeepEqual(gotPods, basePods) {
				t.Errorf("bound pods differ from the no-policy path:\n got %+v\nwant %+v", gotPods, basePods)
			}
			if !reflect.DeepEqual(gotPodRules, basePodRules) {
				t.Errorf("ListRulesForPod differs from the no-policy path:\n got %+v\nwant %+v", gotPodRules, basePodRules)
			}
		})
	}

	signed := signBinding(t, bindingFor("rb-nopolicy", string(bundle.ClassOverlay)), key)
	c := bindingTestCache(t)
	c.addRuleBinding(signed)
	if !c.rbNameToRB.Has(rbName) {
		t.Error("with binding signing disabled a signed binding must be cached exactly like any other")
	}
}

func TestRBCache_EmbeddedBindingUsesAuthenticatedSpec(t *testing.T) {
	for _, field := range []string{"rules", "pod selector", "namespace selector"} {
		t.Run(field, func(t *testing.T) {
			b := bindingFor("rb-embedded", string(bundle.ClassOverlay))
			b.Spec.PodSelector = metav1.LabelSelector{MatchLabels: map[string]string{"app": "nginx"}}
			b.Spec.NamespaceSelector = metav1.LabelSelector{MatchLabels: map[string]string{"app": "default"}}
			want := b.Spec
			if err := signature.SignObject(profiles.NewRuleBindingAdapter(b), signature.WithPrivateKey(bindingTestKey(t)), signature.WithEmbedContent(true)); err != nil {
				t.Fatal(err)
			}
			policy := policyTrusting(t, b)
			switch field {
			case "rules":
				b.Spec.Rules = nil
			case "pod selector":
				b.Spec.PodSelector = metav1.LabelSelector{MatchLabels: map[string]string{"app": "attacker"}}
			case "namespace selector":
				b.Spec.NamespaceSelector = metav1.LabelSelector{MatchLabels: map[string]string{"app": "attacker"}}
			}
			stored := b.Spec
			c := bindingTestCache(t)
			c.SetTrustPolicy(policy)
			c.addRuleBinding(b)
			if got := c.rbNameToRB.Get(uniqueName(b)).Spec; !reflect.DeepEqual(got, want) {
				t.Errorf("cached spec = %+v, want authenticated %+v", got, want)
			}
			if !reflect.DeepEqual(b.Spec, stored) {
				t.Error("admission mutated the informer object")
			}
			assertRules := func() {
				t.Helper()
				if got := c.ListRulesForPod("default", "nginx-77b4fdf86c-hp4x5"); len(got) != 1 || got[0].ID != "R0001" {
					t.Fatalf("rules = %+v, want authenticated R0001", got)
				}
			}
			assertRules()
			c.RefreshRuleBindingsRules()
			assertRules()
			c.deletePod(signedBindingPodID)
			pod, err := c.k8sClient.GetKubernetesClient().CoreV1().Pods("default").Get(context.Background(), "nginx-77b4fdf86c-hp4x5", metav1.GetOptions{})
			if err != nil {
				t.Fatal(err)
			}
			c.addPod(context.Background(), pod)
			if !c.podToRBNames.Has(signedBindingPodID) {
				t.Fatal("later pod admission must use authenticated selectors")
			}
			c.rulesForPod.Purge()
			assertRules()
		})
	}
}
