//go:build experimental_signing

package ruleswatcher

import (
	"context"
	"testing"

	"github.com/kubescape/node-agent/pkg/rulemanager/rulecreator"
	typesv1 "github.com/kubescape/node-agent/pkg/rulemanager/types/v1"
	"github.com/kubescape/node-agent/pkg/signature/bundle"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/runtime/schema"
	dynamicfake "k8s.io/client-go/dynamic/fake"
)

func mutableRulesClient(t *testing.T, objs ...*typesv1.Rules) *fakeK8sClient {
	t.Helper()
	items := make([]runtime.Object, 0, len(objs))
	for _, o := range objs {
		u, err := runtime.DefaultUnstructuredConverter.ToUnstructured(o)
		if err != nil {
			t.Fatalf("to unstructured: %v", err)
		}
		items = append(items, &unstructured.Unstructured{Object: u})
	}
	listKinds := map[schema.GroupVersionResource]string{typesv1.RuleGvr: "RuleList"}
	// Seed the explicit GVR: the fake client's pluralizer maps Kind Rules to
	// "ruleses", whereas the CRD resource is "rules".
	dyn := dynamicfake.NewSimpleDynamicClientWithCustomListKinds(runtime.NewScheme(), listKinds)
	for _, item := range items {
		obj := item.(*unstructured.Unstructured)
		if err := dyn.Tracker().Create(typesv1.RuleGvr, obj, obj.GetNamespace()); err != nil {
			t.Fatalf("seed rules: %v", err)
		}
	}
	return &fakeK8sClient{dyn: dyn}
}

func applyRules(t *testing.T, c *fakeK8sClient, r *typesv1.Rules) {
	t.Helper()
	u, err := runtime.DefaultUnstructuredConverter.ToUnstructured(r)
	if err != nil {
		t.Fatalf("to unstructured: %v", err)
	}
	_, err = c.dyn.Resource(typesv1.RuleGvr).Namespace(r.Namespace).
		Create(context.Background(), &unstructured.Unstructured{Object: u}, metav1.CreateOptions{})
	if err != nil {
		t.Fatalf("create %s: %v", r.Name, err)
	}
}

func deleteRules(t *testing.T, c *fakeK8sClient, namespace, name string) {
	t.Helper()
	if err := c.dyn.Resource(typesv1.RuleGvr).Namespace(namespace).
		Delete(context.Background(), name, metav1.DeleteOptions{}); err != nil {
		t.Fatalf("delete %s: %v", name, err)
	}
}

func trustPolicyFor(signer string) *bundle.TrustPolicy {
	return &bundle.TrustPolicy{RuleClasses: map[bundle.RuleClass]bundle.RuleClassPolicy{
		bundle.RuleClassBase: {Signers: []string{signer}, AllowedRuleIDs: []string{"*"}},
	}}
}

func ruleIDs(rules []typesv1.Rule) map[string]bool {
	out := map[string]bool{}
	for _, r := range rules {
		out[r.ID] = true
	}
	return out
}

// entlein/node-agent#48: Test_45 drives the ruleset to zero and back, and
// asserts detection returns without restarting the agent. Every other test in
// this package is single-shot, so nothing covered the sequence itself. This
// walks it and names which half of the chain loses the rules.
func TestRecovery_RulesetReturnsAfterAZeroAdmittedInterval(t *testing.T) {
	baseline := rulesObj("baseline", "kubescape", "", "", "R0001", "R0002")
	client := mutableRulesClient(t, baseline)
	creator := rulecreator.NewRuleCreator()
	w := NewRulesWatcher(client, creator, nil)

	sync := func(stage string) map[string]bool {
		t.Helper()
		if err := w.syncAllRulesFromCluster(context.Background()); err != nil {
			t.Fatalf("%s: sync: %v", stage, err)
		}
		return ruleIDs(creator.CreateAllRules())
	}

	before := sync("baseline present")
	if !before["R0001"] {
		t.Fatalf("baseline must load R0001, got %v", before)
	}

	deleteRules(t, client, "kubescape", "baseline")
	during := sync("zero rules")
	if len(during) != 0 {
		t.Fatalf("deleting every Rules object must empty the effective ruleset, got %v", during)
	}

	applyRules(t, client, rulesObj("baseline", "kubescape", "", "", "R0001", "R0002"))
	after := sync("baseline re-applied")
	if !after["R0001"] {
		t.Fatalf("re-applying the baseline must restore R0001 without a restart, got %v", after)
	}
	if len(after) != len(before) {
		t.Errorf("recovered ruleset must match the original: before=%v after=%v", before, after)
	}
}

// The same sequence run repeatedly: a recovery that works once but degrades
// across cycles is the shape an accumulating cache would produce.
func TestRecovery_SurvivesRepeatedOutageCycles(t *testing.T) {
	client := mutableRulesClient(t, rulesObj("baseline", "kubescape", "", "", "R0001", "R0002"))
	creator := rulecreator.NewRuleCreator()
	w := NewRulesWatcher(client, creator, nil)

	for cycle := 1; cycle <= 3; cycle++ {
		if err := w.syncAllRulesFromCluster(context.Background()); err != nil {
			t.Fatalf("cycle %d: sync: %v", cycle, err)
		}
		if got := ruleIDs(creator.CreateAllRules()); !got["R0001"] {
			t.Fatalf("cycle %d: R0001 must be present before the outage, got %v", cycle, got)
		}

		deleteRules(t, client, "kubescape", "baseline")
		if err := w.syncAllRulesFromCluster(context.Background()); err != nil {
			t.Fatalf("cycle %d: sync during outage: %v", cycle, err)
		}
		if got := ruleIDs(creator.CreateAllRules()); len(got) != 0 {
			t.Fatalf("cycle %d: outage must empty the ruleset, got %v", cycle, got)
		}

		applyRules(t, client, rulesObj("baseline", "kubescape", "", "", "R0001", "R0002"))
		if err := w.syncAllRulesFromCluster(context.Background()); err != nil {
			t.Fatalf("cycle %d: sync after recovery: %v", cycle, err)
		}
		if got := ruleIDs(creator.CreateAllRules()); !got["R0001"] {
			t.Fatalf("cycle %d: R0001 must return, got %v", cycle, got)
		}
	}
}

// A signing outage is the shape Test_45 actually drives: the objects are still
// there, signing is on, and nothing is admitted. Recovery is re-admission, not
// re-creation, so the ruleset must come back when the policy accepts again.
func TestRecovery_RulesetReturnsAfterASigningOutage(t *testing.T) {
	key := testKey(t)
	signed := sign(t, rulesObj("baseline", "kubescape", "b1", "base", "R0001"), key)
	client := mutableRulesClient(t, signed)
	creator := rulecreator.NewRuleCreator()
	w := NewRulesWatcher(client, creator, nil)

	trusted := trustPolicyFor(signerOf(t, signed))
	w.SetTrustPolicy(trusted)
	if err := w.syncAllRulesFromCluster(context.Background()); err != nil {
		t.Fatalf("sync trusted: %v", err)
	}
	if got := ruleIDs(creator.CreateAllRules()); !got["R0001"] {
		t.Fatalf("a trusted fragment must be admitted, got %v", got)
	}

	w.SetTrustPolicy(trustPolicyFor("sha256:0000000000000000000000000000000000000000000000000000000000000000"))
	if err := w.syncAllRulesFromCluster(context.Background()); err != nil {
		t.Fatalf("sync untrusted: %v", err)
	}
	if got := ruleIDs(creator.CreateAllRules()); len(got) != 0 {
		t.Fatalf("a policy trusting nobody must admit nothing, got %v", got)
	}

	w.SetTrustPolicy(trusted)
	if err := w.syncAllRulesFromCluster(context.Background()); err != nil {
		t.Fatalf("sync re-trusted: %v", err)
	}
	if got := ruleIDs(creator.CreateAllRules()); !got["R0001"] {
		t.Fatalf("restoring the policy must re-admit the fragment without a restart, got %v", got)
	}
}
