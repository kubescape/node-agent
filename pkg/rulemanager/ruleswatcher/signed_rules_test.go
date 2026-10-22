//go:build experimental_signing

package ruleswatcher

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"strings"
	"testing"

	"github.com/kubescape/k8s-interface/k8sinterface"
	"github.com/kubescape/node-agent/pkg/rulemanager/rulecreator"
	typesv1 "github.com/kubescape/node-agent/pkg/rulemanager/types/v1"
	"github.com/kubescape/node-agent/pkg/signature"
	"github.com/kubescape/node-agent/pkg/signature/bundle"
	"github.com/kubescape/node-agent/pkg/signature/profiles"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/runtime/schema"
	"k8s.io/client-go/dynamic"
	dynamicfake "k8s.io/client-go/dynamic/fake"
	"k8s.io/client-go/kubernetes"
)

// fakeK8sClient serves a fixed set of Rules objects from a fake dynamic client.
type fakeK8sClient struct {
	dyn dynamic.Interface
}

func (f *fakeK8sClient) GetWorkload(string, string, string) (k8sinterface.IWorkload, error) {
	return nil, nil
}

func (f *fakeK8sClient) CalculateWorkloadParentRecursive(k8sinterface.IWorkload) (string, string, error) {
	return "", "", nil
}

func (f *fakeK8sClient) GetKubernetesClient() kubernetes.Interface { return nil }
func (f *fakeK8sClient) GetDynamicClient() dynamic.Interface       { return f.dyn }

func newFakeK8sClient(t *testing.T, objs ...*typesv1.Rules) *fakeK8sClient {
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
	return &fakeK8sClient{dyn: dynamicfake.NewSimpleDynamicClientWithCustomListKinds(runtime.NewScheme(), listKinds, items...)}
}

func testKey(t *testing.T) *ecdsa.PrivateKey {
	t.Helper()
	k, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("gen key: %v", err)
	}
	return k
}

// rulesObj builds a Rules fragment labelled exactly like a ContainerProfile
// fragment: signature.kubescape.io/bundle + signature.kubescape.io/fragment-class.
func rulesObj(name, namespace, bundleName, class string, ruleIDs ...string) *typesv1.Rules {
	rules := make([]typesv1.Rule, 0, len(ruleIDs))
	for _, id := range ruleIDs {
		rules = append(rules, typesv1.Rule{Enabled: true, ID: id, Name: "rule-" + id})
	}
	labels := map[string]string{}
	if class != "" {
		labels[bundle.LabelFragmentClass] = class
	}
	if bundleName != "" {
		labels[bundle.LabelBundle] = bundleName
	}
	return &typesv1.Rules{
		TypeMeta:   metav1.TypeMeta{APIVersion: "kubescape.io/v1", Kind: "Rule"},
		ObjectMeta: metav1.ObjectMeta{Name: name, Namespace: namespace, Labels: labels},
		Spec:       typesv1.RulesSpec{Rules: rules},
	}
}

func sign(t *testing.T, r *typesv1.Rules, key *ecdsa.PrivateKey) *typesv1.Rules {
	t.Helper()
	if err := signature.SignObject(profiles.NewRulesAdapter(r), signature.WithPrivateKey(key)); err != nil {
		t.Fatalf("sign %s: %v", r.Name, err)
	}
	return r
}

func signerOf(t *testing.T, r *typesv1.Rules) string {
	t.Helper()
	id, err := bundle.RulesSignerID(r)
	if err != nil {
		t.Fatalf("signer id: %v", err)
	}
	return id
}

// Rule signing disabled is the pre-existing behaviour: every enabled rule from
// every Rules object in every namespace is loaded, signed or not, and carries
// cluster-wide provenance so downstream bundle scoping is a no-op.
func TestSyncAllRulesFromCluster_SigningDisabled(t *testing.T) {
	unsigned := rulesObj("baseline", "kubescape", "", "", "R0001", "R0002")
	rogue := rulesObj("rogue", "attacker", "", "", "R0003")

	creator := rulecreator.NewRuleCreator()
	w := NewRulesWatcher(newFakeK8sClient(t, unsigned, rogue), creator, nil)

	if w.ruleSigningEnabled() {
		t.Fatal("rule signing must be disabled without a trust policy")
	}
	if err := w.syncAllRulesFromCluster(context.Background()); err != nil {
		t.Fatalf("sync: %v", err)
	}

	all := creator.CreateAllRules()
	if len(all) != 3 {
		t.Fatalf("got %d rules, want 3 (unchanged pre-signing behaviour)", len(all))
	}
	for _, r := range all {
		if !r.ClusterWide || r.Bundle != "" {
			t.Errorf("rule %s: want cluster-wide/unbundled provenance, got clusterWide=%v bundle=%q", r.ID, r.ClusterWide, r.Bundle)
		}
	}
}

// A policy that only configures ContainerProfile fragment classes must not turn
// rule signing on.
func TestSetTrustPolicy_ProfileOnlyPolicyKeepsSigningDisabled(t *testing.T) {
	w := NewRulesWatcher(newFakeK8sClient(t), rulecreator.NewRuleCreator(), nil)
	w.SetTrustPolicy(&bundle.TrustPolicy{Classes: map[bundle.FragmentClass]bundle.ClassPolicy{bundle.ClassBase: {}}})
	if w.ruleSigningEnabled() {
		t.Fatal("a policy without ruleClasses must leave rule signing disabled")
	}
	w.SetTrustPolicy(nil)
	if w.ruleSigningEnabled() {
		t.Fatal("nil policy must leave rule signing disabled")
	}
}

// With rule signing enabled the watcher fails closed: an unsigned or
// untrusted Rules object is dropped whole, so an attacker who can create a
// Rules object in any namespace cannot override or disable a base rule.
func TestSyncAllRulesFromCluster_SigningEnabledFailsClosed(t *testing.T) {
	vendor, operator, attacker := testKey(t), testKey(t), testKey(t)

	baseline := sign(t, rulesObj("baseline", "kubescape", "", string(bundle.RuleClassBase), "R0001", "R0002"), vendor)
	overlay := sign(t, rulesObj("redis-tuning", "redis", "redis", string(bundle.RuleClassOverlay), "R0001"), operator)
	// Same shape as the real attack: a Rules object in an arbitrary namespace
	// that redefines R0001, signed with a key nobody trusts.
	rogueSigned := sign(t, rulesObj("rogue", "attacker", "", string(bundle.RuleClassBase), "R0001"), attacker)
	rogueUnsigned := rulesObj("rogue-unsigned", "attacker", "", string(bundle.RuleClassBase), "R0002")

	creator := rulecreator.NewRuleCreator()
	w := NewRulesWatcher(newFakeK8sClient(t, baseline, overlay, rogueSigned, rogueUnsigned), creator, nil)
	w.SetTrustPolicy(&bundle.TrustPolicy{RuleClasses: map[bundle.RuleClass]bundle.RuleClassPolicy{
		bundle.RuleClassBase:    {Signers: []string{signerOf(t, baseline)}, AllowedRuleIDs: []string{"*"}},
		bundle.RuleClassOverlay: {Signers: []string{signerOf(t, overlay)}, AllowedRuleIDs: []string{"R0001"}},
	}})
	if !w.ruleSigningEnabled() {
		t.Fatal("rule signing must be enabled with a ruleClasses policy")
	}

	if err := w.syncAllRulesFromCluster(context.Background()); err != nil {
		t.Fatalf("sync: %v", err)
	}

	all := creator.CreateAllRules()
	// 2 base rules + 1 bundle-scoped R0001; both rogue objects dropped.
	if len(all) != 3 {
		t.Fatalf("got %d rules, want 3: %+v", len(all), all)
	}
	var baseR1, overlayR1, r2 int
	for _, r := range all {
		if r.ID == "R0002" {
			r2++
		}
		if r.ID != "R0001" {
			continue
		}
		if r.ClusterWide {
			baseR1++
			if r.Bundle != "" {
				t.Errorf("base R0001 bundle = %q, want empty", r.Bundle)
			}
		} else {
			overlayR1++
			if r.Bundle != "redis" {
				t.Errorf("overlay R0001 bundle = %q, want redis", r.Bundle)
			}
		}
	}
	// The composite (bundle, ID) key in SyncRules is what lets both survive.
	if baseR1 != 1 || overlayR1 != 1 {
		t.Fatalf("want one base and one overlay R0001, got base=%d overlay=%d", baseR1, overlayR1)
	}
	// The rogue objects redefine R0001 (signed, untrusted) and R0002 (unsigned).
	// Exactly one of each surviving proves neither contributed anything: a rogue
	// R0001 would be a second base variant, a rogue R0002 a second R0002.
	if r2 != 1 {
		t.Fatalf("want exactly one R0002, got %d — a rogue fragment leaked", r2)
	}
}

// The bundle a rule is scoped by is the SIGNED one, and metadata.namespace has
// no say: the same signed overlay installed into two different namespaces yields
// the same bundle provenance.
func TestSyncAllRulesFromCluster_BundleProvenanceIsNamespaceIndependent(t *testing.T) {
	operator := testKey(t)
	overlay := sign(t, rulesObj("redis-tuning", "redis", "redis", string(bundle.RuleClassOverlay), "R0001"), operator)

	for _, ns := range []string{"redis", "team-a", "some-random-ns"} {
		// Same signed bytes, only the install namespace differs.
		installed := *overlay
		installed.ObjectMeta = *overlay.ObjectMeta.DeepCopy()
		installed.Namespace = ns

		creator := rulecreator.NewRuleCreator()
		w := NewRulesWatcher(newFakeK8sClient(t, &installed), creator, nil)
		w.SetTrustPolicy(&bundle.TrustPolicy{RuleClasses: map[bundle.RuleClass]bundle.RuleClassPolicy{
			bundle.RuleClassOverlay: {Signers: []string{signerOf(t, overlay)}, AllowedRuleIDs: []string{"*"}},
		}})
		if err := w.syncAllRulesFromCluster(context.Background()); err != nil {
			t.Fatalf("sync in %s: %v", ns, err)
		}

		all := creator.CreateAllRules()
		if len(all) != 1 {
			t.Fatalf("installed in %s: got %d rules, want 1", ns, len(all))
		}
		if all[0].Bundle != "redis" || all[0].ClusterWide {
			t.Fatalf("installed in %s: bundle=%q clusterWide=%v, want redis/false", ns, all[0].Bundle, all[0].ClusterWide)
		}
	}
}

// An overlay fragment carrying no bundle label cannot be scoped, so the whole
// fragment is dropped rather than applied to everything.
func TestSyncAllRulesFromCluster_OverlayWithoutBundleDropped(t *testing.T) {
	operator := testKey(t)
	bad := sign(t, rulesObj("bundleless", "redis", "", string(bundle.RuleClassOverlay), "R0001"), operator)

	creator := rulecreator.NewRuleCreator()
	w := NewRulesWatcher(newFakeK8sClient(t, bad), creator, nil)
	w.SetTrustPolicy(&bundle.TrustPolicy{RuleClasses: map[bundle.RuleClass]bundle.RuleClassPolicy{
		bundle.RuleClassOverlay: {Signers: []string{signerOf(t, bad)}, AllowedRuleIDs: []string{"*"}},
	}})

	if err := w.syncAllRulesFromCluster(context.Background()); err != nil {
		t.Fatalf("sync: %v", err)
	}
	if all := creator.CreateAllRules(); len(all) != 0 {
		t.Fatalf("got %d rules, want the whole fragment dropped: %+v", len(all), all)
	}
}

// A policy reload must change admission WITHOUT waiting for a Rules watch
// event: SetTrustPolicy + ResyncNow flips a previously loaded unsigned object
// to dropped within the same call.
func TestResyncNow_AppliesReloadedPolicyWithoutWatchEvent(t *testing.T) {
	vendor := testKey(t)
	signed := sign(t, rulesObj("baseline", "kubescape", "", string(bundle.RuleClassBase), "R0001"), vendor)
	unsigned := rulesObj("legacy", "other", "", "", "R0002")

	creator := rulecreator.NewRuleCreator()
	w := NewRulesWatcher(newFakeK8sClient(t, signed, unsigned), creator, nil)

	if err := w.syncAllRulesFromCluster(context.Background()); err != nil {
		t.Fatalf("sync: %v", err)
	}
	if got := len(creator.CreateAllRules()); got != 2 {
		t.Fatalf("signing off: got %d rules, want 2", got)
	}

	w.SetTrustPolicy(&bundle.TrustPolicy{RuleClasses: map[bundle.RuleClass]bundle.RuleClassPolicy{
		bundle.RuleClassBase: {Signers: []string{signerOf(t, signed)}, AllowedRuleIDs: []string{"*"}},
	}})
	w.ResyncNow(context.Background())

	all := creator.CreateAllRules()
	if len(all) != 1 || all[0].ID != "R0001" {
		t.Fatalf("after strict reload + resync: got %+v, want only the signed R0001", all)
	}

	w.SetTrustPolicy(nil)
	w.ResyncNow(context.Background())
	if got := len(creator.CreateAllRules()); got != 2 {
		t.Fatalf("after signing-off reload + resync: got %d rules, want 2", got)
	}
}

// An admitted embedded-content Rules object whose stored rules were edited
// after signing loads the SIGNED rules and warns once about the divergence.
func TestSyncRules_StoredDivergenceWarnsOnceAndLoadsSignedRules(t *testing.T) {
	vendor := testKey(t)
	r := rulesObj("baseline", "kubescape", "", string(bundle.RuleClassBase), "R0001")
	if err := signature.SignObject(profiles.NewRulesAdapter(r), signature.WithPrivateKey(vendor), signature.WithEmbedContent(true)); err != nil {
		t.Fatalf("sign: %v", err)
	}
	r.Spec.Rules = append(r.Spec.Rules, typesv1.Rule{Enabled: true, ID: "R9999", Name: "rogue"})

	creator := rulecreator.NewRuleCreator()
	w := NewRulesWatcher(newFakeK8sClient(t, r), creator, nil)
	w.SetTrustPolicy(&bundle.TrustPolicy{RuleClasses: map[bundle.RuleClass]bundle.RuleClassPolicy{
		bundle.RuleClassBase: {Signers: []string{signerOf(t, r)}, AllowedRuleIDs: []string{"*"}},
	}})

	out := captureLoggerOutput(t, func() {
		if err := w.syncAllRulesFromCluster(context.Background()); err != nil {
			t.Fatalf("sync: %v", err)
		}
		if err := w.syncAllRulesFromCluster(context.Background()); err != nil {
			t.Fatalf("resync: %v", err)
		}
	})
	if got := strings.Count(out, "stored spec diverges"); got != 1 {
		t.Fatalf("want exactly one divergence warning across two syncs, got %d\n%s", got, out)
	}

	all := creator.CreateAllRules()
	if len(all) != 1 || all[0].ID != "R0001" {
		t.Fatalf("only the SIGNED rules may load, got %+v", all)
	}
}
