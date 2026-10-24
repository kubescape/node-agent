//go:build experimental_signing

package bundle

import (
	"crypto/ecdsa"
	"errors"
	"testing"

	rulemanagertypesv1 "github.com/kubescape/node-agent/pkg/rulemanager/types/v1"
	"github.com/kubescape/node-agent/pkg/signature"
	"github.com/kubescape/node-agent/pkg/signature/profiles"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

// rule is a minimal enabled Rule with the given ID.
func rule(id string, enabled bool) rulemanagertypesv1.Rule {
	return rulemanagertypesv1.Rule{
		Enabled: enabled,
		ID:      id,
		Name:    "rule-" + id,
	}
}

// rulesObject builds a Rules fragment labelled exactly like a ContainerProfile
// fragment: LabelBundle + LabelFragmentClass. Both labels are set BEFORE signing
// because metadata.labels is inside the signed content, so the signature binds
// the class AND the bundle. The namespace is NOT signed and is only where the
// object happens to be installed.
func rulesObject(name, namespace, bundleName, class string, rules []rulemanagertypesv1.Rule) *rulemanagertypesv1.Rules {
	labels := map[string]string{}
	if class != "" {
		labels[LabelFragmentClass] = class
	}
	if bundleName != "" {
		labels[LabelBundle] = bundleName
	}
	return &rulemanagertypesv1.Rules{
		TypeMeta: metav1.TypeMeta{APIVersion: "kubescape.io/v1", Kind: "Rules"},
		ObjectMeta: metav1.ObjectMeta{
			Name:      name,
			Namespace: namespace,
			Labels:    labels,
		},
		Spec: rulemanagertypesv1.RulesSpec{Rules: rules},
	}
}

// signedRules builds a Rules object and signs it with key.
func signedRules(t *testing.T, name, namespace, bundleName, class string, rules []rulemanagertypesv1.Rule, key *ecdsa.PrivateKey) *rulemanagertypesv1.Rules {
	t.Helper()
	r := rulesObject(name, namespace, bundleName, class, rules)
	if err := signature.SignObject(profiles.NewRulesAdapter(r), signature.WithPrivateKey(key)); err != nil {
		t.Fatalf("sign %s: %v", name, err)
	}
	return r
}

func rulesSignerIDOf(t *testing.T, r *rulemanagertypesv1.Rules) string {
	t.Helper()
	id, err := RulesSignerID(r)
	if err != nil {
		t.Fatalf("signer identity: %v", err)
	}
	return id
}

func rulePolicy(baseSigner, overlaySigner string, baseIDs, overlayIDs []string) TrustPolicy {
	return TrustPolicy{RuleClasses: map[RuleClass]RuleClassPolicy{
		RuleClassBase:    {Signers: []string{baseSigner}, AllowedRuleIDs: baseIDs},
		RuleClassOverlay: {Signers: []string{overlaySigner}, AllowedRuleIDs: overlayIDs},
	}}
}

func TestRuleSigningEnabled(t *testing.T) {
	if (TrustPolicy{}).RuleSigningEnabled() {
		t.Error("empty policy must report rule signing disabled")
	}
	// A profile-only policy (the pre-existing shape) must NOT turn rule signing on.
	profileOnly := TrustPolicy{Classes: map[FragmentClass]ClassPolicy{ClassBase: {}}}
	if profileOnly.RuleSigningEnabled() {
		t.Error("policy without ruleClasses must report rule signing disabled")
	}
	withRules := TrustPolicy{RuleClasses: map[RuleClass]RuleClassPolicy{RuleClassBase: {}}}
	if !withRules.RuleSigningEnabled() {
		t.Error("policy with ruleClasses must report rule signing enabled")
	}
}

func TestAdmitRulesFragment_BaseHappyPath(t *testing.T) {
	vendor, operator := genKey(t), genKey(t)
	frag := signedRules(t, "baseline", "kubescape", "", string(RuleClassBase), []rulemanagertypesv1.Rule{rule("R0001", true), rule("R0002", true)}, vendor)
	ovlFrag := signedRules(t, "redis-tuning", "redis", "redis", string(RuleClassOverlay), []rulemanagertypesv1.Rule{rule("R0001", true)}, operator)
	policy := rulePolicy(rulesSignerIDOf(t, frag), rulesSignerIDOf(t, ovlFrag), []string{"R0001", "R0002"}, []string{"R0001"})

	got, err := AdmitRulesFragment(frag, policy)
	if err != nil {
		t.Fatalf("AdmitRulesFragment: %v", err)
	}
	if got.Class != RuleClassBase {
		t.Errorf("class = %q, want %q", got.Class, RuleClassBase)
	}
	if !got.ClusterWide {
		t.Error("base class fragment must be ClusterWide")
	}
	// The cluster baseline belongs to no bundle: it applies to every workload.
	if got.Bundle != "" {
		t.Errorf("bundle = %q, want empty for a base fragment", got.Bundle)
	}
	if len(got.Rules) != 2 {
		t.Fatalf("got %d rules, want 2", len(got.Rules))
	}
	if got.Signer != rulesSignerIDOf(t, frag) {
		t.Errorf("signer = %q", got.Signer)
	}
}

func TestAdmitRulesFragment_OverlayHappyPath(t *testing.T) {
	vendor, operator := genKey(t), genKey(t)
	baseFrag := signedRules(t, "baseline", "kubescape", "", string(RuleClassBase), []rulemanagertypesv1.Rule{rule("R0001", true)}, vendor)
	frag := signedRules(t, "redis-tuning", "redis", "redis", string(RuleClassOverlay), []rulemanagertypesv1.Rule{rule("R0001", false)}, operator)
	policy := rulePolicy(rulesSignerIDOf(t, baseFrag), rulesSignerIDOf(t, frag), []string{"R0001"}, []string{"R0001"})

	got, err := AdmitRulesFragment(frag, policy)
	if err != nil {
		t.Fatalf("AdmitRulesFragment: %v", err)
	}
	if got.Class != RuleClassOverlay {
		t.Errorf("class = %q, want %q", got.Class, RuleClassOverlay)
	}
	if got.ClusterWide {
		t.Error("overlay class fragment must not be ClusterWide")
	}
	if got.Bundle != "redis" {
		t.Errorf("bundle = %q, want %q", got.Bundle, "redis")
	}
}

// The bundle the agent scopes by must come from the SIGNED labels, never from
// the stored carrier object: relabelling a validly signed overlay must not
// re-target it at another bundle.
func TestAdmitRulesFragment_BundleComesFromSignedLabels(t *testing.T) {
	key := genKey(t)
	frag := signedRules(t, "redis-tuning", "redis", "redis", string(RuleClassOverlay), []rulemanagertypesv1.Rule{rule("R0001", true)}, key)
	policy := rulePolicy("key:none", rulesSignerIDOf(t, frag), []string{"*"}, []string{"*"})

	// Precondition: the fragment ships with embedded signed content, which is
	// what makes the carrier's labels irrelevant.
	if _, present, _ := signature.EmbeddedContent(profiles.NewRulesAdapter(frag)); !present {
		t.Skip("fragment carries no embedded content; relabelling is caught by the signature instead")
	}

	frag.Labels[LabelBundle] = "payments"

	got, err := AdmitRulesFragment(frag, policy)
	if err != nil {
		t.Fatalf("AdmitRulesFragment: %v", err)
	}
	if got.Bundle != "redis" {
		t.Fatalf("bundle = %q, want the SIGNED bundle %q", got.Bundle, "redis")
	}
}

func TestAdmitRulesFragment_Unsigned(t *testing.T) {
	policy := rulePolicy("key:whatever", "key:whatever", []string{"*"}, []string{"*"})
	frag := rulesObject("unsigned", "redis", "redis", string(RuleClassOverlay), []rulemanagertypesv1.Rule{rule("R0001", true)})

	_, err := AdmitRulesFragment(frag, policy)
	if !errors.Is(err, ErrFragmentUnsigned) {
		t.Fatalf("want ErrFragmentUnsigned, got %v", err)
	}
}

func TestAdmitRulesFragment_Tampered(t *testing.T) {
	// The canonical attack: flip a rule to disabled after the vendor signed it.
	key := genKey(t)
	frag := signedRules(t, "baseline", "kubescape", "", string(RuleClassBase), []rulemanagertypesv1.Rule{rule("R0001", true)}, key)
	policy := rulePolicy(rulesSignerIDOf(t, frag), "key:none", []string{"*"}, []string{"*"})
	if _, err := AdmitRulesFragment(frag, policy); err != nil {
		t.Fatalf("precondition: fragment must admit before tampering: %v", err)
	}

	frag.Spec.Rules[0].Enabled = false

	_, err := AdmitRulesFragment(frag, policy)
	if !errors.Is(err, ErrFragmentTampered) {
		t.Fatalf("want ErrFragmentTampered, got %v", err)
	}
}

func TestAdmitRulesFragment_NamespaceIsNotSigned(t *testing.T) {
	// A vendor cannot know which namespace a customer installs into, so
	// metadata.namespace is NOT part of the signed content: the same signed
	// artifact must admit wherever it is placed, and it stays scoped to its
	// BUNDLE regardless of the namespace it landed in.
	key := genKey(t)
	frag := signedRules(t, "redis-tuning", "redis", "redis", string(RuleClassOverlay), []rulemanagertypesv1.Rule{rule("R0001", true)}, key)
	policy := rulePolicy("key:none", rulesSignerIDOf(t, frag), []string{"*"}, []string{"*"})

	for _, ns := range []string{"payments", "team-a", ""} {
		frag.Namespace = ns

		v, err := AdmitRulesFragment(frag, policy)
		if err != nil {
			t.Fatalf("a signed fragment must admit in any namespace (%q), got %v", ns, err)
		}
		if v.Bundle != "redis" {
			t.Fatalf("installed in %q: bundle = %q, want %q — the namespace must not affect scoping", ns, v.Bundle, "redis")
		}
	}
}

func TestAdmitRulesFragment_UntrustedSigner(t *testing.T) {
	vendor, attacker := genKey(t), genKey(t)
	trusted := signedRules(t, "baseline", "kubescape", "", string(RuleClassBase), []rulemanagertypesv1.Rule{rule("R0001", true)}, vendor)
	frag := signedRules(t, "rogue", "kubescape", "", string(RuleClassBase), []rulemanagertypesv1.Rule{rule("R0001", false)}, attacker)
	policy := rulePolicy(rulesSignerIDOf(t, trusted), "key:none", []string{"*"}, []string{"*"})

	_, err := AdmitRulesFragment(frag, policy)
	if !errors.Is(err, ErrSignerNotTrusted) {
		t.Fatalf("want ErrSignerNotTrusted, got %v", err)
	}
}

func TestAdmitRulesFragment_RuleIDNotAllowed(t *testing.T) {
	key := genKey(t)
	frag := signedRules(t, "redis-tuning", "redis", "redis", string(RuleClassOverlay), []rulemanagertypesv1.Rule{rule("R0001", true), rule("R9999", true)}, key)
	policy := rulePolicy("key:none", rulesSignerIDOf(t, frag), []string{"*"}, []string{"R0001"})

	_, err := AdmitRulesFragment(frag, policy)
	if !errors.Is(err, ErrRuleIDNotAllowed) {
		t.Fatalf("want ErrRuleIDNotAllowed, got %v", err)
	}
	if err == nil || !contains(err.Error(), "R9999") {
		t.Errorf("error must name the offending rule ID, got %v", err)
	}
}

func TestAdmitRulesFragment_ClassNotAllowed(t *testing.T) {
	key := genKey(t)
	frag := signedRules(t, "redis-tuning", "redis", "redis", string(RuleClassOverlay), []rulemanagertypesv1.Rule{rule("R0001", true)}, key)
	// Policy only knows the base class.
	policy := TrustPolicy{RuleClasses: map[RuleClass]RuleClassPolicy{
		RuleClassBase: {Signers: []string{rulesSignerIDOf(t, frag)}, AllowedRuleIDs: []string{"*"}},
	}}

	_, err := AdmitRulesFragment(frag, policy)
	if !errors.Is(err, ErrRuleClassNotAllowed) {
		t.Fatalf("want ErrRuleClassNotAllowed, got %v", err)
	}
}

func TestAdmitRulesFragment_NoClassLabel(t *testing.T) {
	key := genKey(t)
	frag := signedRules(t, "unclassed", "redis", "redis", "", []rulemanagertypesv1.Rule{rule("R0001", true)}, key)
	policy := rulePolicy(rulesSignerIDOf(t, frag), rulesSignerIDOf(t, frag), []string{"*"}, []string{"*"})

	_, err := AdmitRulesFragment(frag, policy)
	if !errors.Is(err, ErrNoClass) {
		t.Fatalf("want ErrNoClass, got %v", err)
	}
}

func TestAdmitRulesFragment_WildcardRuleIDs(t *testing.T) {
	key := genKey(t)
	frag := signedRules(t, "baseline", "kubescape", "", string(RuleClassBase), []rulemanagertypesv1.Rule{rule("R0001", true), rule("R4242", true), rule("anything", true)}, key)
	policy := TrustPolicy{RuleClasses: map[RuleClass]RuleClassPolicy{
		RuleClassBase: {Signers: []string{rulesSignerIDOf(t, frag)}, AllowedRuleIDs: []string{"*"}},
	}}

	got, err := AdmitRulesFragment(frag, policy)
	if err != nil {
		t.Fatalf("wildcard AllowedRuleIDs must admit any ID: %v", err)
	}
	if len(got.Rules) != 3 {
		t.Errorf("got %d rules, want 3", len(got.Rules))
	}
}

// An overlay with no bundle label could not be scoped to anything, so it is
// rejected rather than silently applied everywhere or nowhere.
func TestAdmitRulesFragment_OverlayWithoutBundle(t *testing.T) {
	key := genKey(t)
	frag := signedRules(t, "bundleless", "redis", "", string(RuleClassOverlay), []rulemanagertypesv1.Rule{rule("R0001", true)}, key)
	policy := TrustPolicy{RuleClasses: map[RuleClass]RuleClassPolicy{
		RuleClassOverlay: {Signers: []string{rulesSignerIDOf(t, frag)}, AllowedRuleIDs: []string{"*"}},
	}}

	_, err := AdmitRulesFragment(frag, policy)
	if !errors.Is(err, ErrRuleBundleRequired) {
		t.Fatalf("want ErrRuleBundleRequired, got %v", err)
	}
}

// A base fragment belongs to no bundle, so an empty bundle label is fine.
func TestAdmitRulesFragment_BaseWithoutBundleAdmits(t *testing.T) {
	key := genKey(t)
	frag := signedRules(t, "baseline", "kubescape", "", string(RuleClassBase), []rulemanagertypesv1.Rule{rule("R0001", true)}, key)
	policy := TrustPolicy{RuleClasses: map[RuleClass]RuleClassPolicy{
		RuleClassBase: {Signers: []string{rulesSignerIDOf(t, frag)}, AllowedRuleIDs: []string{"*"}},
	}}

	got, err := AdmitRulesFragment(frag, policy)
	if err != nil {
		t.Fatalf("a base fragment without a bundle must admit, got %v", err)
	}
	if got.Bundle != "" || !got.ClusterWide {
		t.Fatalf("base fragment shape: bundle=%q clusterWide=%v", got.Bundle, got.ClusterWide)
	}
}

// The vendor ships ONE bundle: the ContainerProfile half and the Rules half
// carry the SAME labels, only the fragment class differs. This pins the
// symmetry — the rule fragment is read with the very constants the profile
// fragments use.
func TestAdmitRulesFragment_SameLabelsAsProfileFragments(t *testing.T) {
	key := genKey(t)
	frag := signedRules(t, "redis-rules", "anywhere", "redis", string(ClassOverlay), []rulemanagertypesv1.Rule{rule("R0001", true)}, key)
	policy := TrustPolicy{RuleClasses: map[RuleClass]RuleClassPolicy{
		RuleClassOverlay: {Signers: []string{rulesSignerIDOf(t, frag)}, AllowedRuleIDs: []string{"*"}},
	}}

	got, err := AdmitRulesFragment(frag, policy)
	if err != nil {
		t.Fatalf("AdmitRulesFragment: %v", err)
	}
	if string(got.Class) != string(ClassOverlay) || got.Bundle != "redis" {
		t.Fatalf("class=%q bundle=%q, want overlay/redis", got.Class, got.Bundle)
	}
	// And the profile-fragment class constants are literally the same strings.
	if string(RuleClassBase) != string(ClassBase) || string(RuleClassOverlay) != string(ClassOverlay) {
		t.Fatal("rule and profile fragment class names must match")
	}
}

func TestRuleClassPolicy_Allows(t *testing.T) {
	p := RuleClassPolicy{Signers: []string{"key:a"}, AllowedRuleIDs: []string{"R0001"}}
	if !p.allowsSigner("key:a") || p.allowsSigner("key:b") {
		t.Error("allowsSigner mismatch")
	}
	if !p.allowsRuleID("R0001") || p.allowsRuleID("R0002") {
		t.Error("allowsRuleID mismatch")
	}
	// The wildcard is only honoured in AllowedRuleIDs, never in Signers.
	w := RuleClassPolicy{Signers: []string{"*"}, AllowedRuleIDs: []string{"*"}}
	if !w.allowsRuleID("whatever") {
		t.Error("wildcard rule ID must match")
	}
	if !w.allowsSigner("*") || w.allowsSigner("key:a") {
		t.Error("signers must be matched literally, no wildcard")
	}
}

func contains(haystack, needle string) bool {
	for i := 0; i+len(needle) <= len(haystack); i++ {
		if haystack[i:i+len(needle)] == needle {
			return true
		}
	}
	return false
}

// The literal #68 observation: a key that IS trusted — for the base class —
// signs an overlay fragment. Cross-class use of a legitimate key must be
// refused exactly like an unknown key.
func TestAdmitRulesFragment_TrustedBaseKeySigningOverlay(t *testing.T) {
	vendor, operator := genKey(t), genKey(t)
	baseFrag := signedRules(t, "baseline", "kubescape", "", string(RuleClassBase), []rulemanagertypesv1.Rule{rule("R0001", true)}, vendor)
	ovlProbe := signedRules(t, "probe", "redis", "redis", string(RuleClassOverlay), []rulemanagertypesv1.Rule{rule("R0001", true)}, operator)
	policy := rulePolicy(rulesSignerIDOf(t, baseFrag), rulesSignerIDOf(t, ovlProbe), []string{"*"}, []string{"R0001", "R0002"})

	crossClass := signedRules(t, "rogue-overlay", "redis", "redis", string(RuleClassOverlay), []rulemanagertypesv1.Rule{rule("R0001", false)}, vendor)
	got, err := AdmitRulesFragment(crossClass, policy)
	if !errors.Is(err, ErrSignerNotTrusted) {
		t.Fatalf("want ErrSignerNotTrusted for a base-trusted key signing an overlay, got %v", err)
	}
	if len(got.Rules) != 0 {
		t.Fatalf("no rules may load from a cross-class fragment, got %d", len(got.Rules))
	}

	swapped := signedRules(t, "rogue-base", "kubescape", "", string(RuleClassBase), []rulemanagertypesv1.Rule{rule("R0001", false)}, operator)
	if _, err := AdmitRulesFragment(swapped, policy); !errors.Is(err, ErrSignerNotTrusted) {
		t.Fatalf("want ErrSignerNotTrusted for an overlay-trusted key signing base, got %v", err)
	}
}
