//go:build experimental_signing

// Guards the committed stacking fixtures: the v2 fragments must admit under
// the committed CT trust policy with a version strictly above their v1s, or
// the Test_56 replacement/rollback legs assert against dead fixtures.
package bundle

import (
	"encoding/json"
	"os"
	"testing"

	rulemanagertypesv1 "github.com/kubescape/node-agent/pkg/rulemanager/types/v1"
	"github.com/kubescape/storage/pkg/apis/softwarecomposition/v1beta1"
	"sigs.k8s.io/yaml"
)

func committedPolicy(t *testing.T) TrustPolicy {
	t.Helper()
	raw, err := os.ReadFile("../../../tests/resources/signed/trust-policy.json")
	if err != nil {
		t.Skipf("committed policy not present: %v", err)
	}
	var policy TrustPolicy
	if err := json.Unmarshal(raw, &policy); err != nil {
		t.Fatal(err)
	}
	return policy
}

func TestStackingFixtures_OverlayV2AdmitsAboveV1(t *testing.T) {
	policy := committedPolicy(t)
	load := func(rel string) *v1beta1.ContainerProfile {
		b, err := os.ReadFile("../../../tests/resources/signed/fragments/" + rel)
		if err != nil {
			t.Fatalf("read %s: %v", rel, err)
		}
		var cp v1beta1.ContainerProfile
		if err := yaml.Unmarshal(b, &cp); err != nil {
			t.Fatalf("parse %s: %v", rel, err)
		}
		return &cp
	}
	v1f, err := admitFragment(load("bundle37-overlay-signed.yaml"), "bundle37", policy)
	if err != nil {
		t.Fatalf("overlay v1 must admit: %v", err)
	}
	v2f, err := admitFragment(load("bundle37-overlay-v2-signed.yaml"), "bundle37", policy)
	if err != nil {
		t.Fatalf("overlay v2 must admit: %v", err)
	}
	if v2f.version <= v1f.version {
		t.Fatalf("v2 version (%d) must exceed v1 (%d) for the replacement/rollback legs", v2f.version, v1f.version)
	}
}

func TestStackingFixtures_RulesOverrideV2Admits(t *testing.T) {
	policy := committedPolicy(t)
	b, err := os.ReadFile("../../../tests/resources/signed/rules/namespace-override-v2-signed.yaml")
	if err != nil {
		t.Fatalf("read rules v2: %v", err)
	}
	var rules rulemanagertypesv1.Rules
	if err := yaml.Unmarshal(b, &rules); err != nil {
		t.Fatalf("parse rules v2: %v", err)
	}
	verified, err := AdmitRulesFragment(&rules, policy)
	if err != nil {
		t.Fatalf("rules override v2 must admit under the committed policy: %v", err)
	}
	if verified.Bundle != "bundle37" {
		t.Fatalf("rules override v2 bundle = %q, want bundle37", verified.Bundle)
	}
	if len(verified.Rules) != 1 || verified.Rules[0].ID != "R0001" || verified.Rules[0].Severity != 8 {
		t.Fatalf("rules override v2 must carry exactly R0001 severity 8: %+v", verified.Rules)
	}
}

// W6b: a multi-rule fragment carrying ONE rule ID outside its class allowlist
// is rejected WHOLLY — no partial admission of the allowed subset.
func TestRulesAdmission_DisallowedIDRejectsWholeFragment(t *testing.T) {
	key := genKey(t)
	mixed := signedRules(t, "mixed-rules", "ns", "bundle37", "overlay", []rulemanagertypesv1.Rule{
		{ID: "R0001", Name: "ok", Enabled: true},
		{ID: "R0011", Name: "not-allowed", Enabled: true},
	}, key)
	policy := TrustPolicy{RuleClasses: map[RuleClass]RuleClassPolicy{
		RuleClassOverlay: {Signers: []string{rulesSignerIDOf(t, mixed)}, AllowedRuleIDs: []string{"R0001"}},
	}}
	if _, aerr := AdmitRulesFragment(mixed, policy); aerr == nil {
		t.Fatal("a fragment with any disallowed rule ID must be rejected wholly")
	}

	pure := signedRules(t, "pure-rules", "ns", "bundle37", "overlay", []rulemanagertypesv1.Rule{
		{ID: "R0001", Name: "ok", Enabled: true},
	}, key)
	if v, aerr := AdmitRulesFragment(pure, policy); aerr != nil {
		t.Fatalf("the compliant single-ID fragment must admit: %v", aerr)
	} else if len(v.Rules) != 1 {
		t.Fatalf("admitted view must carry exactly the one rule: %+v", v.Rules)
	}
}

func TestStackingFixtures_OverlayV3AdmitsAboveV2(t *testing.T) {
	policy := committedPolicy(t)
	b, err := os.ReadFile("../../../tests/resources/signed/fragments/bundle37-overlay-v3-signed.yaml")
	if err != nil {
		t.Fatalf("read v3: %v", err)
	}
	var cp v1beta1.ContainerProfile
	if err := yaml.Unmarshal(b, &cp); err != nil {
		t.Fatal(err)
	}
	vf, err := admitFragment(&cp, "bundle37", policy)
	if err != nil {
		t.Fatalf("overlay v3 must admit: %v", err)
	}
	if vf.version != 3 {
		t.Fatalf("v3 version = %d, want 3", vf.version)
	}
}

func TestStackingFixtures_MixedRulesFragmentRejectedByCommittedPolicy(t *testing.T) {
	policy := committedPolicy(t)
	b, err := os.ReadFile("../../../tests/resources/signed/rules/mixed-overlay-rejected-signed.yaml")
	if err != nil {
		t.Fatalf("read mixed: %v", err)
	}
	var rules rulemanagertypesv1.Rules
	if err := yaml.Unmarshal(b, &rules); err != nil {
		t.Fatal(err)
	}
	if _, aerr := AdmitRulesFragment(&rules, policy); aerr == nil {
		t.Fatal("the mixed R0001+R0011 overlay fragment must be rejected wholly (R0011 outside the overlay allowlist)")
	}
}

// bundle56 fixtures (debian coreutils, distinct real binaries) admit under the
// committed CT policy with monotonic overlay versions — the exec-grant Test_56
// legs depend on real binaries so R0001 can actually discriminate grants
// (busybox applets all collapse to /bin/busybox and cannot).
func TestStackingFixtures_Bundle56AdmitsWithVersions(t *testing.T) {
	policy := committedPolicy(t)
	load := func(rel string) *v1beta1.ContainerProfile {
		b, err := os.ReadFile("../../../tests/resources/signed/fragments/" + rel)
		if err != nil {
			t.Fatalf("read %s: %v", rel, err)
		}
		var cp v1beta1.ContainerProfile
		if err := yaml.Unmarshal(b, &cp); err != nil {
			t.Fatalf("parse %s: %v", rel, err)
		}
		return &cp
	}
	if _, err := admitFragment(load("bundle56-base-signed.yaml"), "bundle56", policy); err != nil {
		t.Fatalf("bundle56 base must admit: %v", err)
	}
	var prev int64
	for i, rel := range []string{"bundle56-overlay-v1-signed.yaml", "bundle56-overlay-v2-signed.yaml", "bundle56-overlay-v3-signed.yaml"} {
		vf, err := admitFragment(load(rel), "bundle56", policy)
		if err != nil {
			t.Fatalf("%s must admit: %v", rel, err)
		}
		if int64(i+1) != vf.version {
			t.Fatalf("%s version = %d, want %d", rel, vf.version, i+1)
		}
		if vf.version <= prev {
			t.Fatalf("overlay versions must be strictly monotonic: %d after %d", vf.version, prev)
		}
		prev = vf.version
	}
}
