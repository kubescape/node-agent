//go:build experimental_signing

package ruleswatcher

import (
	"encoding/json"
	"os"
	"testing"

	typesv1 "github.com/kubescape/node-agent/pkg/rulemanager/types/v1"
	"github.com/kubescape/node-agent/pkg/signature/bundle"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"sigs.k8s.io/yaml"
)

// The admission truth table (A1-A5, stated on admitFragments).
//
// It exists because a component test cannot tell the two halves of this apart.
// Test_39 asserts that a rejected untrusted fragment leaves the trusted R0001
// firing, and it does that by exec'ing a binary and watching for an alert — a
// path that also runs through profile completion, the profile cache, the
// cooldown and the alert exporter. When it failed, the failure was in profile
// completion and had nothing to do with signing, but the assertion message
// said "R0001 from the trusted base fragment must still fire" and pointed
// squarely at the admission gate. These tests separate the claim from the
// plumbing: they run the real signed fixtures through the real admission code
// and read the resulting rule set directly.
//
// Every case uses committed, really-signed fixtures. Nothing here constructs a
// fragment that could not exist in a cluster.

const fixtureDir = "../../../tests/resources/signed/"

func policy(t *testing.T) *bundle.TrustPolicy {
	t.Helper()
	raw, err := os.ReadFile(fixtureDir + "trust-policy.json")
	require.NoError(t, err, "the committed trust policy is the subject, not a detail")
	var p bundle.TrustPolicy
	require.NoError(t, json.Unmarshal(raw, &p))
	return &p
}

func fragment(t *testing.T, rel string) *typesv1.Rules {
	t.Helper()
	b, err := os.ReadFile(fixtureDir + "rules/" + rel)
	require.NoError(t, err, "read %s", rel)
	var r typesv1.Rules
	require.NoError(t, yaml.Unmarshal(b, &r), "parse %s", rel)
	return &r
}

// severitiesOf collects the severities admitted for one rule ID, keyed by the
// bundle they were admitted under. That is exactly the (bundle, ID) key
// SyncRules uses, so a collision here is a collision there.
func severitiesOf(rules []typesv1.Rule, id string) map[string][]int {
	out := map[string][]int{}
	for _, r := range rules {
		if r.ID == id {
			out[r.Bundle] = append(out[r.Bundle], r.Severity)
		}
	}
	return out
}

func idsOf(rules []typesv1.Rule) map[string]bool {
	out := map[string]bool{}
	for _, r := range rules {
		out[r.ID] = true
	}
	return out
}

const (
	baseFixture    = "cluster-baseline-signed.yaml"
	rogueFixture   = "untrusted-signer-signed.yaml"
	overlayFixture = "namespace-override-signed.yaml"
	mixedFixture   = "mixed-overlay-rejected-signed.yaml"

	baseR0001Sev    = 1
	rogueR0001Sev   = 7
	overlayR0001Sev = 9
	baseR0011Sev    = 5
)

// A3, the property this whole file exists for, in both orderings. The rogue
// fragment is a base-class R0001 signed by a key no class in the policy names.
// It must contribute nothing, and — the part that matters — it must not take
// the trusted R0001 with it.
func TestAdmission_UntrustedFragmentCannotSilenceTheTrustedRule(t *testing.T) {
	base := fragment(t, baseFixture)
	rogue := fragment(t, rogueFixture)

	for _, tc := range []struct {
		name  string
		input []*typesv1.Rules
	}{
		{"rogue after the base", []*typesv1.Rules{base, rogue}},
		{"rogue before the base", []*typesv1.Rules{rogue, base}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			rules, tally := admitFragments(tc.input, policy(t), true, nil)

			assert.Equal(t, 1, tally.admitted, "only the base fragment is admissible")
			assert.Equal(t, 1, tally.rejected, "the untrusted fragment is rejected")

			sev := severitiesOf(rules, "R0001")
			assert.Equal(t, []int{baseR0001Sev}, sev[""],
				"the trusted cluster-wide R0001 survives the rejection alongside it")
			assert.NotContains(t, sev[""], rogueR0001Sev, "the rogue severity must never be admitted")
			assert.Len(t, sev, 1, "the rogue fragment must not have created a second scope for R0001")

			// Not just R0001: nothing else the base fragment carries may go
			// missing because a fragment next to it was rejected.
			assert.True(t, idsOf(rules)["R0011"], "an unrelated trusted rule is untouched by the rejection")
			assert.True(t, idsOf(rules)["R1002"], "an unrelated trusted rule is untouched by the rejection")
		})
	}
}

// A3 again, at the harshest point: the rogue fragment ALONE. Detection goes to
// zero, which is correct — but the tally has to say so, because that number is
// what the outage backstop screams on.
func TestAdmission_RejectedFragmentAloneLeavesNoRulesAndSaysSo(t *testing.T) {
	rules, tally := admitFragments([]*typesv1.Rules{fragment(t, rogueFixture)}, policy(t), true, nil)

	assert.Empty(t, rules, "an untrusted fragment contributes no rules at all")
	assert.Equal(t, 0, tally.admitted, "admitted==0 with fragments present is the detection-outage signal")
	assert.Equal(t, 1, tally.rejected)
}

// A1: with signing off the gate is not in the path at all, and the rogue
// fragment's R0001 is admitted right next to the base one. This is the
// pre-signing behaviour, and stating it here is what makes the value of
// signing legible: without it, anyone who can create a Rules object retunes
// any rule they name.
func TestAdmission_SigningOffAdmitsEveryFragmentIncludingTheRogueOne(t *testing.T) {
	rules, tally := admitFragments([]*typesv1.Rules{fragment(t, baseFixture), fragment(t, rogueFixture)}, nil, false, nil)

	sev := severitiesOf(rules, "R0001")
	assert.ElementsMatch(t, []int{baseR0001Sev, rogueR0001Sev}, sev[""],
		"unsigned mode admits both, and which one wins is decided downstream by SyncRules")
	assert.Equal(t, admissionTally{}, tally, "the tally counts admission decisions, and none were made")
}

// A2: an admitted overlay is scoped to its signed bundle and is NOT
// cluster-wide, so it coexists with the base rule under a different key rather
// than replacing it. This is the difference between "retune for the workloads
// that opted in" and "retune for the cluster".
func TestAdmission_OverlayIsScopedToItsBundleAndCoexistsWithTheBase(t *testing.T) {
	rules, tally := admitFragments([]*typesv1.Rules{fragment(t, baseFixture), fragment(t, overlayFixture)}, policy(t), true, nil)

	assert.Equal(t, 2, tally.admitted)
	assert.Equal(t, 0, tally.rejected)

	sev := severitiesOf(rules, "R0001")
	assert.Equal(t, []int{baseR0001Sev}, sev[""], "the cluster-wide R0001 is unchanged")
	assert.Equal(t, []int{overlayR0001Sev}, sev["bundle37"], "the overlay's R0001 lives under its bundle")

	for _, r := range rules {
		if r.ID != "R0001" {
			continue
		}
		if r.Bundle == "bundle37" {
			assert.False(t, r.ClusterWide, "an overlay must never be cluster-wide — that is the whole confinement")
		} else {
			assert.True(t, r.ClusterWide, "the base class is the only cluster-wide class")
		}
	}
}

// A3 with a subtler rejection: this overlay is signed by a TRUSTED signer for
// its class, but carries one rule ID (R0011) the overlay class is not allowed
// to touch. The fragment is refused whole — no partial admission of the
// allowed half — and both rules keep their trusted values.
func TestAdmission_TrustedSignerReachingOutsideItsClassIsRefusedWhole(t *testing.T) {
	rules, tally := admitFragments([]*typesv1.Rules{fragment(t, baseFixture), fragment(t, mixedFixture)}, policy(t), true, nil)

	assert.Equal(t, 1, tally.admitted)
	assert.Equal(t, 1, tally.rejected)

	r1 := severitiesOf(rules, "R0001")
	assert.Equal(t, []int{baseR0001Sev}, r1[""])
	assert.NotContains(t, r1, "bundle37", "the allowed half of a refused fragment must not slip through")

	r11 := severitiesOf(rules, "R0011")
	assert.Equal(t, []int{baseR0011Sev}, r11[""], "the out-of-class rule keeps its trusted severity")
}

// A4: a rule the fragment ships disabled contributes nothing. This is why a
// fragment cannot silence a rule by redefining it as disabled — the disabled
// copy simply never enters the set, and any enabled copy from another fragment
// is unaffected.
func TestAdmission_DisabledRulesNeverEnterTheSet(t *testing.T) {
	rules, _ := admitFragments([]*typesv1.Rules{fragment(t, baseFixture)}, policy(t), true, nil)

	ids := idsOf(rules)
	// R0002, R1003 and R1011 ship disabled in the committed baseline.
	assert.False(t, ids["R0002"], "a disabled rule is absent, not present-and-off")
	assert.False(t, ids["R1003"])
	assert.False(t, ids["R1011"])
	assert.True(t, ids["R0001"], "the enabled ones from the same fragment are there")
}

// A5: a version skip is counted apart from a rejection, because the two mean
// opposite things to an operator — one is "your agent is old", the other is
// "someone tried to change your rules".
func TestAdmission_VersionSkipIsNotARejection(t *testing.T) {
	t.Setenv("AGENT_VERSION", "v0.1.0")
	frag := &typesv1.Rules{Spec: typesv1.RulesSpec{Rules: []typesv1.Rule{
		{ID: "R9998", Enabled: true, AgentVersionRequirement: ">= 99.0.0"},
		{ID: "R9999", Enabled: true},
	}}}

	rules, tally := admitFragments([]*typesv1.Rules{frag}, nil, false, nil)

	assert.Equal(t, []string{"R9999"}, func() []string {
		var out []string
		for _, r := range rules {
			out = append(out, r.ID)
		}
		return out
	}())
	assert.Equal(t, 1, tally.skippedVersion)
	assert.Equal(t, 0, tally.rejected, "an incompatible agent version is not an admission failure")
}

// The known ambiguity, asserted rather than left to be discovered: two
// fragments admitted under the SAME (bundle, ID) key both enter the flat set,
// and SyncRules keeps whichever it maps last. Reaching this needs two signers
// both trusted for the base class, which the policy format permits. Recorded
// here so a change in that resolution shows up as a failing test with a name
// that explains what it is.
func TestAdmission_SameKeyFromTwoAdmittedFragmentsIsNotResolvedHere(t *testing.T) {
	dup := func(sev int) *typesv1.Rules {
		return &typesv1.Rules{Spec: typesv1.RulesSpec{Rules: []typesv1.Rule{{ID: "R0001", Enabled: true, Severity: sev}}}}
	}
	rules, _ := admitFragments([]*typesv1.Rules{dup(1), dup(7)}, nil, false, nil)

	assert.Equal(t, []int{1, 7}, severitiesOf(rules, "R0001")[""],
		"admission emits both; the collision is decided by SyncRules' map, not here")
}

func TestAdmission_NilFragmentIsSkipped(t *testing.T) {
	rules, tally := admitFragments([]*typesv1.Rules{nil, fragment(t, baseFixture), nil}, policy(t), true, nil)

	assert.Equal(t, 1, tally.admitted)
	assert.True(t, idsOf(rules)["R0001"])
}

// The divergence callback fires for admitted fragments only. A rejected
// fragment must not be reported as if the agent had taken it into account.
func TestAdmission_DivergenceIsReportedOnlyForAdmittedFragments(t *testing.T) {
	var seen []string
	_, _ = admitFragments([]*typesv1.Rules{fragment(t, baseFixture), fragment(t, rogueFixture)}, policy(t), true,
		func(r *typesv1.Rules) { seen = append(seen, r.Name) })

	assert.Equal(t, []string{"ct-base-rules"}, seen, "a rejected fragment is never handed downstream")
}
