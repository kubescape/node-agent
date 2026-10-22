//go:build experimental_signing

package bundle

import (
	"testing"

	"github.com/stretchr/testify/require"
)

func TestPolicyStatus_LifecycleAndCounters(t *testing.T) {
	resetPolicyStatusForTest()
	require.Nil(t, PolicyStatusSnapshot(), "no status before any policy is in force")

	RecordRuleAdmission(1, 2, 3)
	require.Nil(t, PolicyStatusSnapshot(), "counters alone must not fabricate an in-force policy")

	p := &TrustPolicy{Mode: ModeEnforce, RuleClasses: map[RuleClass]RuleClassPolicy{RuleClassBase: {}}, PolicyVersion: 7}
	SetInForcePolicy(p, "d1", DemoRootFingerprint, false)
	s := PolicyStatusSnapshot()
	require.Equal(t, "d1", s.InForceDigest)
	require.Equal(t, "enforce", s.Mode)
	require.Equal(t, "demo", s.RootAnchor)
	require.Equal(t, int64(7), s.PolicyVersion)
	require.Equal(t, 1, s.RuleClassCount)

	RecordRuleAdmission(2, 1, 28)
	RecordPolicyRefusal("bad1")
	s = PolicyStatusSnapshot()
	require.Equal(t, 2, s.RulesAdmitted)
	require.Equal(t, 28, s.EffectiveRules)
	require.Equal(t, "bad1", s.LastRefusedDigest)
	require.Equal(t, "d1", s.InForceDigest, "a refusal must not move the in-force digest")

	SetInForcePolicy(&TrustPolicy{}, "d2", "key:real", true)
	s = PolicyStatusSnapshot()
	require.Equal(t, "d2", s.InForceDigest)
	require.Equal(t, "mounted", s.RootAnchor)
	require.Equal(t, "bad1", s.LastRefusedDigest, "refusal history survives a later apply")
	require.Equal(t, 2, s.RulesAdmitted, "counters survive a policy apply")

	snap := PolicyStatusSnapshot()
	snap.InForceDigest = "mutated"
	require.Equal(t, "d2", PolicyStatusSnapshot().InForceDigest, "snapshot must be a copy")
	resetPolicyStatusForTest()
}
