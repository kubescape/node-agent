//go:build experimental_signing

package bundle

import (
	"sync"
	"time"
)

// PolicyStatus is the operator-queryable identity of the trust policy in
// force. It exists because after a refused reload the mounted ConfigMap
// contains the REFUSED artifact: the cluster is the wrong place to ask what is
// enforced, so the agent must answer. Exposes digests, mode and counts only —
// never the policy body and never per-class signer fingerprints, so an
// unauthenticated read path cannot bypass ConfigMap RBAC or enumerate trusted
// signers.
type PolicyStatus struct {
	InForceDigest     string    `json:"inForceDigest"`
	Mode              string    `json:"mode"`
	RootFingerprint   string    `json:"rootFingerprint"`
	RootAnchor        string    `json:"rootAnchor"`
	PolicyVersion     int64     `json:"policyVersion"`
	RuleClassCount    int       `json:"ruleClassCount"`
	BindingClassCount int       `json:"bindingClassCount"`
	AppliedAt         time.Time `json:"appliedAt"`
	LastRefusedDigest string    `json:"lastRefusedDigest,omitempty"`
	LastRefusedAt     time.Time `json:"lastRefusedAt,omitempty"`
	RulesAdmitted     int       `json:"rulesAdmitted"`
	RulesRejected     int       `json:"rulesRejected"`
	EffectiveRules    int       `json:"effectiveRules"`
}

var (
	policyStatusMu sync.Mutex
	policyStatus   *PolicyStatus
)

func SetInForcePolicy(p *TrustPolicy, digest, rootFp string, mounted bool) {
	anchor := "compiled"
	if mounted {
		anchor = "mounted"
	} else if IsDemoRoot(rootFp) {
		anchor = "demo"
	}
	policyStatusMu.Lock()
	defer policyStatusMu.Unlock()
	next := &PolicyStatus{
		InForceDigest:     digest,
		Mode:              string(p.EffectiveMode()),
		RootFingerprint:   rootFp,
		RootAnchor:        anchor,
		PolicyVersion:     p.PolicyVersion,
		RuleClassCount:    len(p.RuleClasses),
		BindingClassCount: len(p.BindingClasses),
		AppliedAt:         time.Now().UTC(),
	}
	if policyStatus != nil {
		next.LastRefusedDigest = policyStatus.LastRefusedDigest
		next.LastRefusedAt = policyStatus.LastRefusedAt
		next.RulesAdmitted = policyStatus.RulesAdmitted
		next.RulesRejected = policyStatus.RulesRejected
		next.EffectiveRules = policyStatus.EffectiveRules
	}
	policyStatus = next
}

func RecordPolicyRefusal(refusedDigest string) {
	policyStatusMu.Lock()
	defer policyStatusMu.Unlock()
	if policyStatus == nil {
		policyStatus = &PolicyStatus{}
	}
	policyStatus.LastRefusedDigest = refusedDigest
	policyStatus.LastRefusedAt = time.Now().UTC()
}

func RecordRuleAdmission(admitted, rejected, effective int) {
	policyStatusMu.Lock()
	defer policyStatusMu.Unlock()
	if policyStatus == nil {
		return
	}
	policyStatus.RulesAdmitted = admitted
	policyStatus.RulesRejected = rejected
	policyStatus.EffectiveRules = effective
}

// PolicyStatusSnapshot returns a copy, nil when no policy was ever in force.
func PolicyStatusSnapshot() *PolicyStatus {
	policyStatusMu.Lock()
	defer policyStatusMu.Unlock()
	if policyStatus == nil {
		return nil
	}
	s := *policyStatus
	return &s
}

func resetPolicyStatusForTest() {
	policyStatusMu.Lock()
	defer policyStatusMu.Unlock()
	policyStatus = nil
}
