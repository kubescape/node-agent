//go:build experimental_signing

package ruleswatcher

import (
	"encoding/json"
	"fmt"
	"os"

	"github.com/kubescape/go-logger"
	"github.com/kubescape/go-logger/helpers"
	typesv1 "github.com/kubescape/node-agent/pkg/rulemanager/types/v1"
	"github.com/kubescape/node-agent/pkg/signature"
	"github.com/kubescape/node-agent/pkg/signature/bundle"
	"github.com/kubescape/node-agent/pkg/signature/profiles"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
)

// admissionTally counts what one sync pass did, for the log line and the
// detection-outage backstop.
type admissionTally struct {
	admitted       int
	rejected       int
	skippedVersion int
}

// admitFragments turns the Rules objects found in the cluster into the flat
// enabled-rule set the rule creator is synced with.
//
// It is a free function rather than a loop inside syncAllRulesFromCluster so
// the admission contract can be stated as a table against real signed
// fixtures, without a cluster. The contract it implements, in full:
//
//	A1. Signing off: every fragment contributes, cluster-wide, no bundle. This
//	    reproduces the pre-signing semantics exactly.
//	A2. Signing on, fragment admitted: it contributes its rules under its own
//	    class's provenance — cluster-wide only for the base class, otherwise
//	    scoped to the bundle named in its signed labels.
//	A3. Signing on, fragment rejected: it contributes NOTHING, and it removes
//	    nothing. Admission is per fragment; a rejection cannot reach across to
//	    another fragment's rules. This is the property that keeps an untrusted
//	    fragment from silencing a trusted rule it names.
//	A4. A disabled rule contributes nothing, from any fragment. So a fragment
//	    cannot switch off a rule another fragment enables — it can only fail to
//	    add its own copy.
//	A5. A rule whose agent-version requirement is not met contributes nothing
//	    and is counted separately, so a version skip is never read as a
//	    rejection.
//
// What the table does NOT claim, because it is not true: two ADMITTED
// fragments that both claim the same (bundle, rule ID) collide, and which one
// survives is decided downstream by SyncRules' map, not here. That requires
// two separately trusted signers for the same class, which the trust policy
// permits, and it is recorded as a known ambiguity rather than papered over.
func admitFragments(fragments []*typesv1.Rules, policy *bundle.TrustPolicy, signingEnabled bool, onAdmitted func(*typesv1.Rules)) ([]typesv1.Rule, admissionTally) {
	var enabledRules []typesv1.Rule
	var tally admissionTally

	for _, rules := range fragments {
		if rules == nil {
			continue
		}

		// A1: provenance defaults reproduce the pre-signing semantics exactly —
		// every rule is cluster-wide and belongs to no bundle, so bundle
		// resolution downstream is a no-op.
		bundleName := ""
		clusterWide := true
		candidates := rules.Spec.Rules

		if signingEnabled {
			verified, admitErr := bundle.AdmitRulesFragment(rules, *policy)
			if admitErr == nil {
				admitErr = validateAdmittedRules(rules, verified.Rules)
			}
			if admitErr != nil {
				// A3: drop this fragment whole and move on. Nothing already
				// collected is revisited.
				tally.rejected++
				logger.L().Warning("rules fragment rejected",
					helpers.String("name", rules.Name),
					helpers.String("namespace", rules.Namespace),
					helpers.Error(admitErr))
				continue
			}
			tally.admitted++
			bundleName = verified.Bundle
			clusterWide = verified.ClusterWide
			candidates = verified.Rules
			if onAdmitted != nil {
				onAdmitted(rules)
			}
		}

		for _, rule := range candidates {
			if !rule.Enabled { // A4
				continue
			}
			if rule.AgentVersionRequirement != "" && !isAgentVersionCompatible(rule.AgentVersionRequirement) { // A5
				logger.L().Debug("RulesWatcher - skipping rule due to agent version requirement",
					helpers.String("ruleID", rule.ID),
					helpers.String("requirement", rule.AgentVersionRequirement),
					helpers.String("agentVersion", os.Getenv("AGENT_VERSION")))
				tally.skippedVersion++
				continue
			}
			rule.Bundle = bundleName
			rule.ClusterWide = clusterWide
			enabledRules = append(enabledRules, rule)
		}
	}

	return enabledRules, tally
}

// Validate the authenticated view, including raw fields that typed decoding can
// discard, before admitting any rules from the fragment.
func validateAdmittedRules(carrier *typesv1.Rules, rules []typesv1.Rule) error {
	if content, present, err := signature.EmbeddedContent(profiles.NewRulesAdapter(carrier)); present {
		if err != nil {
			return err
		}
		var raw map[string]any
		if err := json.Unmarshal(content, &raw); err != nil {
			return err
		}
		if err := validateRawProfileDataInUnstructured(&unstructured.Unstructured{Object: raw}); err != nil {
			return err
		}
	}
	for _, rule := range rules {
		if rule.ProfileDataRequired != nil {
			if err := rule.ProfileDataRequired.Validate(); err != nil {
				return fmt.Errorf("rule %q invalid profileDataRequired: %w", rule.ID, err)
			}
		}
	}
	return nil
}
