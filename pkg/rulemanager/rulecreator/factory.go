package rulecreator

import (
	"slices"
	"sync"

	"github.com/kubescape/node-agent/pkg/contextdetection"
	"github.com/kubescape/node-agent/pkg/rulemanager/prefilter"
	typesv1 "github.com/kubescape/node-agent/pkg/rulemanager/types/v1"
	"github.com/kubescape/node-agent/pkg/utils"
)

var _ RuleCreator = (*RuleCreatorImpl)(nil)

type RuleCreatorImpl struct {
	mutex sync.RWMutex
	Rules []typesv1.Rule
}

func NewRuleCreator() *RuleCreatorImpl {
	return &RuleCreatorImpl{}
}

func (r *RuleCreatorImpl) CreateRulesByTags(tags []string) []typesv1.Rule {
	var rules []typesv1.Rule
	for _, rule := range r.Rules {
		for _, tag := range tags {
			if slices.Contains(rule.Tags, tag) {
				rules = append(rules, rule)
				break
			}
		}
	}
	return rules
}

// CreateRuleByID returns the rule with the given ID.
//
// Since signed bundle overlays may carry a rule ID that also exists
// cluster-wide, an ID can now match several entries. This single-return lookup
// deliberately prefers the CLUSTER-WIDE variant (Bundle == "") so its result is
// identical to the pre-signing behaviour for every existing caller; bundle
// overriding is resolved later, per pod, in the rule-binding cache
// (scopeRulesToBundle). If no cluster-wide variant exists, the first match
// wins.
func (r *RuleCreatorImpl) CreateRuleByID(id string) typesv1.Rule {
	r.mutex.RLock()
	defer r.mutex.RUnlock()

	var fallback typesv1.Rule
	var found bool
	for _, rule := range r.Rules {
		if rule.ID != id {
			continue
		}
		if rule.ClusterWide || rule.Bundle == "" {
			return rule
		}
		if !found {
			fallback, found = rule, true
		}
	}
	return fallback
}

// CreateRuleByName returns the rule with the given name, preferring the
// cluster-wide variant for the same reason as CreateRuleByID.
func (r *RuleCreatorImpl) CreateRuleByName(name string) typesv1.Rule {
	r.mutex.RLock()
	defer r.mutex.RUnlock()

	var fallback typesv1.Rule
	var found bool
	for _, rule := range r.Rules {
		if rule.Name != name {
			continue
		}
		if rule.ClusterWide || rule.Bundle == "" {
			return rule
		}
		if !found {
			fallback, found = rule, true
		}
	}
	return fallback
}

// CreateRulesByID returns EVERY rule carrying the given ID: the cluster-wide
// rule and each bundle overlay that overrides it. Unlike CreateRuleByID this
// makes no choice — the choice belongs to the per-pod resolution in the
// rule-binding cache, which knows the pod's bundle.
// Ordering follows registration order, so it is deterministic.
func (r *RuleCreatorImpl) CreateRulesByID(id string) []typesv1.Rule {
	r.mutex.RLock()
	defer r.mutex.RUnlock()

	var rules []typesv1.Rule
	for _, rule := range r.Rules {
		if rule.ID == id {
			rules = append(rules, rule)
		}
	}
	return rules
}

// CreateRulesByName returns EVERY rule carrying the given name, for the same
// reason as CreateRulesByID.
func (r *RuleCreatorImpl) CreateRulesByName(name string) []typesv1.Rule {
	r.mutex.RLock()
	defer r.mutex.RUnlock()

	var rules []typesv1.Rule
	for _, rule := range r.Rules {
		if rule.Name == name {
			rules = append(rules, rule)
		}
	}
	return rules
}

func (r *RuleCreatorImpl) RegisterRule(rule typesv1.Rule) {
	r.Rules = append(r.Rules, rule)
}

func (r *RuleCreatorImpl) CreateRulesByEventType(eventType utils.EventType) []typesv1.Rule {
	var rules []typesv1.Rule
	for _, rule := range r.Rules {
		for _, expression := range rule.Expressions.RuleExpression {
			if expression.EventType == eventType {
				rules = append(rules, rule)
				break
			}
		}
	}
	return rules
}

func (r *RuleCreatorImpl) CreateRulePolicyRulesByEventType(eventType utils.EventType) []typesv1.Rule {
	rules := r.CreateRulesByEventType(eventType)
	for _, rule := range rules {
		if rule.SupportPolicy {
			rules = append(rules, rule)
		}
	}

	return rules
}

func (r *RuleCreatorImpl) GetAllRuleIDs() []string {
	r.mutex.RLock()
	defer r.mutex.RUnlock()

	seen := make(map[string]struct{}, len(r.Rules))
	var ruleIDs []string
	for _, rule := range r.Rules {
		if _, ok := seen[rule.ID]; !ok {
			seen[rule.ID] = struct{}{}
			ruleIDs = append(ruleIDs, rule.ID)
		}
	}
	return ruleIDs
}

func (r *RuleCreatorImpl) CreateAllRules() []typesv1.Rule {
	r.mutex.Lock()
	defer r.mutex.Unlock()

	var rules []typesv1.Rule
	for i := range r.Rules {
		if r.Rules[i].Prefilter == nil {
			r.Rules[i].Prefilter = prefilter.ParseWithDefaults(r.Rules[i].State, nil)
		}
		rules = append(rules, r.Rules[i])
	}
	return rules
}

func (r *RuleCreatorImpl) CreateRulesForContext(ctx contextdetection.EventSourceContext) []typesv1.Rule {
	r.mutex.Lock()
	defer r.mutex.Unlock()

	var rules []typesv1.Rule
	for i := range r.Rules {
		if !RuleMatchesContext(&r.Rules[i], ctx) {
			continue
		}
		if r.Rules[i].Prefilter == nil {
			r.Rules[i].Prefilter = prefilter.ParseWithDefaults(r.Rules[i].State, nil)
		}
		rules = append(rules, r.Rules[i])
	}
	return rules
}

// ruleKey identifies a rule inside the creator's rule set. A rule ID alone is
// NOT unique any more: a signed bundle overlay may carry the same rule ID as the
// cluster-wide rule it overrides for that bundle, and the two must coexist here
// (bundle resolution happens later, in the rule-binding cache). Cluster-wide
// rules have an empty Bundle, so their key is "/<id>" and the pre-signing
// behaviour is unchanged.
func ruleKey(rule typesv1.Rule) string {
	return rule.Bundle + "/" + rule.ID
}

// SyncRules replaces the current rules with the new set of rules
// It removes rules that are no longer present and adds/updates existing ones
func (r *RuleCreatorImpl) SyncRules(newRules []typesv1.Rule) {
	r.mutex.Lock()
	defer r.mutex.Unlock()

	// Create a map of new rules by (bundle, ID) for quick lookup
	newRuleMap := make(map[string]typesv1.Rule)
	for _, rule := range newRules {
		newRuleMap[ruleKey(rule)] = rule
	}

	// Remove rules that are no longer present
	var updatedRules []typesv1.Rule
	for _, existingRule := range r.Rules {
		key := ruleKey(existingRule)
		if newRule, exists := newRuleMap[key]; exists {
			// Rule still exists, use the new version
			updatedRules = append(updatedRules, newRule)
			delete(newRuleMap, key) // Mark as processed
		}
		// If rule doesn't exist in newRuleMap, it's removed (not added to updatedRules)
	}

	// Add any completely new rules
	for _, newRule := range newRules {
		key := ruleKey(newRule)
		if ruleToAdd, exists := newRuleMap[key]; exists {
			updatedRules = append(updatedRules, ruleToAdd)
			delete(newRuleMap, key)
		}
	}

	r.Rules = updatedRules
}

// RemoveRuleByID removes a rule with the given ID and returns true if found.
// Like CreateRuleByID it prefers the cluster-wide variant when several rules
// share an ID, so its effect on a cluster without bundle overlays is unchanged.
func (r *RuleCreatorImpl) RemoveRuleByID(id string) bool {
	r.mutex.Lock()
	defer r.mutex.Unlock()

	fallback := -1
	for i, rule := range r.Rules {
		if rule.ID != id {
			continue
		}
		if rule.ClusterWide || rule.Bundle == "" {
			r.Rules = append(r.Rules[:i], r.Rules[i+1:]...)
			return true
		}
		if fallback < 0 {
			fallback = i
		}
	}
	if fallback >= 0 {
		r.Rules = append(r.Rules[:fallback], r.Rules[fallback+1:]...)
		return true
	}
	return false
}

// UpdateRule updates an existing rule or adds it if it doesn't exist. The match
// is on the composite (bundle, ID) key so updating a cluster-wide rule never
// clobbers a bundle overlay with the same ID, and vice versa.
func (r *RuleCreatorImpl) UpdateRule(rule typesv1.Rule) bool {
	r.mutex.Lock()
	defer r.mutex.Unlock()

	key := ruleKey(rule)
	for i, existingRule := range r.Rules {
		if ruleKey(existingRule) == key {
			r.Rules[i] = rule
			return true
		}
	}

	// Rule not found, add it
	r.Rules = append(r.Rules, rule)
	return false
}

// HasRule checks if a rule with the given ID exists
func (r *RuleCreatorImpl) HasRule(id string) bool {
	r.mutex.RLock()
	defer r.mutex.RUnlock()

	for _, rule := range r.Rules {
		if rule.ID == id {
			return true
		}
	}
	return false
}
