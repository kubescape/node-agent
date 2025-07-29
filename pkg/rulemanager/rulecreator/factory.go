package rulecreator

import (
	"slices"
	"sync"

	typesv1 "github.com/kubescape/node-agent/pkg/rulemanager/types/v1"
	"github.com/kubescape/node-agent/pkg/utils"
)

var _ RuleCreator = (*RuleCreatorImpl)(nil)

type RuleCreatorImpl struct {
	mutex sync.RWMutex
	Rules []typesv1.RuleSpec
}

func NewRuleCreator() *RuleCreatorImpl {
	return &RuleCreatorImpl{}
}

func (r *RuleCreatorImpl) CreateRulesByTags(tags []string) []typesv1.RuleSpec {
	var rules []typesv1.RuleSpec
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

func (r *RuleCreatorImpl) CreateRuleByID(id string) typesv1.RuleSpec {
	for _, rule := range r.Rules {
		if rule.ID == id {
			return rule
		}
	}
	return typesv1.RuleSpec{}
}

func (r *RuleCreatorImpl) CreateRuleByName(name string) typesv1.RuleSpec {
	for _, rule := range r.Rules {
		if rule.Name == name {
			return rule
		}
	}
	return typesv1.RuleSpec{}
}

func (r *RuleCreatorImpl) RegisterRule(rule typesv1.RuleSpec) {
	r.Rules = append(r.Rules, rule)
}

func (r *RuleCreatorImpl) CreateRulesByEventType(eventType utils.EventType) []typesv1.RuleSpec {
	var rules []typesv1.RuleSpec
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

func (r *RuleCreatorImpl) CreateRulePolicyRulesByEventType(eventType utils.EventType) []typesv1.RuleSpec {
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

	var ruleIDs []string
	for _, rule := range r.Rules {
		ruleIDs = append(ruleIDs, rule.ID)
	}
	return ruleIDs
}

func (r *RuleCreatorImpl) CreateAllRules() []typesv1.RuleSpec {
	var rules []typesv1.RuleSpec
	for _, rule := range r.Rules {
		rules = append(rules, rule)
	}
	return rules
}

// SyncRules replaces the current rules with the new set of rules
// It removes rules that are no longer present and adds/updates existing ones
func (r *RuleCreatorImpl) SyncRules(newRules []typesv1.RuleSpec) {
	r.mutex.Lock()
	defer r.mutex.Unlock()

	// Create a map of new rules by ID for quick lookup
	newRuleMap := make(map[string]typesv1.RuleSpec)
	for _, rule := range newRules {
		newRuleMap[rule.ID] = rule
	}

	// Remove rules that are no longer present
	var updatedRules []typesv1.RuleSpec
	for _, existingRule := range r.Rules {
		if newRule, exists := newRuleMap[existingRule.ID]; exists {
			// Rule still exists, use the new version
			updatedRules = append(updatedRules, newRule)
			delete(newRuleMap, existingRule.ID) // Mark as processed
		}
		// If rule doesn't exist in newRuleMap, it's removed (not added to updatedRules)
	}

	// Add any completely new rules
	for _, newRule := range newRuleMap {
		updatedRules = append(updatedRules, newRule)
	}

	r.Rules = updatedRules
}

// RemoveRuleByID removes a rule with the given ID and returns true if found
func (r *RuleCreatorImpl) RemoveRuleByID(id string) bool {
	r.mutex.Lock()
	defer r.mutex.Unlock()

	for i, rule := range r.Rules {
		if rule.ID == id {
			// Remove the rule by slicing
			r.Rules = append(r.Rules[:i], r.Rules[i+1:]...)
			return true
		}
	}
	return false
}

// UpdateRule updates an existing rule or adds it if it doesn't exist
func (r *RuleCreatorImpl) UpdateRule(rule typesv1.RuleSpec) bool {
	r.mutex.Lock()
	defer r.mutex.Unlock()

	for i, existingRule := range r.Rules {
		if existingRule.ID == rule.ID {
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

func containsEventType(eventTypes []utils.EventType, eventType utils.EventType) bool {
	for _, et := range eventTypes {
		if et == eventType {
			return true
		}
	}
	return false
}
