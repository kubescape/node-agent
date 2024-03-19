package ruleengine

import "node-agent/pkg/ruleengine"

var _ ruleengine.RuleCreator = (*RuleCreatorImpl)(nil)

type RuleCreatorImpl struct {
	ruleDescriptions []RuleDescriptor
}

func NewRuleCreator() *RuleCreatorImpl {
	return &RuleCreatorImpl{
		ruleDescriptions: []RuleDescriptor{
			R0001UnexpectedProcessLaunchedRuleDescriptor,
			R0002UnexpectedFileAccessRuleDescriptor,
			// R0003UnexpectedSystemCallRuleDescriptor,
			// R0004UnexpectedCapabilityUsedRuleDescriptor,
			// R0005UnexpectedDomainRequestRuleDescriptor,
			// R0006UnexpectedServiceAccountTokenAccessRuleDescriptor,
			// R0007KubernetesClientExecutedDescriptor,
			R1000ExecFromMaliciousSourceDescriptor,
			// R1001ExecBinaryNotInBaseImageRuleDescriptor,
			// R1002LoadKernelModuleRuleDescriptor,
			// R1003MaliciousSSHConnectionRuleDescriptor,
			// R1004ExecFromMountRuleDescriptor,
			// R1006UnshareSyscallRuleDescriptor,
			// R1007CryptoMinersRuleDescriptor,
		},
	}
}
func (r *RuleCreatorImpl) CreateRulesByTags(tags []string) []ruleengine.RuleEvaluator {
	var rules []ruleengine.RuleEvaluator
	for _, rule := range r.ruleDescriptions {
		if rule.HasTags(tags) {
			rules = append(rules, rule.RuleCreationFunc())
		}
	}
	return rules
}
func (r *RuleCreatorImpl) CreateRuleByID(id string) ruleengine.RuleEvaluator {
	for _, rule := range r.ruleDescriptions {
		if rule.ID == id {
			return rule.RuleCreationFunc()
		}
	}
	return nil
}

func (r *RuleCreatorImpl) CreateRuleByName(name string) ruleengine.RuleEvaluator {
	for _, rule := range r.ruleDescriptions {
		if rule.Name == name {
			return rule.RuleCreationFunc()
		}
	}
	return nil
}

func (r *RuleCreatorImpl) GetAllRuleDescriptors() []RuleDescriptor {
	return r.ruleDescriptions
}
