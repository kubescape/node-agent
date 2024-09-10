package ruleengine

import "github.com/kubescape/node-agent/pkg/ruleengine"

var _ ruleengine.RuleCreator = (*RuleCreatorImpl)(nil)

type RuleCreatorImpl struct {
	ruleDescriptions []RuleDescriptor
}

func NewRuleCreator() *RuleCreatorImpl {
	return &RuleCreatorImpl{
		ruleDescriptions: []RuleDescriptor{
			R0001UnexpectedProcessLaunchedRuleDescriptor,
			R0002UnexpectedFileAccessRuleDescriptor,
			R0003UnexpectedSystemCallRuleDescriptor,
			R0004UnexpectedCapabilityUsedRuleDescriptor,
			R0005UnexpectedDomainRequestRuleDescriptor,
			R0006UnexpectedServiceAccountTokenAccessRuleDescriptor,
			R0007KubernetesClientExecutedDescriptor,
			R0008ReadEnvironmentVariablesProcFSRuleDescriptor,
			R0009EbpfProgramLoadRuleDescriptor,
			R0010UnexpectedSensitiveFileAccessRuleDescriptor,
			R0011UnexpectedEgressNetworkTrafficRuleDescriptor,
			R1000ExecFromMaliciousSourceDescriptor,
			R1001ExecBinaryNotInBaseImageRuleDescriptor,
			R1002LoadKernelModuleRuleDescriptor,
			R1003MaliciousSSHConnectionRuleDescriptor,
			R1004ExecFromMountRuleDescriptor,
			R1005FilelessExecutionRuleDescriptor,
			R1006UnshareSyscallRuleDescriptor,
			R1007XMRCryptoMiningRuleDescriptor,
			R1008CryptoMiningDomainCommunicationRuleDescriptor,
			R1009CryptoMiningRelatedPortRuleDescriptor,
			R1010SymlinkCreatedOverSensitiveFileRuleDescriptor,
			R1011LdPreloadHookRuleDescriptor,
			R1012HardlinkCreatedOverSensitiveFileRuleDescriptor,
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

func (r *RuleCreatorImpl) AddRuleDescriptor(rule RuleDescriptor) {
	r.ruleDescriptions = append(r.ruleDescriptions, rule)
}
