package ruleengine

import (
	"github.com/kubescape/node-agent/pkg/ruleengine"
	"github.com/kubescape/node-agent/pkg/utils"
)

var _ ruleengine.RuleCreator = (*RuleCreatorImpl)(nil)

type RuleCreatorImpl struct {
	RuleDescriptions []ruleengine.RuleDescriptor
}

func NewRuleCreator() *RuleCreatorImpl {
	return &RuleCreatorImpl{
		RuleDescriptions: []ruleengine.RuleDescriptor{
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
			R1015MaliciousPtraceUsageRuleDescriptor,
			R1030UnexpectedIouringOperationRuleDescriptor,
		},
	}
}

func (r *RuleCreatorImpl) CreateRulesByTags(tags []string) []ruleengine.RuleEvaluator {
	var rules []ruleengine.RuleEvaluator
	for _, rule := range r.RuleDescriptions {
		if rule.HasTags(tags) {
			rules = append(rules, rule.RuleCreationFunc())
		}
	}
	return rules
}

func (r *RuleCreatorImpl) CreateRuleByID(id string) ruleengine.RuleEvaluator {
	for _, rule := range r.RuleDescriptions {
		if rule.ID == id {
			return rule.RuleCreationFunc()
		}
	}
	return nil
}

func (r *RuleCreatorImpl) CreateRuleByName(name string) ruleengine.RuleEvaluator {
	for _, rule := range r.RuleDescriptions {
		if rule.Name == name {
			return rule.RuleCreationFunc()
		}
	}
	return nil
}

func (r *RuleCreatorImpl) GetAllRuleDescriptors() []ruleengine.RuleDescriptor {
	return r.RuleDescriptions
}

func (r *RuleCreatorImpl) RegisterRule(rule ruleengine.RuleDescriptor) {
	r.RuleDescriptions = append(r.RuleDescriptions, rule)
}

func (r *RuleCreatorImpl) CreateRulesByEventType(eventType utils.EventType) []ruleengine.RuleEvaluator {
	var rules []ruleengine.RuleEvaluator
	for _, rule := range r.RuleDescriptions {
		if containsEventType(rule.Requirements.RequiredEventTypes(), eventType) {
			rules = append(rules, rule.RuleCreationFunc())
		}
	}
	return rules
}
func (r *RuleCreatorImpl) GetAllRuleIDs() []string {
	var ruleIDs []string
	for _, rule := range r.RuleDescriptions {
		ruleIDs = append(ruleIDs, rule.ID)
	}
	return ruleIDs
}

func (r *RuleCreatorImpl) CreateAllRules() []ruleengine.RuleEvaluator {
	var rules []ruleengine.RuleEvaluator
	for _, rule := range r.RuleDescriptions {
		rules = append(rules, rule.RuleCreationFunc())
	}
	return rules
}

func containsEventType(eventTypes []utils.EventType, eventType utils.EventType) bool {
	for _, et := range eventTypes {
		if et == eventType {
			return true
		}
	}
	return false
}
