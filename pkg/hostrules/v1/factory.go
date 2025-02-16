package hostrules

import (
	"github.com/kubescape/node-agent/pkg/ruleengine"
	ruleenginev1 "github.com/kubescape/node-agent/pkg/ruleengine/v1"
)

func NewRuleCreator() *ruleenginev1.RuleCreatorImpl {
	return &ruleenginev1.RuleCreatorImpl{
		RuleDescriptions: []ruleengine.RuleDescriptor{
			ruleenginev1.R1000ExecFromMaliciousSourceDescriptor,
			ruleenginev1.R1002LoadKernelModuleRuleDescriptor,
			ruleenginev1.R1005FilelessExecutionRuleDescriptor,
			ruleenginev1.R1007XMRCryptoMiningRuleDescriptor,
			ruleenginev1.R1008CryptoMiningDomainCommunicationRuleDescriptor,
			ruleenginev1.R1015MaliciousPtraceUsageRuleDescriptor,
			R3001UnexpectedProcessLaunchedRuleDescriptor,
			R3002CGroupsReleaseAgentModifiedRuleDescriptor,
			R3003SuspiciousToolRuleDescriptor,
			R3004DockerSocketAccessRuleDescriptor,
			R3005MaliciousFsMemoryInjectionRuleDescriptor,
		},
	}
}
