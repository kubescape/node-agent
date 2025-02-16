package hostrules

import (
	"github.com/kubescape/node-agent/pkg/ruleengine"
	ruleenginev1 "github.com/kubescape/node-agent/pkg/ruleengine/v1"
)

func NewRuleCreator() *ruleenginev1.RuleCreatorImpl {
	return &ruleenginev1.RuleCreatorImpl{
		RuleDescriptions: []ruleengine.RuleDescriptor{
			ruleenginev1.R0008ReadEnvironmentVariablesProcFSRuleDescriptor,
			ruleenginev1.R0010UnexpectedSensitiveFileAccessRuleDescriptor,
			ruleenginev1.R1003MaliciousSSHConnectionRuleDescriptor,
			ruleenginev1.R1010SymlinkCreatedOverSensitiveFileRuleDescriptor,
			ruleenginev1.R1012HardlinkCreatedOverSensitiveFileRuleDescriptor,
			ruleenginev1.R1000ExecFromMaliciousSourceDescriptor,
			ruleenginev1.R1002LoadKernelModuleRuleDescriptor,
			ruleenginev1.R1005FilelessExecutionRuleDescriptor,
			ruleenginev1.R1007XMRCryptoMiningRuleDescriptor,
			ruleenginev1.R1008CryptoMiningDomainCommunicationRuleDescriptor,
			ruleenginev1.R1015MaliciousPtraceUsageRuleDescriptor,
			ruleenginev1.R1030UnexpectedIouringOperationRuleDescriptor,
		},
	}
}
