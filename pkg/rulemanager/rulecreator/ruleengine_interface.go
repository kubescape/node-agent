package rulecreator

import (
	"github.com/kubescape/node-agent/pkg/rulemanager/types"
	"github.com/kubescape/node-agent/pkg/utils"

	apitypes "github.com/armosec/armoapi-go/armotypes"
)

// ProfileRequirement indicates how a rule uses profiles
type ProfileRequirement struct {
	// ProfileDependency indicates if the rule requires a profile
	ProfileDependency apitypes.ProfileDependency

	// ProfileType indicates what type of profile is needed (Application, Network, etc)
	ProfileType apitypes.ProfileType
}

// RuleCreator is an interface for creating rules by tags, IDs, and names
type RuleCreator interface {
	CreateRulesByTags(tags []string) []types.Rule
	CreateRuleByID(id string) types.Rule
	CreateRuleByName(name string) types.Rule
	RegisterRule(rule types.Rule)
	CreateRulesByEventType(eventType utils.EventType) []types.Rule
	CreateRulePolicyRulesByEventType(eventType utils.EventType) []types.Rule
	CreateAllRules() []types.Rule
	GetAllRuleIDs() []string
}
