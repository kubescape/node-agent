package rulecreator

import (
	typesv1 "github.com/kubescape/node-agent/pkg/rulemanager/types/v1"
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
	CreateRulesByTags(tags []string) []typesv1.Rule
	CreateRuleByID(id string) typesv1.Rule
	CreateRuleByName(name string) typesv1.Rule
	RegisterRule(rule typesv1.Rule)
	CreateRulesByEventType(eventType utils.EventType) []typesv1.Rule
	CreateRulePolicyRulesByEventType(eventType utils.EventType) []typesv1.Rule
	CreateAllRules() []typesv1.Rule
	GetAllRuleIDs() []string
}
