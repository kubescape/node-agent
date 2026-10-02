package types

import (
	"github.com/armosec/armoapi-go/armotypes"
	"github.com/kubescape/node-agent/pkg/rulemanager/prefilter"
	"github.com/kubescape/node-agent/pkg/utils"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

type Rules struct {
	metav1.TypeMeta   `json:",inline"`
	metav1.ObjectMeta `json:"metadata"`

	Spec RulesSpec `json:"spec"`
}

type RulesSpec struct {
	Rules []Rule `json:"rules" yaml:"rules"`
}

type Rule struct {
	Enabled                 bool                        `json:"enabled" yaml:"enabled"`
	ID                      string                      `json:"id" yaml:"id"`
	Name                    string                      `json:"name" yaml:"name"`
	Description             string                      `json:"description" yaml:"description"`
	Expressions             RuleExpressions             `json:"expressions" yaml:"expressions"`
	ProfileDependency       armotypes.ProfileDependency `json:"profileDependency" yaml:"profileDependency"`
	ProfileDataRequired     *ProfileDataRequired        `json:"profileDataRequired,omitempty" yaml:"profileDataRequired,omitempty"`
	Severity                int                         `json:"severity" yaml:"severity"`
	SupportPolicy           bool                        `json:"supportPolicy" yaml:"supportPolicy"`
	Tags                    []string                    `json:"tags" yaml:"tags"`
	State                   map[string]any              `json:"state,omitempty" yaml:"state,omitempty"`
	AgentVersionRequirement string                      `json:"agentVersionRequirement" yaml:"agentVersionRequirement"`
	IsTriggerAlert          bool                        `json:"isTriggerAlert" yaml:"isTriggerAlert"`
	MitreTactic             string                      `json:"mitreTactic" yaml:"mitreTactic"`
	MitreTechnique          string                      `json:"mitreTechnique" yaml:"mitreTechnique"`
	Prefilter               *prefilter.Params           `json:"-" yaml:"-"`

	// Provenance of the rule, established by the rules watcher after the
	// carrying Rules object was admitted. Bundle is the SIGNED bundle the
	// admitted overlay fragment belongs to — the same bundle its ContainerProfile
	// half carries — so the rule applies to exactly the workloads that opted into
	// that bundle via the kubescape.io/user-defined-profile pod label, in any
	// namespace. ClusterWide marks a rule from a base fragment, which applies to
	// every workload and belongs to no bundle. Both bundle membership and the
	// fragment class are signed, so an installer can neither re-target an overlay
	// nor promote it to cluster-wide.
	//
	// These MUST stay json:"-" / yaml:"-": Rule is inside RulesSpec, which IS
	// the signed content, so making them serialisable would change every
	// existing content hash and invalidate every existing signature.
	Bundle      string `json:"-" yaml:"-"`
	ClusterWide bool   `json:"-" yaml:"-"`
}

type RuleExpressions struct {
	Message        string           `json:"message" yaml:"message"`
	UniqueID       string           `json:"uniqueId" yaml:"uniqueId"`
	RuleExpression []RuleExpression `json:"ruleExpression" yaml:"ruleExpression"`
}

type RuleExpression struct {
	EventType  utils.EventType `json:"eventType" yaml:"eventType"`
	Expression string          `json:"expression" yaml:"expression"`
}
