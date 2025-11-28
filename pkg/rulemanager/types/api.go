package types

const (
	RuleGroup  string = "kubescape.io"
	RuleKind   string = "Rule"
	RulePlural string = "rules"
)

type Enricher interface {
	EnrichRuleFailure(rule RuleFailure) error
}
