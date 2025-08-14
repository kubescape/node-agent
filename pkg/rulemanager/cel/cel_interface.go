package cel

import (
	"github.com/google/cel-go/cel"
	"github.com/kubescape/node-agent/pkg/ebpf/events"
	typesv1 "github.com/kubescape/node-agent/pkg/rulemanager/types/v1"
)

type CELRuleEvaluator interface {
	EvaluateRule(event *events.EnrichedEvent, expressions []typesv1.RuleExpression) (bool, error)
	EvaluateExpression(event *events.EnrichedEvent, expression string) (string, error)
	RegisterHelper(function cel.EnvOption) error
}
