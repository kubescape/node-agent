package cel

import (
	"github.com/google/cel-go/cel"
	typesv1 "github.com/kubescape/node-agent/pkg/rulemanager/types/v1"
)

type CELRuleEvaluator interface {
	EvaluateRule(event map[string][]byte, expressions []typesv1.RuleExpression) (bool, error)
	EvaluateExpression(event map[string][]byte, expression string) (string, error)

	RegisterHelper(function cel.EnvOption) error
}
