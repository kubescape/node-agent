package cel

import (
	"encoding/json"

	"github.com/google/cel-go/cel"
	typesv1 "github.com/kubescape/node-agent/pkg/rulemanager/types/v1"
)

type CELRuleEvaluator interface {
	EvaluateRule(event json.RawMessage, expressions []typesv1.RuleExpression) (bool, error)
	EvaluateExpression(event json.RawMessage, expression string) (string, error)

	RegisterHelper(function cel.EnvOption) error
}
