package cel

import (
	"encoding/json"

	"github.com/google/cel-go/cel"
	"github.com/kubescape/node-agent/pkg/rulemanager/types"
)

type CELRuleEvaluator interface {
	EvaluateRule(event []byte, expressions []types.RuleExpression) (bool, error)
	EvaluateExpression(event []byte, expression string) (string, error)

	RegisterHelper(function cel.EnvOption) error
}
