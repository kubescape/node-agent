package rulemanager

import (
	"encoding/json"

	"github.com/kubescape/node-agent/pkg/rulemanager/types"
)

type CELRuleEvaluator interface {
	EvaluateRule(event json.Marshaler, expressions []types.RuleExpression) (bool, error)
	EvaluateExpression(event json.Marshaler, expression string) (string, error)
}
