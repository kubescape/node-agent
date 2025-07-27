package rulemanager

import (
	"github.com/kubescape/node-agent/pkg/rulemanager/types"
)

type CELRuleEvaluator interface {
	EvaluateRule(event []byte, expressions []types.RuleExpression) (bool, error)
	EvaluateExpression(event []byte, expression string) (string, error)
}
