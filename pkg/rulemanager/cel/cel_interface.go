package rulemanager

import (
	"encoding/json"

	"github.com/kubescape/node-agent/pkg/rulemanager"
)

type CELInterface interface {
	EvaluateRule(event json.Marshaler, expressions []rulemanager.RuleExpression) (bool, error)
	EvaluateExpression(event json.Marshaler, expression string) (string, error)
}

