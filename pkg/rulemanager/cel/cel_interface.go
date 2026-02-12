package cel

import (
	"github.com/google/cel-go/cel"
	"github.com/kubescape/node-agent/pkg/ebpf/events"
	typesv1 "github.com/kubescape/node-agent/pkg/rulemanager/types/v1"
	"github.com/kubescape/node-agent/pkg/utils"
)

type RuleEvaluator interface {
	EvaluateRule(event *events.EnrichedEvent, expressions []typesv1.RuleExpression) (bool, error)
	EvaluateExpression(event *events.EnrichedEvent, expression string) (string, error)
	RegisterHelper(function cel.EnvOption) error
	RegisterCustomType(eventType utils.EventType, obj interface{}) error
	RegisterEventConverter(eventType utils.EventType, converter func(utils.K8sEvent) utils.K8sEvent)

	// Context-aware variants — create the eval context once and reuse across multiple evaluations
	CreateEvalContext(event *events.EnrichedEvent) map[string]any
	EvaluateRuleWithContext(evalContext map[string]any, expressions []typesv1.RuleExpression) (bool, error)
	EvaluateExpressionWithContext(evalContext map[string]any, expression string) (string, error)
}
