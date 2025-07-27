package cel

import (
	"encoding/json"
	"fmt"

	"github.com/google/cel-go/cel"
	"github.com/kubescape/go-logger"
	"github.com/kubescape/go-logger/helpers"
	"github.com/kubescape/node-agent/pkg/objectcache"
	"github.com/kubescape/node-agent/pkg/rulemanager/cel/library"
	"github.com/kubescape/node-agent/pkg/rulemanager/types"
)

var _ CELRuleEvaluator = (*CEL)(nil)

type CEL struct {
	env         *cel.Env
	objectCache objectcache.ObjectCache
}

func NewCEL(objectCache objectcache.ObjectCache) (*CEL, error) {
	env, err := cel.NewEnv(
		cel.Variable("event", cel.AnyType),
		library.K8s(objectCache.K8sObjectCache()),
	)
	if err != nil {
		return nil, err
	}
	return &CEL{env: env, objectCache: objectCache}, nil
}

func (c *CEL) EvaluateRule(event json.Marshaler, expressions []types.RuleExpression) (bool, error) {
	for _, expression := range expressions {
		ast, issues := c.env.Compile(expression.Expression)
		if issues != nil {
			return false, fmt.Errorf("failed to compile expression: %s", issues.Err())
		}

		program, err := c.env.Program(ast)
		if err != nil {
			return false, fmt.Errorf("failed to create program: %s", err)
		}

		eventBytes, err := event.MarshalJSON()
		if err != nil {
			return false, fmt.Errorf("failed to marshal event: %s", err)
		}

		out, _, err := program.Eval(map[string]any{
			"event": eventBytes,
		})
		if err != nil {
			logger.L().Error("evaluation error", helpers.Error(err))
		}

		if !out.Value().(bool) {
			return false, nil
		}

		// TODO: remove this.
		logger.L().Debug("evaluation result", helpers.Interface("result", out))
	}

	return true, nil
}

func (c *CEL) EvaluateExpression(event json.Marshaler, expression string) (string, error) {
	ast, issues := c.env.Compile(expression)
	if issues != nil {
		return "", fmt.Errorf("failed to compile expression: %s", issues.Err())
	}

	program, err := c.env.Program(ast)
	if err != nil {
		return "", fmt.Errorf("failed to create program: %s", err)
	}

	eventBytes, err := event.MarshalJSON()
	if err != nil {
		return "", fmt.Errorf("failed to marshal event: %s", err)
	}

	out, _, err := program.Eval(map[string]any{
		"event": eventBytes,
	})
	if err != nil {
		return "", fmt.Errorf("failed to evaluate expression: %s", err)
	}

	logger.L().Debug("evaluation result", helpers.Interface("result", out))

	return out.Value().(string), nil
}

func (c *CEL) RegisterHelper(function cel.EnvOption) error {
	extendedEnv, err := c.env.Extend(function)
	if err != nil {
		return err
	}
	c.env = extendedEnv
	return nil
}
