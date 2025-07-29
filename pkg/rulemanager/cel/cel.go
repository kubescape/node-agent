package cel

import (
	"encoding/json"
	"fmt"
	"sync"

	"github.com/google/cel-go/cel"
	"github.com/kubescape/go-logger"
	"github.com/kubescape/go-logger/helpers"
	"github.com/kubescape/node-agent/pkg/objectcache"
	"github.com/kubescape/node-agent/pkg/rulemanager/cel/library"
	typesv1 "github.com/kubescape/node-agent/pkg/rulemanager/types/v1"
)

var _ CELRuleEvaluator = (*CEL)(nil)

type CEL struct {
	env          *cel.Env
	objectCache  objectcache.ObjectCache
	programCache map[string]cel.Program
	cacheMutex   sync.RWMutex
}

func NewCEL(objectCache objectcache.ObjectCache) (*CEL, error) {
	env, err := cel.NewEnv(
		cel.Variable("event", cel.AnyType),
		library.K8s(objectCache.K8sObjectCache()),
	)
	if err != nil {
		return nil, err
	}
	return &CEL{
		env:          env,
		objectCache:  objectCache,
		programCache: make(map[string]cel.Program),
	}, nil
}

func (c *CEL) registerExpression(expression string) error {
	c.cacheMutex.Lock()
	defer c.cacheMutex.Unlock()

	// Check if already compiled
	if _, exists := c.programCache[expression]; exists {
		return nil
	}

	ast, issues := c.env.Compile(expression)
	if issues != nil {
		return fmt.Errorf("failed to compile expression: %s", issues.Err())
	}

	program, err := c.env.Program(ast, cel.EvalOptions(cel.OptOptimize))
	if err != nil {
		return fmt.Errorf("failed to create program: %s", err)
	}

	c.programCache[expression] = program
	return nil
}

func (c *CEL) getOrCreateProgram(expression string) (cel.Program, error) {
	c.cacheMutex.RLock()
	if program, exists := c.programCache[expression]; exists {
		c.cacheMutex.RUnlock()
		return program, nil
	}
	c.cacheMutex.RUnlock()

	// If not in cache, compile and cache it
	if err := c.registerExpression(expression); err != nil {
		return nil, err
	}

	c.cacheMutex.RLock()
	program := c.programCache[expression]
	c.cacheMutex.RUnlock()
	return program, nil
}

func (c *CEL) EvaluateRule(event json.RawMessage, expressions []typesv1.RuleExpression) (bool, error) {
	for _, expression := range expressions {
		program, err := c.getOrCreateProgram(expression.Expression)
		if err != nil {
			return false, err
		}

		// Convert event to map[string]any
		var eventMap map[string]any
		if err := json.Unmarshal(event, &eventMap); err != nil {
			return false, fmt.Errorf("failed to unmarshal event: %s", err)
		}

		out, _, err := program.Eval(map[string]any{"data": eventMap})
		if err != nil {
			logger.L().Error("evaluation error", helpers.Error(err))
		}

		if !out.Value().(bool) {
			return false, nil
		}

		logger.L().Debug("evaluation result", helpers.Interface("result", out.Value().(bool)))
	}

	return true, nil
}

func (c *CEL) EvaluateExpression(event json.RawMessage, expression string) (string, error) {
	program, err := c.getOrCreateProgram(expression)
	if err != nil {
		return "", err
	}

	// Convert event to map[string]any
	var eventMap map[string]any
	if err := json.Unmarshal(event, &eventMap); err != nil {
		return "", fmt.Errorf("failed to unmarshal event: %s", err)
	}

	out, _, err := program.Eval(map[string]any{"data": eventMap})
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
