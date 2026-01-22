package cel

import (
	"fmt"
	"sync"

	"github.com/google/cel-go/cel"
	"github.com/google/cel-go/ext"
	"github.com/kubescape/node-agent/pkg/config"
	"github.com/kubescape/node-agent/pkg/ebpf/events"
	"github.com/kubescape/node-agent/pkg/objectcache"
	"github.com/kubescape/node-agent/pkg/rulemanager/cel/libraries/applicationprofile"
	"github.com/kubescape/node-agent/pkg/rulemanager/cel/libraries/k8s"
	"github.com/kubescape/node-agent/pkg/rulemanager/cel/libraries/net"
	"github.com/kubescape/node-agent/pkg/rulemanager/cel/libraries/networkneighborhood"
	"github.com/kubescape/node-agent/pkg/rulemanager/cel/libraries/parse"
	"github.com/kubescape/node-agent/pkg/rulemanager/cel/libraries/process"
	typesv1 "github.com/kubescape/node-agent/pkg/rulemanager/types/v1"
	"github.com/kubescape/node-agent/pkg/utils"
	"github.com/picatz/xcel"
)

var _ CELRuleEvaluator = (*CEL)(nil)

type CEL struct {
	env             *cel.Env
	objectCache     objectcache.ObjectCache
	programCache    map[string]cel.Program
	cacheMutex      sync.RWMutex
	typeMutex       sync.RWMutex
	evalContextPool sync.Pool
	ta              xcel.TypeAdapter
	tp              *xcel.TypeProvider
}

func NewCEL(objectCache objectcache.ObjectCache, cfg config.Config) (*CEL, error) {
	ta, tp := xcel.NewTypeAdapter(), xcel.NewTypeProvider()
	eventObj, eventTyp := xcel.NewObject(&utils.CelEventImpl{})
	xcel.RegisterObject(ta, tp, eventObj, eventTyp, utils.CelFields)
	procObj, procTyp := xcel.NewObject(&events.ProcfsEvent{})
	xcel.RegisterObject(ta, tp, procObj, procTyp, xcel.NewFields(procObj))
	envOptions := []cel.EnvOption{
		cel.Variable("event", eventTyp),
		cel.Variable("eventType", cel.StringType),
		cel.Variable(string(utils.ProcfsEventType), procTyp),
		cel.Variable(string(utils.HTTPEventType), cel.AnyType),
		cel.CustomTypeAdapter(ta),
		cel.CustomTypeProvider(tp),
		ext.Strings(),
		k8s.K8s(objectCache.K8sObjectCache(), cfg),
		applicationprofile.AP(objectCache, cfg),
		networkneighborhood.NN(objectCache, cfg),
		parse.Parse(cfg),
		net.Net(cfg),
		process.Process(cfg),
	}

	env, err := cel.NewEnv(envOptions...)
	if err != nil {
		return nil, err
	}
	c := &CEL{
		env:          env,
		objectCache:  objectCache,
		programCache: make(map[string]cel.Program),
		ta:           ta,
		tp:           tp,
	}

	c.evalContextPool.New = func() interface{} {
		return make(map[string]any, 2)
	}

	return c, nil
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

func (c *CEL) EvaluateRule(event *events.EnrichedEvent, expressions []typesv1.RuleExpression) (bool, error) {
	obj, _ := xcel.NewObject(event.Event.(utils.CelEvent)) // FIXME put safety check here
	eventType := event.Event.GetEventType()
	input := map[string]any{"event": obj, "eventType": string(eventType)}

	for _, expression := range expressions {
		if expression.EventType != eventType {
			continue
		}

		program, err := c.getOrCreateProgram(expression.Expression)
		if err != nil {
			return false, err
		}
		out, _, err := program.Eval(input)
		if err != nil {
			return false, err
		}

		if !out.Value().(bool) {
			return false, nil
		}
	}

	return true, nil
}

func (c *CEL) EvaluateRuleByMap(event any, eventType utils.EventType, expressions []typesv1.RuleExpression) (bool, error) {
	// Get evaluation context map from pool to reduce allocations
	evalContext := c.evalContextPool.Get().(map[string]any)
	defer func() {
		// Clear and return to pool
		clear(evalContext)
		c.evalContextPool.Put(evalContext)
	}()

	evalContext[string(eventType)] = event
	evalContext["eventType"] = string(eventType)

	for _, expression := range expressions {
		if expression.EventType != eventType {
			continue
		}

		program, err := c.getOrCreateProgram(expression.Expression)
		if err != nil {
			return false, err
		}

		out, _, err := program.Eval(evalContext)
		if err != nil {
			return false, err
		}

		if !out.Value().(bool) {
			return false, nil
		}
	}

	return true, nil
}

func (c *CEL) EvaluateExpressionByMap(event any, expression string, eventType utils.EventType) (string, error) {
	program, err := c.getOrCreateProgram(expression)
	if err != nil {
		return "", err
	}

	// Get evaluation context map from pool to reduce allocations
	evalContext := c.evalContextPool.Get().(map[string]any)
	defer func() {
		// Clear and return to pool
		clear(evalContext)
		c.evalContextPool.Put(evalContext)
	}()

	evalContext[string(eventType)] = event
	evalContext["eventType"] = string(eventType)

	out, _, err := program.Eval(evalContext)
	if err != nil {
		return "", fmt.Errorf("failed to evaluate expression: %s", err)
	}

	return out.Value().(string), nil
}

func (c *CEL) EvaluateExpression(event *events.EnrichedEvent, expression string) (string, error) {
	program, err := c.getOrCreateProgram(expression)
	if err != nil {
		return "", err
	}

	obj, _ := xcel.NewObject(event.Event.(utils.CelEvent)) // FIXME put safety check here
	out, _, err := program.Eval(map[string]any{"event": obj, "eventType": string(event.Event.GetEventType())})
	if err != nil {
		return "", err
	}

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

func (c *CEL) RegisterCustomType(eventType utils.EventType, obj interface{}) error {
	c.typeMutex.Lock()
	defer c.typeMutex.Unlock()

	// Create new object and type using xcel
	xcelObj, xcelTyp := xcel.NewObject(obj)

	// Register the new object with the existing type adapter/provider
	xcel.RegisterObject(c.ta, c.tp, xcelObj, xcelTyp, xcel.NewFields(xcelObj))

	// Extend the environment with the new variable
	// This preserves all existing types while adding the new one
	extendedEnv, err := c.env.Extend(
		cel.Variable(string(eventType), xcelTyp),
	)
	if err != nil {
		return fmt.Errorf("failed to extend environment with custom type: %w", err)
	}

	c.env = extendedEnv

	// Clear program cache since environment has changed
	c.cacheMutex.Lock()
	c.programCache = make(map[string]cel.Program)
	c.cacheMutex.Unlock()

	return nil
}
