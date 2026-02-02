package cel

import (
	"fmt"
	"sync"

	"github.com/google/cel-go/cel"
	"github.com/google/cel-go/common/types/ref"
	"github.com/google/cel-go/ext"
	"github.com/kubescape/go-logger"
	"github.com/kubescape/go-logger/helpers"
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

var _ RuleEvaluator = (*CEL)(nil)

type CEL struct {
	env             *cel.Env
	objectCache     objectcache.ObjectCache
	programCache    map[string]cel.Program
	cacheMutex      sync.RWMutex
	typeMutex       sync.RWMutex
	ta              xcel.TypeAdapter
	tp              *xcel.TypeProvider
	eventConverters map[utils.EventType]func(utils.K8sEvent) utils.K8sEvent
}

func NewCEL(objectCache objectcache.ObjectCache, cfg config.Config) (*CEL, error) {
	ta, tp := xcel.NewTypeAdapter(), xcel.NewTypeProvider()

	eventObj, eventTyp := xcel.NewObject(&utils.CelEventImpl{})
	xcel.RegisterObject(ta, tp, eventObj, eventTyp, utils.CelFields)

	envOptions := []cel.EnvOption{
		cel.Variable("event", eventTyp), // All events accessible via "event" variable
		cel.Variable("eventType", cel.StringType),
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
		env:             env,
		objectCache:     objectCache,
		programCache:    make(map[string]cel.Program),
		ta:              ta,
		tp:              tp,
		eventConverters: make(map[utils.EventType]func(utils.K8sEvent) utils.K8sEvent),
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
		// Cache nil to prevent repeated compilation attempts for invalid expressions
		c.programCache[expression] = nil
		logger.L().Warning("CEL expression disabled: failed to compile", helpers.String("expression", expression), helpers.Error(issues.Err()))
		return fmt.Errorf("failed to compile expression: %s", issues.Err())
	}

	program, err := c.env.Program(ast, cel.EvalOptions(cel.OptOptimize))
	if err != nil {
		// Cache nil to prevent repeated program creation attempts
		c.programCache[expression] = nil
		logger.L().Warning("CEL expression disabled: failed to create program", helpers.String("expression", expression), helpers.Error(err))
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

func (c *CEL) createEvalContext(event *events.EnrichedEvent) map[string]any {
	eventType := event.Event.GetEventType()

	// Apply event converter if one is registered, otherwise cast to CelEvent
	var obj interface{}
	if converter, exists := c.eventConverters[eventType]; exists {
		obj, _ = xcel.NewObject(converter(event.Event))
	} else {
		obj, _ = xcel.NewObject(event.Event.(utils.CelEvent))
	}

	evalContext := map[string]any{
		"eventType": string(eventType),
		"event":     obj,
	}

	// For HTTP events, also add "http" variable
	if eventType == utils.HTTPEventType {
		evalContext["http"] = obj
	}

	return evalContext
}

// evaluateProgramWithContext compiles (or retrieves cached) and evaluates a CEL expression
// with the provided evaluation context, returning the CEL result value
func (c *CEL) evaluateProgramWithContext(expression string, evalContext map[string]any) (ref.Val, error) {
	program, err := c.getOrCreateProgram(expression)
	if err != nil {
		return nil, err
	}
	// Check if program is nil (compilation failed previously)
	if program == nil {
		return nil, nil
	}

	out, _, err := program.Eval(evalContext)
	if err != nil {
		// Do not cache nil on evaluation errors - these may be transient issues
		// with specific event data rather than problems with the expression itself.
		// Only compilation failures are cached as nil to prevent recompilation.
		return nil, err
	}

	return out, nil
}

func (c *CEL) EvaluateRule(event *events.EnrichedEvent, expressions []typesv1.RuleExpression) (bool, error) {
	eventType := event.Event.GetEventType()
	evalContext := c.createEvalContext(event)

	for _, expression := range expressions {
		if expression.EventType != eventType {
			continue
		}

		out, err := c.evaluateProgramWithContext(expression.Expression, evalContext)
		if err != nil {
			return false, err
		}

		// Skip if program compilation failed (cached as nil)
		if out == nil {
			continue
		}

		boolVal, ok := out.Value().(bool)
		if !ok {
			return false, fmt.Errorf("rule expression returned %T, expected bool", out.Value())
		}
		if !boolVal {
			return false, nil
		}
	}

	return true, nil
}

func (c *CEL) EvaluateExpression(event *events.EnrichedEvent, expression string) (string, error) {
	evalContext := c.createEvalContext(event)

	out, err := c.evaluateProgramWithContext(expression, evalContext)
	if err != nil {
		return "", err
	}

	// Return empty string if program compilation failed (cached as nil)
	if out == nil {
		return "", nil
	}

	strVal, ok := out.Value().(string)
	if !ok {
		return "", fmt.Errorf("expression returned %T, expected string", out.Value())
	}
	return strVal, nil
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

func (c *CEL) RegisterEventConverter(eventType utils.EventType, converter func(utils.K8sEvent) utils.K8sEvent) {
	c.eventConverters[eventType] = converter
}
