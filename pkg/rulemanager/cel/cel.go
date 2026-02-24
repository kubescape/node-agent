package cel

import (
	"fmt"
	"sync"

	"github.com/google/cel-go/cel"
	"github.com/google/cel-go/common/types/ref"
	"github.com/google/cel-go/ext"
	"github.com/google/cel-go/interpreter"
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

// EventActivation implements interpreter.Activation for zero-allocation CEL evaluation.
type EventActivation struct {
	eventType string
	event     *xcel.Object[utils.CelEvent]
	isHTTP    bool
}

var eventActivationPool = sync.Pool{
	New: func() any { return &EventActivation{} },
}

var objectPool = sync.Pool{
	New: func() any { return &xcel.Object[utils.CelEvent]{} },
}

func (a *EventActivation) ResolveName(name string) (any, bool) {
	switch name {
	case "event":
		return a.event, true
	case "eventType":
		return a.eventType, true
	case "http":
		if a.isHTTP {
			return a.event, true
		}
		return nil, false
	}
	return nil, false
}

func (a *EventActivation) Parent() interpreter.Activation { return nil }

// Release returns the activation and its wrapped object to their pools.
func (a *EventActivation) Release() {
	a.event.Raw = nil
	objectPool.Put(a.event)
	a.event = nil
	a.eventType = ""
	a.isHTTP = false
	eventActivationPool.Put(a)
}

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

	// Register the nested request accessor type
	requestObj, requestTyp := xcel.NewObject(utils.HttpRequestAccessor{})
	xcel.RegisterObject(ta, tp, requestObj, requestTyp, utils.HttpRequestFields)

	// Set the request field's type now that requestTyp is available
	utils.CelFields["request"].Type = requestTyp

	envOptions := []cel.EnvOption{
		cel.Variable("event", eventTyp), // All events accessible via "event" variable
		cel.Variable("http", eventTyp),  // HTTP events also accessible via "http" variable
		cel.Variable("eventType", cel.StringType),
		cel.CustomTypeAdapter(ta),
		cel.CustomTypeProvider(tp),
		ext.Strings(),
		ext.Bindings(),
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

func (c *CEL) CreateEvalContext(event utils.K8sEvent) *EventActivation {
	eventType := event.GetEventType()

	obj := objectPool.Get().(*xcel.Object[utils.CelEvent])
	if converter, exists := c.eventConverters[eventType]; exists {
		obj.Raw = converter(event).(utils.CelEvent)
	} else {
		obj.Raw = event.(utils.CelEvent)
	}

	activation := eventActivationPool.Get().(*EventActivation)
	activation.eventType = string(eventType)
	activation.event = obj
	activation.isHTTP = eventType == utils.HTTPEventType

	return activation
}

// evaluateProgramWithContext compiles (or retrieves cached) and evaluates a CEL expression
// with the provided evaluation context, returning the CEL result value
func (c *CEL) evaluateProgramWithContext(expression string, evalContext *EventActivation) (ref.Val, error) {
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

func (c *CEL) EvaluateRuleWithContext(evalContext *EventActivation, expressions []typesv1.RuleExpression) (bool, error) {
	for _, expression := range expressions {
		out, err := c.evaluateProgramWithContext(expression.Expression, evalContext)
		if err != nil {
			return false, err
		}

		// Skip if program compilation failed (cached as nil)
		if out == nil {
			return false, nil
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

func (c *CEL) EvaluateExpressionWithContext(evalContext *EventActivation, expression string) (string, error) {
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

func (c *CEL) EvaluateRule(event *events.EnrichedEvent, expressions []typesv1.RuleExpression) (bool, error) {
	evalContext := c.CreateEvalContext(event.Event)
	defer evalContext.Release()
	return c.EvaluateRuleWithContext(evalContext, expressions)
}

func (c *CEL) EvaluateExpression(event *events.EnrichedEvent, expression string) (string, error) {
	evalContext := c.CreateEvalContext(event.Event)
	defer evalContext.Release()
	return c.EvaluateExpressionWithContext(evalContext, expression)
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
