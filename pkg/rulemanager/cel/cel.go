package cel

import (
	"fmt"
	"sync"

	"github.com/google/cel-go/cel"
	"github.com/google/cel-go/ext"
	"github.com/kubescape/node-agent/pkg/config"
	"github.com/kubescape/node-agent/pkg/ebpf/events"
	tracerforktype "github.com/kubescape/node-agent/pkg/ebpf/gadgets/fork/types"
	tracerhardlinktype "github.com/kubescape/node-agent/pkg/ebpf/gadgets/hardlink/types"
	traceriouringtype "github.com/kubescape/node-agent/pkg/ebpf/gadgets/iouring/tracer/types"
	tracerptracetype "github.com/kubescape/node-agent/pkg/ebpf/gadgets/ptrace/tracer/types"
	tracerrandomxtype "github.com/kubescape/node-agent/pkg/ebpf/gadgets/randomx/types"
	tracersshtype "github.com/kubescape/node-agent/pkg/ebpf/gadgets/ssh/types"
	tracersymlinktype "github.com/kubescape/node-agent/pkg/ebpf/gadgets/symlink/types"
	"github.com/kubescape/node-agent/pkg/objectcache"
	"github.com/kubescape/node-agent/pkg/rulemanager/cel/libraries/applicationprofile"
	"github.com/kubescape/node-agent/pkg/rulemanager/cel/libraries/k8s"
	"github.com/kubescape/node-agent/pkg/rulemanager/cel/libraries/net"
	"github.com/kubescape/node-agent/pkg/rulemanager/cel/libraries/networkneighborhood"
	"github.com/kubescape/node-agent/pkg/rulemanager/cel/libraries/parse"
	"github.com/kubescape/node-agent/pkg/rulemanager/cel/libraries/process"
	"github.com/kubescape/node-agent/pkg/rulemanager/types"
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
	//capaObj, capaTyp := xcel.NewObject(&tracercapabilitiestype.Event{})
	//xcel.RegisterObject(ta, tp, capaObj, capaTyp, xcel.NewFields(capaObj))
	//dnsObj, dnsTyp := xcel.NewObject(&events.IGDnsEvent{})
	//xcel.RegisterObject(ta, tp, dnsObj, dnsTyp, xcel.NewFields(dnsObj))
	//execObj, execTyp := xcel.NewObject(&events.ExecEvent{})
	//xcel.RegisterObject(ta, tp, execObj, execTyp, xcel.NewFields(execObj))
	//exitObj, exitTyp := xcel.NewObject(&tracerexectype.Event{})
	//xcel.RegisterObject(ta, tp, exitObj, exitTyp, xcel.NewFields(exitObj))
	forkObj, forkTyp := xcel.NewObject(&tracerforktype.Event{})
	xcel.RegisterObject(ta, tp, forkObj, forkTyp, xcel.NewFields(forkObj))
	hardlinkObj, hardlinkTyp := xcel.NewObject(&tracerhardlinktype.Event{})
	xcel.RegisterObject(ta, tp, hardlinkObj, hardlinkTyp, xcel.NewFields(hardlinkObj))
	iouringObj, iouringTyp := xcel.NewObject(&traceriouringtype.Event{})
	xcel.RegisterObject(ta, tp, iouringObj, iouringTyp, xcel.NewFields(iouringObj))
	//netObj, netTyp := xcel.NewObject(&datasource.Data{})
	//xcel.RegisterObject(ta, tp, netObj, netTyp, xcel.NewFields(netObj))
	//openObj, openTyp := xcel.NewObject(&events.OpenEvent{})
	//xcel.RegisterObject(ta, tp, openObj, openTyp, xcel.NewFields(openObj))
	procObj, procTyp := xcel.NewObject(&events.ProcfsEvent{})
	xcel.RegisterObject(ta, tp, procObj, procTyp, xcel.NewFields(procObj))
	ptraceObj, ptraceTyp := xcel.NewObject(&tracerptracetype.Event{})
	xcel.RegisterObject(ta, tp, ptraceObj, ptraceTyp, xcel.NewFields(ptraceObj))
	randObj, randTyp := xcel.NewObject(&tracerrandomxtype.Event{})
	xcel.RegisterObject(ta, tp, randObj, randTyp, xcel.NewFields(randObj))
	sshObj, sshTyp := xcel.NewObject(&tracersshtype.Event{})
	xcel.RegisterObject(ta, tp, sshObj, sshTyp, xcel.NewFields(sshObj))
	symlinkObj, symlinkTyp := xcel.NewObject(&tracersymlinktype.Event{})
	xcel.RegisterObject(ta, tp, symlinkObj, symlinkTyp, xcel.NewFields(symlinkObj))
	syscallObj, syscallTyp := xcel.NewObject(&types.SyscallEvent{})
	xcel.RegisterObject(ta, tp, syscallObj, syscallTyp, xcel.NewFields(syscallObj))
	envOptions := []cel.EnvOption{
		cel.Variable("event_type", cel.StringType),
		//cel.Variable(string(utils.CapabilitiesEventType), capaTyp),
		//cel.Variable(string(utils.DnsEventType), dnsTyp),
		//cel.Variable(string(utils.ExecveEventType), execTyp),
		//cel.Variable(string(utils.ExitEventType), exitTyp),
		cel.Variable(string(utils.ForkEventType), forkTyp),
		cel.Variable(string(utils.HardlinkEventType), hardlinkTyp),
		cel.Variable(string(utils.IoUringEventType), iouringTyp),
		//cel.Variable(string(utils.NetworkEventType), netTyp),
		//cel.Variable(string(utils.OpenEventType), openTyp),
		cel.Variable(string(utils.ProcfsEventType), procTyp),
		cel.Variable(string(utils.PtraceEventType), ptraceTyp),
		cel.Variable(string(utils.RandomXEventType), randTyp),
		cel.Variable(string(utils.SSHEventType), sshTyp),
		cel.Variable(string(utils.SymlinkEventType), symlinkTyp),
		cel.Variable(string(utils.SyscallEventType), syscallTyp),
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
		return make(map[string]any, 1)
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
	for _, expression := range expressions {
		if expression.EventType != event.EventType {
			continue
		}

		program, err := c.getOrCreateProgram(expression.Expression)
		if err != nil {
			return false, err
		}

		obj, _ := xcel.NewObject(event.Event)
		out, _, err := program.Eval(map[string]any{string(event.EventType): obj, "event_type": string(event.EventType)})
		if err != nil {
			return false, err
		}

		if !out.Value().(bool) {
			return false, nil
		}
	}

	return true, nil
}

func (c *CEL) EvaluateRuleByMap(event map[string]any, eventType utils.EventType, expressions []typesv1.RuleExpression) (bool, error) {
	// Get evaluation context map from pool to reduce allocations
	evalContext := c.evalContextPool.Get().(map[string]any)
	defer func() {
		// Clear and return to pool
		clear(evalContext)
		c.evalContextPool.Put(evalContext)
	}()

	evalContext[string(eventType)] = event
	evalContext["event_type"] = string(eventType)

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

func (c *CEL) EvaluateExpressionByMap(event map[string]any, expression string, eventType utils.EventType) (string, error) {
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
	evalContext["event_type"] = string(eventType)

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

	obj, _ := xcel.NewObject(event.Event)
	out, _, err := program.Eval(map[string]any{string(event.EventType): obj, "event_type": string(event.EventType)})
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
