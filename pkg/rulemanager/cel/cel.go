package cel

import (
	"fmt"
	"sync"

	"github.com/google/cel-go/cel"
	tracercapabilitiestype "github.com/inspektor-gadget/inspektor-gadget/pkg/gadgets/trace/capabilities/types"
	tracerdnstype "github.com/inspektor-gadget/inspektor-gadget/pkg/gadgets/trace/dns/types"
	tracernetworktype "github.com/inspektor-gadget/inspektor-gadget/pkg/gadgets/trace/network/types"
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
	evalContextPool sync.Pool
}

func NewCEL(objectCache objectcache.ObjectCache, cfg config.Config) (*CEL, error) {
	ta, tp := xcel.NewTypeAdapter(), xcel.NewTypeProvider()
	capaObj, capaTyp := xcel.NewObject(&tracercapabilitiestype.Event{})
	xcel.RegisterObject(ta, tp, capaObj, capaTyp, xcel.NewFields(capaObj))
	dnsObj, dnsTyp := xcel.NewObject(&tracerdnstype.Event{})
	xcel.RegisterObject(ta, tp, dnsObj, dnsTyp, xcel.NewFields(dnsObj))
	execObj, execTyp := xcel.NewObject(&events.ExecEvent{})
	xcel.RegisterObject(ta, tp, execObj, execTyp, xcel.NewFields(execObj))
	netObj, netTyp := xcel.NewObject(&tracernetworktype.Event{})
	xcel.RegisterObject(ta, tp, netObj, netTyp, xcel.NewFields(netObj))
	openObj, openTyp := xcel.NewObject(&events.OpenEvent{})
	xcel.RegisterObject(ta, tp, openObj, openTyp, xcel.NewFields(openObj))
	syscallObj, syscallTyp := xcel.NewObject(&types.SyscallEvent{})
	xcel.RegisterObject(ta, tp, syscallObj, syscallTyp, xcel.NewFields(syscallObj))
	envOptions := []cel.EnvOption{
		cel.Types(capaTyp, execTyp, openTyp, syscallTyp),
		cel.Variable(string(utils.CapabilitiesEventType), capaTyp),
		cel.Variable(string(utils.DnsEventType), dnsTyp),
		cel.Variable(string(utils.ExecveEventType), execTyp),
		cel.Variable(string(utils.NetworkEventType), netTyp),
		cel.Variable(string(utils.OpenEventType), openTyp),
		cel.Variable(string(utils.SyscallEventType), syscallTyp),
		cel.CustomTypeAdapter(ta),
		cel.CustomTypeProvider(tp),
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
	cel := &CEL{
		env:          env,
		objectCache:  objectCache,
		programCache: make(map[string]cel.Program),
	}

	// Initialize evaluation context pool to reduce map allocations
	cel.evalContextPool.New = func() interface{} {
		return make(map[string]any, 1)
	}

	return cel, nil
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
		out, _, err := program.Eval(map[string]any{string(event.EventType): obj})
		if err != nil {
			logger.L().Error("evaluation error", helpers.Error(err))
		}

		if !out.Value().(bool) {
			return false, nil
		}
	}

	return true, nil
}

func (c *CEL) EvaluateExpression(event *events.EnrichedEvent, expression string) (string, error) {
	program, err := c.getOrCreateProgram(expression)
	if err != nil {
		return "", err
	}

	obj, _ := xcel.NewObject(event.Event)
	out, _, err := program.Eval(map[string]any{string(event.EventType): obj})
	if err != nil {
		logger.L().Error("evaluation error", helpers.Error(err))
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
