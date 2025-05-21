package ruleengine

import (
	"fmt"
	"path/filepath"
	"slices"
	"strings"

	apitypes "github.com/armosec/armoapi-go/armotypes"
	tracernetworktype "github.com/inspektor-gadget/inspektor-gadget/pkg/gadgets/trace/network/types"
	events "github.com/kubescape/node-agent/pkg/ebpf/events"
	"github.com/kubescape/node-agent/pkg/objectcache"
	"github.com/kubescape/node-agent/pkg/ruleengine"
	"github.com/kubescape/node-agent/pkg/utils"
)

const (
	R0007ID   = "R0007"
	R0007Name = "Kubernetes Client Executed"
)

var kubernetesClients = []string{
	"kubectl",
}

var R0007KubernetesClientExecutedDescriptor = ruleengine.RuleDescriptor{
	ID:          R0007ID,
	Name:        R0007Name,
	Description: "Detecting exececution of kubernetes client",
	Priority:    RulePriorityHigh,
	Tags:        []string{"exec", "malicious", "whitelisted"},
	Requirements: &RuleRequirements{
		EventTypes: []utils.EventType{utils.ExecveEventType, utils.NetworkEventType},
	},
	RuleCreationFunc: func() ruleengine.RuleEvaluator {
		return CreateRuleR0007KubernetesClientExecuted()
	},
}
var _ ruleengine.RuleEvaluator = (*R0007KubernetesClientExecuted)(nil)

type R0007KubernetesClientExecuted struct {
	BaseRule
}

func CreateRuleR0007KubernetesClientExecuted() *R0007KubernetesClientExecuted {
	return &R0007KubernetesClientExecuted{}
}

func (rule *R0007KubernetesClientExecuted) Name() string {
	return R0007Name
}

func (rule *R0007KubernetesClientExecuted) ID() string {
	return R0007ID
}

func (rule *R0007KubernetesClientExecuted) DeleteRule() {
}

func (rule *R0007KubernetesClientExecuted) EvaluateRule(eventType utils.EventType, event utils.K8sEvent, k8sObjCache objectcache.K8sObjectCache) (bool, interface{}) {
	if eventType != utils.ExecveEventType && eventType != utils.NetworkEventType {
		return false, nil
	}

	if eventType == utils.ExecveEventType {
		execEvent, ok := event.(*events.ExecEvent)
		if !ok {
			return false, nil
		}

		execPath := GetExecPathFromEvent(execEvent)
		if slices.Contains(kubernetesClients, filepath.Base(execPath)) || slices.Contains(kubernetesClients, execEvent.ExePath) {
			return true, execEvent
		}
		return false, nil
	}

	networkEvent, ok := event.(*tracernetworktype.Event)
	if !ok {
		return false, nil
	}

	if networkEvent.PktType != "OUTGOING" {
		return false, nil
	}

	if k8sObjCache == nil {
		return false, nil
	}

	apiServerIP := k8sObjCache.GetApiServerIpAddress()
	if apiServerIP == "" || networkEvent.DstEndpoint.Addr != apiServerIP {
		return false, nil
	}

	return true, networkEvent
}

func (rule *R0007KubernetesClientExecuted) EvaluateRuleWithProfile(eventType utils.EventType, event utils.K8sEvent, objCache objectcache.ObjectCache) (bool, interface{}, error) {
	// First do basic evaluation
	ok, eventData := rule.EvaluateRule(eventType, event, objCache.K8sObjectCache())
	if !ok {
		return false, nil, nil
	}

	if eventType == utils.ExecveEventType {
		execEvent, _ := eventData.(*events.ExecEvent)
		ap, err := GetApplicationProfile(execEvent.Runtime.ContainerID, objCache)
		if err != nil {
			return false, nil, err
		}

		whitelistedExecs, err := GetContainerFromApplicationProfile(ap, execEvent.GetContainer())
		if err != nil {
			return false, nil, err
		}

		execPath := GetExecPathFromEvent(execEvent)
		for _, whitelistedExec := range whitelistedExecs.Execs {
			if whitelistedExec.Path == execPath {
				return false, nil, nil
			}
		}
	} else {
		networkEvent, _ := eventData.(*tracernetworktype.Event)
		nn, err := GetNetworkNeighborhood(networkEvent.Runtime.ContainerID, objCache)
		if err != nil {
			return false, nil, err
		}

		nnContainer, err := GetContainerFromNetworkNeighborhood(nn, networkEvent.GetContainer())
		if err != nil {
			return false, nil, err
		}

		for _, egress := range nnContainer.Egress {
			if egress.IPAddress == networkEvent.DstEndpoint.Addr {
				return false, nil, nil
			}
		}
	}

	return true, nil, nil
}

func (rule *R0007KubernetesClientExecuted) CreateRuleFailure(eventType utils.EventType, event utils.K8sEvent, objCache objectcache.ObjectCache, payload interface{}) ruleengine.RuleFailure {
	if eventType == utils.ExecveEventType {
		execEvent, _ := event.(*events.ExecEvent)
		execPath := GetExecPathFromEvent(execEvent)
		upperLayer := execEvent.UpperLayer || execEvent.PupperLayer

		return &GenericRuleFailure{
			BaseRuntimeAlert: apitypes.BaseRuntimeAlert{
				UniqueID:    HashStringToMD5(fmt.Sprintf("%s%s%s", execEvent.Comm, execPath, execEvent.Pcomm)),
				AlertName:   rule.Name(),
				InfectedPID: execEvent.Pid,
				Arguments: map[string]interface{}{
					"exec": execPath,
					"args": execEvent.Args,
				},
				Severity: R0007KubernetesClientExecutedDescriptor.Priority,
			},
			RuntimeProcessDetails: apitypes.ProcessTree{
				ProcessTree: apitypes.Process{
					Comm:       execEvent.Comm,
					Gid:        &execEvent.Gid,
					PID:        execEvent.Pid,
					Uid:        &execEvent.Uid,
					UpperLayer: &upperLayer,
					PPID:       execEvent.Ppid,
					Pcomm:      execEvent.Pcomm,
					Cwd:        execEvent.Cwd,
					Hardlink:   execEvent.ExePath,
					Path:       execPath,
					Cmdline:    fmt.Sprintf("%s %s", execPath, strings.Join(utils.GetExecArgsFromEvent(&execEvent.Event), " ")),
				},
				ContainerID: execEvent.Runtime.ContainerID,
			},
			TriggerEvent: execEvent.Event.Event,
			RuleAlert: apitypes.RuleAlert{
				RuleDescription: fmt.Sprintf("Kubernetes client %s was executed", execPath),
			},
			RuntimeAlertK8sDetails: apitypes.RuntimeAlertK8sDetails{
				PodName:   execEvent.GetPod(),
				PodLabels: execEvent.K8s.PodLabels,
			},
			RuleID: rule.ID(),
			Extra:  execEvent.GetExtra(),
		}
	}

	networkEvent, _ := event.(*tracernetworktype.Event)
	return &GenericRuleFailure{
		BaseRuntimeAlert: apitypes.BaseRuntimeAlert{
			UniqueID:  HashStringToMD5(fmt.Sprintf("%s%s%d", networkEvent.Comm, networkEvent.DstEndpoint.Addr, networkEvent.Port)),
			AlertName: rule.Name(),
			Arguments: map[string]interface{}{
				"dstIP": networkEvent.DstEndpoint.Addr,
				"port":  networkEvent.Port,
				"proto": networkEvent.Proto,
			},
			InfectedPID: networkEvent.Pid,
			Severity:    R0007KubernetesClientExecutedDescriptor.Priority,
		},
		RuntimeProcessDetails: apitypes.ProcessTree{
			ProcessTree: apitypes.Process{
				Comm: networkEvent.Comm,
				Gid:  &networkEvent.Gid,
				PID:  networkEvent.Pid,
				Uid:  &networkEvent.Uid,
			},
			ContainerID: networkEvent.Runtime.ContainerID,
		},
		TriggerEvent: networkEvent.Event,
		RuleAlert: apitypes.RuleAlert{
			RuleDescription: fmt.Sprintf("Kubernetes client executed: %s", networkEvent.Comm),
		},
		RuntimeAlertK8sDetails: apitypes.RuntimeAlertK8sDetails{
			PodName:   networkEvent.GetPod(),
			PodLabels: networkEvent.K8s.PodLabels,
		},
		RuleID: rule.ID(),
	}
}

func (rule *R0007KubernetesClientExecuted) Requirements() ruleengine.RuleSpec {
	return &RuleRequirements{
		EventTypes: R0007KubernetesClientExecutedDescriptor.Requirements.RequiredEventTypes(),
		ProfileRequirements: ruleengine.ProfileRequirement{
			ProfileDependency: apitypes.Optional,
			ProfileType:       apitypes.ApplicationProfile,
		},
	}
}
