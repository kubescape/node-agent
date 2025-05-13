package ruleengine

import (
	"fmt"
	"path/filepath"
	"slices"
	"strings"

	helpersv1 "github.com/kubescape/k8s-interface/instanceidhandler/v1/helpers"
	events "github.com/kubescape/node-agent/pkg/ebpf/events"
	"github.com/kubescape/node-agent/pkg/objectcache"
	"github.com/kubescape/node-agent/pkg/ruleengine"
	"github.com/kubescape/node-agent/pkg/utils"

	apitypes "github.com/armosec/armoapi-go/armotypes"
	tracernetworktype "github.com/inspektor-gadget/inspektor-gadget/pkg/gadgets/trace/network/types"

	"github.com/kubescape/go-logger"
	"github.com/kubescape/go-logger/helpers"
	"github.com/kubescape/storage/pkg/apis/softwarecomposition/v1beta1"
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

func (rule *R0007KubernetesClientExecuted) handleNetworkEvent(event *tracernetworktype.Event, nn *v1beta1.NetworkNeighborhood, k8sObjCache objectcache.K8sObjectCache) *GenericRuleFailure {
	var profileMetadata *apitypes.ProfileMetadata

	if nn != nil {
		profileMetadata = &apitypes.ProfileMetadata{
			Status:             nn.GetAnnotations()[helpersv1.StatusMetadataKey],
			Completion:         nn.GetAnnotations()[helpersv1.CompletionMetadataKey],
			Name:               nn.Name,
			Type:               apitypes.NetworkProfile,
			IsProfileDependent: true,
		}
		nnContainer, err := GetContainerFromNetworkNeighborhood(nn, event.GetContainer())
		if err != nil {
			return nil
		}

		for _, egress := range nnContainer.Egress {
			if egress.IPAddress == event.DstEndpoint.Addr {
				return nil
			}
		}
	}

	apiServerIP := k8sObjCache.GetApiServerIpAddress()
	if apiServerIP == "" || event.DstEndpoint.Addr != apiServerIP {
		return nil
	}

	ruleFailure := GenericRuleFailure{
		BaseRuntimeAlert: apitypes.BaseRuntimeAlert{
			UniqueID:  HashStringToMD5(fmt.Sprintf("%s%s%d", event.Comm, event.DstEndpoint.Addr, event.Port)),
			AlertName: rule.Name(),
			Arguments: map[string]interface{}{
				"dstIP": event.DstEndpoint.Addr,
				"port":  event.Port,
				"proto": event.Proto,
			},
			InfectedPID:     event.Pid,
			Severity:        R0007KubernetesClientExecutedDescriptor.Priority,
			ProfileMetadata: profileMetadata,
		},
		RuntimeProcessDetails: apitypes.ProcessTree{
			ProcessTree: apitypes.Process{
				Comm: event.Comm,
				Gid:  &event.Gid,
				PID:  event.Pid,
				Uid:  &event.Uid,
			},
			ContainerID: event.Runtime.ContainerID,
		},
		TriggerEvent: event.Event,
		RuleAlert: apitypes.RuleAlert{
			RuleDescription: fmt.Sprintf("Kubernetes client executed: %s", event.Comm),
		},
		RuntimeAlertK8sDetails: apitypes.RuntimeAlertK8sDetails{
			PodName:   event.GetPod(),
			PodLabels: event.K8s.PodLabels,
		},
		RuleID: rule.ID(),
	}

	return &ruleFailure
}

func (rule *R0007KubernetesClientExecuted) handleExecEvent(event *events.ExecEvent, ap *v1beta1.ApplicationProfile) *GenericRuleFailure {
	var profileMetadata *apitypes.ProfileMetadata
	execPath := GetExecPathFromEvent(event)
	if ap != nil {
		profileMetadata = &apitypes.ProfileMetadata{
			Status:     ap.GetAnnotations()[helpersv1.StatusMetadataKey],
			Completion: ap.GetAnnotations()[helpersv1.CompletionMetadataKey],
			Name:       ap.Name,
			Type:       apitypes.ApplicationProfile,
		}
		whitelistedExecs, err := GetContainerFromApplicationProfile(ap, event.GetContainer())
		if err != nil {
			logger.L().Error("R0007KubernetesClientExecuted.handleExecEvent - failed to get container from application profile", helpers.String("ruleID", rule.ID()), helpers.String("error", err.Error()))
			return nil
		}

		for _, whitelistedExec := range whitelistedExecs.Execs {
			if whitelistedExec.Path == execPath {
				return nil
			}
		}
	}

	if slices.Contains(kubernetesClients, filepath.Base(execPath)) || slices.Contains(kubernetesClients, event.ExePath) {
		// If the parent process  is in the upper layer, the child process is also in the upper layer.
		upperLayer := event.UpperLayer || event.PupperLayer

		ruleFailure := GenericRuleFailure{
			BaseRuntimeAlert: apitypes.BaseRuntimeAlert{
				UniqueID:    HashStringToMD5(fmt.Sprintf("%s%s%s", event.Comm, execPath, event.Pcomm)),
				AlertName:   rule.Name(),
				InfectedPID: event.Pid,
				Arguments: map[string]interface{}{
					"exec": execPath,
					"args": event.Args,
				},
				Severity:        R0007KubernetesClientExecutedDescriptor.Priority,
				ProfileMetadata: profileMetadata,
			},
			RuntimeProcessDetails: apitypes.ProcessTree{
				ProcessTree: apitypes.Process{
					Comm:       event.Comm,
					Gid:        &event.Gid,
					PID:        event.Pid,
					Uid:        &event.Uid,
					UpperLayer: &upperLayer,
					PPID:       event.Ppid,
					Pcomm:      event.Pcomm,
					Cwd:        event.Cwd,
					Hardlink:   event.ExePath,
					Path:       execPath,
					Cmdline:    fmt.Sprintf("%s %s", execPath, strings.Join(utils.GetExecArgsFromEvent(&event.Event), " ")),
				},
				ContainerID: event.Runtime.ContainerID,
			},
			TriggerEvent: event.Event.Event,
			RuleAlert: apitypes.RuleAlert{
				RuleDescription: fmt.Sprintf("Kubernetes client %s was executed", execPath),
			},
			RuntimeAlertK8sDetails: apitypes.RuntimeAlertK8sDetails{
				PodName:   event.GetPod(),
				PodLabels: event.K8s.PodLabels,
			},
			RuleID: rule.ID(),
			Extra:  event.GetExtra(),
		}

		return &ruleFailure
	}

	return nil
}

func (rule *R0007KubernetesClientExecuted) ProcessEvent(eventType utils.EventType, event utils.K8sEvent, objCache objectcache.ObjectCache) ruleengine.RuleFailure {
	if eventType != utils.ExecveEventType && eventType != utils.NetworkEventType {
		return nil
	}

	if eventType == utils.ExecveEventType {
		execEvent, ok := event.(*events.ExecEvent)
		if !ok {
			return nil
		}

		ap := objCache.ApplicationProfileCache().GetApplicationProfile(execEvent.Runtime.ContainerID)
		result := rule.handleExecEvent(execEvent, ap)
		if result != nil {
			return result
		}

		return nil
	}

	networkEvent, ok := event.(*tracernetworktype.Event)
	if !ok {
		return nil
	}

	if networkEvent.PktType != "OUTGOING" {
		return nil
	}
	nn := objCache.NetworkNeighborhoodCache().GetNetworkNeighborhood(networkEvent.Runtime.ContainerID)

	result := rule.handleNetworkEvent(networkEvent, nn, objCache.K8sObjectCache())
	if result != nil {
		return result
	}

	return nil
}

func (rule *R0007KubernetesClientExecuted) Requirements() ruleengine.RuleSpec {
	return &RuleRequirements{
		EventTypes: R0007KubernetesClientExecutedDescriptor.Requirements.RequiredEventTypes(),
	}
}
