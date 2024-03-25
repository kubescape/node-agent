package ruleengine

import (
	"fmt"
	"node-agent/pkg/ruleengine"
	"node-agent/pkg/ruleengine/objectcache"
	"node-agent/pkg/utils"
	"path/filepath"
	"slices"

	tracerexectype "github.com/inspektor-gadget/inspektor-gadget/pkg/gadgets/trace/exec/types"
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
	"kubeadm",
	"kubelet",
	"kube-proxy",
	"kube-apiserver",
	"kube-controller-manager",
	"kube-scheduler",
	"crictl",
	"docker",
	"containerd",
	"runc",
	"ctr",
	"containerd-shim",
	"containerd-shim-runc-v2",
	"containerd-shim-runc-v1",
	"containerd-shim-runc-v0",
	"containerd-shim-runc",
}

var R0007KubernetesClientExecutedDescriptor = RuleDescriptor{
	ID:          R0007ID,
	Name:        R0007Name,
	Description: "Detecting exececution of kubernetes client",
	Priority:    RulePriorityCritical,
	Tags:        []string{"exec", "malicious", "whitelisted"},
	Requirements: &RuleRequirements{
		EventTypes:             []utils.EventType{utils.ExecveEventType, utils.NetworkEventType},
		NeedApplicationProfile: true,
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

func (rule *R0007KubernetesClientExecuted) handleNetworkEvent(event *tracernetworktype.Event, nn *v1beta1.NetworkNeighbors, k8sObjCache objectcache.K8sObjectCache) *GenericRuleFailure {

	for _, egress := range nn.Spec.Egress {
		if egress.DNS == event.DstEndpoint.Addr {
			return nil
		}
	}

	apiServerIP := k8sObjCache.GetApiServerIpAddress()
	if apiServerIP == "" {
		return nil
	}

	if event.DstEndpoint.Addr == apiServerIP {
		return &GenericRuleFailure{
			RuleName:         rule.Name(),
			RuleID:           rule.ID(),
			Err:              fmt.Sprintf("Kubernetes client executed: %s", event.Comm),
			FixSuggestionMsg: "If this is a legitimate action, please consider removing this workload from the binding of this rule.",
			FailureEvent:     utils.NetworkToGeneralEvent(event),
			RulePriority:     R0007KubernetesClientExecutedDescriptor.Priority,
		}
	}

	return nil
}

func (rule *R0007KubernetesClientExecuted) handleExecEvent(event *tracerexectype.Event, ap *v1beta1.ApplicationProfile) *GenericRuleFailure {
	whitelistedExecs, err := getContainerFromApplicationProfile(ap, event.GetContainer())
	if err != nil {
		logger.L().Error("Failed to get container from application profile", helpers.String("ruleID", rule.ID()), helpers.String("error", err.Error()))
		return nil
	}

	execPath := getExecPathFromEvent(event)
	for _, whitelistedExec := range whitelistedExecs.Execs {
		if whitelistedExec.Path == execPath {
			return nil
		}
	}

	if slices.Contains(kubernetesClients, filepath.Base(execPath)) {
		return &GenericRuleFailure{
			RuleName:         rule.Name(),
			RuleID:           rule.ID(),
			Err:              fmt.Sprintf("Kubernetes client executed: %s", execPath),
			FixSuggestionMsg: "If this is a legitimate action, please consider removing this workload from the binding of this rule.",
			FailureEvent:     utils.ExecToGeneralEvent(event),
			RulePriority:     R0007KubernetesClientExecutedDescriptor.Priority,
		}
	}

	return nil
}

func (rule *R0007KubernetesClientExecuted) ProcessEvent(eventType utils.EventType, event interface{}, objCache objectcache.ObjectCache) ruleengine.RuleFailure {
	if eventType != utils.ExecveEventType && eventType != utils.NetworkEventType {
		return nil
	}

	if eventType == utils.ExecveEventType {
		execEvent, ok := event.(*tracerexectype.Event)
		if !ok {
			return nil
		}

		ap := objCache.ApplicationProfileCache().GetApplicationProfile(execEvent.GetNamespace(), execEvent.GetPod())
		if ap == nil {
			return nil
		}
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
	nn := objCache.NetworkNeighborsCache().GetNetworkNeighbors(networkEvent.GetNamespace(), networkEvent.GetPod())
	if nn == nil {
		return nil
	}

	result := rule.handleNetworkEvent(networkEvent, nn, objCache.K8sObjectCache())
	if result != nil {
		return result
	}

	return nil
}

func (rule *R0007KubernetesClientExecuted) Requirements() ruleengine.RuleSpec {
	return &RuleRequirements{
		EventTypes:             R0007KubernetesClientExecutedDescriptor.Requirements.RequiredEventTypes(),
		NeedApplicationProfile: true,
	}
}
