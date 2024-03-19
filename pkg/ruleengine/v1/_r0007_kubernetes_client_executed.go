package ruleengine

import (
	"fmt"
	"node-agent/pkg/ruleengine"
	"node-agent/pkg/utils"
	"path/filepath"
	"slices"

	tracerexectype "github.com/inspektor-gadget/inspektor-gadget/pkg/gadgets/trace/exec/types"
	log "github.com/sirupsen/logrus"

	"github.com/kubescape/kapprofiler/pkg/tracing"
	"github.com/kubescape/storage/pkg/apis/softwarecomposition/v1beta1"
)

const (
	R0007ID                               = "R0007"
	R0007KubernetesClientExecutedRuleName = "Kubernetes Client Executed"
)

var KubernetesClients = []string{
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
	Name:        R0007KubernetesClientExecutedRuleName,
	Description: "Detecting exececution of kubernetes client",
	Priority:    RulePriorityCritical,
	Tags:        []string{"exec", "malicious", "whitelisted"},
	Requirements: &RuleRequirements{
		EventTypes:             []utils.EventType{utils.ExecveEventType, tracing.NetworkEventType},
		NeedApplicationProfile: true,
	},
	RuleCreationFunc: func() ruleengine.RuleEvaluator {
		return CreateRuleR0007KubernetesClientExecuted()
	},
}

type R0007KubernetesClientExecuted struct {
	BaseRule
}

type R0007KubernetesClientExecutedFailure struct {
	RuleName         string
	RulePriority     int
	FixSuggestionMsg string
	Err              string
	FailureEvent     *tracing.GeneralEvent
}

func (rule *R0007KubernetesClientExecuted) Name() string {
	return R0007KubernetesClientExecutedRuleName
}

func CreateRuleR0007KubernetesClientExecuted() *R0007KubernetesClientExecuted {
	return &R0007KubernetesClientExecuted{}
}

func (rule *R0007KubernetesClientExecuted) DeleteRule() {
}

func (rule *R0007KubernetesClientExecuted) handleNetworkEvent(event *tracing.NetworkEvent, ap *v1beta1.ApplicationProfile, k8sProvider ruleengine.K8sObjectProvider) *R0007KubernetesClientExecutedFailure {
	whitelistedNetworks, err := appProfileAccess.GetNetworkActivity()
	if err != nil {
		log.Printf("Failed to get network list from app profile: %v", err)
		return nil
	}

	for _, whitelistedNetwork := range whitelistedNetworks.Outgoing {
		if whitelistedNetwork.DstEndpoint == event.DstEndpoint {
			return nil
		}
	}

	apiServerIP, err := engineAccess.GetApiServerIpAddress()
	if apiServerIP == "" || err != nil {
		log.Printf("Failed to get api server ip: %v", err)
		return nil
	}

	if event.DstEndpoint == apiServerIP {
		return &R0007KubernetesClientExecutedFailure{
			RuleName:         rule.Name(),
			Err:              fmt.Sprintf("Kubernetes client executed: %s", event.Comm),
			FixSuggestionMsg: "If this is a legitimate action, please consider removing this workload from the binding of this rule.",
			FailureEvent:     &event.GeneralEvent,
			RulePriority:     R0007KubernetesClientExecutedDescriptor.Priority,
		}
	}

	return nil
}

func (rule *R0007KubernetesClientExecuted) handleExecEvent(event *tracerexectype.Event, ap *v1beta1.ApplicationProfile) *R0007KubernetesClientExecutedFailure {
	whitelistedExecs, err := appProfileAccess.GetExecList()
	if err != nil {
		log.Printf("Failed to get exec list from app profile: %v", err)
		return nil
	}

	for _, whitelistedExec := range *whitelistedExecs {
		if whitelistedExec.Path == event.PathName {
			return nil
		}
	}

	if slices.Contains(KubernetesClients, filepath.Base(event.PathName)) {
		return &R0007KubernetesClientExecutedFailure{
			RuleName:         rule.Name(),
			Err:              fmt.Sprintf("Kubernetes client executed: %s", event.PathName),
			FixSuggestionMsg: "If this is a legitimate action, please consider removing this workload from the binding of this rule.",
			FailureEvent:     &event.GeneralEvent,
			RulePriority:     R0007KubernetesClientExecutedDescriptor.Priority,
		}
	}

	return nil
}

func (rule *R0007KubernetesClientExecuted) ProcessEvent(eventType utils.EventType, event interface{}, ap *v1beta1.ApplicationProfile, k8sProvider ruleengine.K8sObjectProvider) ruleengine.RuleFailure {
	if eventType != utils.ExecveEventType && eventType != tracing.NetworkEventType {
		return nil
	}

	if eventType == tracing.ExecveEventType {
		execEvent, ok := event.(*tracing.ExecveEvent)
		if !ok {
			return nil
		}

		result := rule.handleExecEvent(execEvent, appProfileAccess)
		if result != nil {
			return result
		}

		return nil
	}

	if eventType == tracing.NetworkEventType {
		networkEvent, ok := event.(*tracing.NetworkEvent)
		if !ok {
			return nil
		}

		if networkEvent.PacketType != "OUTGOING" {
			return nil
		}

		result := rule.handleNetworkEvent(networkEvent, appProfileAccess, engineAccess)
		if result != nil {
			return result
		}

		return nil
	}

	return nil
}

func (rule *R0007KubernetesClientExecuted) Requirements() ruleengine.RuleSpec {
	return &RuleRequirements{
		EventTypes:             []utils.EventType{utils.ExecveEventType, tracing.NetworkEventType},
		NeedApplicationProfile: true,
	}
}

func (rule *R0007KubernetesClientExecutedFailure) Name() string {
	return rule.RuleName
}

func (rule *R0007KubernetesClientExecutedFailure) Error() string {
	return rule.Err
}

func (rule *R0007KubernetesClientExecutedFailure) Event() tracing.GeneralEvent {
	return *rule.FailureEvent
}

func (rule *R0007KubernetesClientExecutedFailure) Priority() int {
	return rule.RulePriority
}

func (rule *R0007KubernetesClientExecutedFailure) FixSuggestion() string {
	return rule.FixSuggestionMsg
}
