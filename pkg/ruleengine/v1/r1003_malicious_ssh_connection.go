package ruleengine

import (
	"fmt"
	"slices"

	"github.com/goradd/maps"
	"github.com/kubescape/node-agent/pkg/objectcache"
	"github.com/kubescape/node-agent/pkg/ruleengine"
	"github.com/kubescape/node-agent/pkg/utils"

	apitypes "github.com/armosec/armoapi-go/armotypes"

	"github.com/kubescape/go-logger"

	tracersshtype "github.com/kubescape/node-agent/pkg/ebpf/gadgets/ssh/types"
)

const (
	R1003ID   = "R1003"
	R1003Name = "Malicious SSH Connection"
)

var R1003MaliciousSSHConnectionRuleDescriptor = RuleDescriptor{
	ID:          R1003ID,
	Name:        R1003Name,
	Description: "Detecting ssh connection to disallowed port",
	Tags:        []string{"ssh", "connection", "port", "malicious"},
	Priority:    RulePriorityMed,
	Requirements: &RuleRequirements{
		EventTypes: []utils.EventType{utils.SSHEventType},
	},
	RuleCreationFunc: func() ruleengine.RuleEvaluator {
		return CreateRuleR1003MaliciousSSHConnection()
	},
}

var _ ruleengine.RuleEvaluator = (*R1003MaliciousSSHConnection)(nil)

type R1003MaliciousSSHConnection struct {
	BaseRule
	allowedPorts []uint16
	requests     maps.SafeMap[string, string] // Mapping of src IP to dst IP
}

func CreateRuleR1003MaliciousSSHConnection() *R1003MaliciousSSHConnection {
	return &R1003MaliciousSSHConnection{
		allowedPorts: []uint16{22},
	}
}
func (rule *R1003MaliciousSSHConnection) Name() string {
	return R1003Name
}

func (rule *R1003MaliciousSSHConnection) ID() string {
	return R1003ID
}

func (rule *R1003MaliciousSSHConnection) SetParameters(params map[string]interface{}) {
	if allowedPortsInterface, ok := params["allowedPorts"].([]interface{}); ok {
		if len(allowedPortsInterface) == 0 {
			logger.L().Error("Allowed ports cannot be empty")
			return
		}

		var allowedPorts []uint16
		for _, port := range allowedPortsInterface {
			if convertedPort, ok := port.(float64); ok {
				allowedPorts = append(allowedPorts, uint16(convertedPort))
			} else {
				logger.L().Error("Failed to convert allowed port to uint16")
				return
			}
		}
		rule.allowedPorts = allowedPorts
	} else {
		logger.L().Error("Failed to convert allowed ports to []interface{}")
		return
	}
}

func (rule *R1003MaliciousSSHConnection) DeleteRule() {
}

func (rule *R1003MaliciousSSHConnection) ProcessEvent(eventType utils.EventType, event interface{}, objectCache objectcache.ObjectCache) ruleengine.RuleFailure {
	if eventType != utils.SSHEventType {
		return nil
	}

	sshEvent := event.(*tracersshtype.Event)

	if !slices.Contains(rule.allowedPorts, sshEvent.DstPort) {
		// Check if the event is a response to a request we have already seen.
		if rule.requests.Has(sshEvent.DstIP) {
			return nil
		}
		rule.requests.Set(sshEvent.SrcIP, sshEvent.DstIP)
		ruleFailure := GenericRuleFailure{
			BaseRuntimeAlert: apitypes.BaseRuntimeAlert{
				AlertName:      rule.Name(),
				InfectedPID:    sshEvent.Pid,
				FixSuggestions: "If this is a legitimate action, please add the port as a parameter to the binding of this rule",
				Severity:       R1003MaliciousSSHConnectionRuleDescriptor.Priority,
			},
			RuntimeProcessDetails: apitypes.ProcessTree{
				ProcessTree: apitypes.Process{
					Comm: sshEvent.Comm,
					Gid:  &sshEvent.Gid,
					PID:  sshEvent.Pid,
					Uid:  &sshEvent.Uid,
				},
				ContainerID: sshEvent.Runtime.ContainerID,
			},
			TriggerEvent: sshEvent.Event,
			RuleAlert: apitypes.RuleAlert{
				RuleDescription: fmt.Sprintf("SSH connection to disallowed port %s:%d", sshEvent.DstIP, sshEvent.DstPort),
			},
			RuntimeAlertK8sDetails: apitypes.RuntimeAlertK8sDetails{
				PodName:   sshEvent.GetPod(),
				PodLabels: sshEvent.K8s.PodLabels,
			},
			RuleID: rule.ID(),
		}

		return &ruleFailure
	}

	return nil
}

func (rule *R1003MaliciousSSHConnection) Requirements() ruleengine.RuleSpec {
	return &RuleRequirements{
		EventTypes: R1003MaliciousSSHConnectionRuleDescriptor.Requirements.RequiredEventTypes(),
	}
}
