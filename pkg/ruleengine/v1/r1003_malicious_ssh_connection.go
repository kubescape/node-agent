package ruleengine

import (
	"fmt"
	"os"
	"slices"
	"strconv"
	"strings"

	"github.com/goradd/maps"
	"github.com/kubescape/go-logger/helpers"
	"github.com/kubescape/node-agent/pkg/objectcache"
	"github.com/kubescape/node-agent/pkg/ruleengine"
	"github.com/kubescape/node-agent/pkg/utils"

	apitypes "github.com/armosec/armoapi-go/armotypes"
	"github.com/armosec/armoapi-go/armotypes/common"

	"github.com/kubescape/go-logger"
	tracersshtype "github.com/kubescape/node-agent/pkg/ebpf/gadgets/ssh/types"
)

const (
	R1003ID   = "R1003"
	R1003Name = "Malicious SSH Connection"
)

var R1003MaliciousSSHConnectionRuleDescriptor = ruleengine.RuleDescriptor{
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
	allowedPorts       []uint16
	ephemeralPortRange [2]uint16
	requests           maps.SafeMap[string, string] // Mapping of src IP to dst IP
}

// ReadPortRange reads the two port numbers from /proc/sys/net/ipv4/ip_local_port_range
func ReadPortRange() ([2]uint16, error) {
	// Default port range
	var startPort, endPort uint16 = 32768, 60999

	// Read the contents of the file
	data, err := os.ReadFile("/proc/sys/net/ipv4/ip_local_port_range")
	if err != nil {
		return [2]uint16{startPort, endPort}, fmt.Errorf("failed to read port range file: %v", err)
	}

	// Convert the data to a string and split by spaces
	ports := strings.Fields(string(data))
	if len(ports) != 2 {
		return [2]uint16{startPort, endPort}, fmt.Errorf("unexpected format in port range file")
	}

	// Convert the port strings to integers
	startPortInt, err := strconv.Atoi(ports[0])
	if err != nil {
		return [2]uint16{startPort, endPort}, fmt.Errorf("failed to convert start port: %v", err)
	}

	endPortInt, err := strconv.Atoi(ports[1])
	if err != nil {
		return [2]uint16{startPort, endPort}, fmt.Errorf("failed to convert end port: %v", err)
	}

	if startPortInt < 0 || startPortInt > 65535 || endPortInt < 0 || endPortInt > 65535 {
		return [2]uint16{startPort, endPort}, fmt.Errorf("invalid port range")
	}

	return [2]uint16{uint16(startPortInt), uint16(endPortInt)}, nil
}

func CreateRuleR1003MaliciousSSHConnection() *R1003MaliciousSSHConnection {
	ephemeralPorts, err := ReadPortRange()
	if err != nil {
		logger.L().Warning("Failed to read port range, setting to default range:", helpers.Error(err))
	}
	return &R1003MaliciousSSHConnection{
		allowedPorts:       []uint16{22, 2022},
		ephemeralPortRange: ephemeralPorts,
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
			logger.L().Fatal("Allowed ports cannot be empty")
			return
		}

		var allowedPorts []uint16
		for _, port := range allowedPortsInterface {
			if convertedPort, ok := port.(float64); ok {
				allowedPorts = append(allowedPorts, uint16(convertedPort))
			} else {
				logger.L().Fatal("Failed to convert allowed port to uint16")
				return
			}
		}
		rule.allowedPorts = allowedPorts
	} else {
		logger.L().Fatal("Failed to convert allowed ports to []interface{}")
		return
	}
}

func (rule *R1003MaliciousSSHConnection) DeleteRule() {
}

func (rule *R1003MaliciousSSHConnection) EvaluateRule(eventType utils.EventType, event utils.K8sEvent, k8sObjCache objectcache.K8sObjectCache) ruleengine.DetectionResult {
	if eventType != utils.SSHEventType {
		return ruleengine.DetectionResult{IsFailure: false, Payload: nil}
	}

	sshEvent, ok := event.(*tracersshtype.Event)
	if !ok {
		return ruleengine.DetectionResult{IsFailure: false, Payload: nil}
	}

	// Check only outgoing packets (source port is ephemeral)
	if sshEvent.SrcPort < rule.ephemeralPortRange[0] || sshEvent.SrcPort > rule.ephemeralPortRange[1] {
		return ruleengine.DetectionResult{IsFailure: false, Payload: nil}
	}

	if !slices.Contains(rule.allowedPorts, sshEvent.DstPort) {
		// Check if the event is a response to a request we have already seen
		if rule.requests.Has(sshEvent.DstIP) {
			return ruleengine.DetectionResult{IsFailure: false, Payload: nil}
		}
		return ruleengine.DetectionResult{IsFailure: true, Payload: sshEvent}
	}

	return ruleengine.DetectionResult{IsFailure: false, Payload: nil}
}

func (rule *R1003MaliciousSSHConnection) EvaluateRuleWithProfile(eventType utils.EventType, event utils.K8sEvent, objCache objectcache.ObjectCache) (ruleengine.DetectionResult, error) {
	// First do basic evaluation
	detectionResult := rule.EvaluateRule(eventType, event, objCache.K8sObjectCache())
	if !detectionResult.IsFailure {
		return detectionResult, nil
	}

	sshEventTyped, _ := event.(*tracersshtype.Event)
	nn, err := GetNetworkNeighborhood(sshEventTyped.Runtime.ContainerID, objCache)
	if err != nil {
		return ruleengine.DetectionResult{IsFailure: false, Payload: nil}, err
	}

	nnContainer, err := GetContainerFromNetworkNeighborhood(nn, sshEventTyped.GetContainer())
	if err != nil {
		return ruleengine.DetectionResult{IsFailure: false, Payload: nil}, err
	}

	for _, egress := range nnContainer.Egress {
		if egress.IPAddress == sshEventTyped.DstIP {
			for _, port := range egress.Ports {
				if port.Port != nil {
					if uint16(*port.Port) == sshEventTyped.DstPort {
						return ruleengine.DetectionResult{IsFailure: false, Payload: nil}, nil
					}
				}
			}
		}
	}

	return ruleengine.DetectionResult{IsFailure: true, Payload: nil}, nil
}

func (rule *R1003MaliciousSSHConnection) CreateRuleFailure(eventType utils.EventType, event utils.K8sEvent, objCache objectcache.ObjectCache, payload ruleengine.DetectionResult) ruleengine.RuleFailure {
	sshEvent, _ := event.(*tracersshtype.Event)

	return &GenericRuleFailure{
		BaseRuntimeAlert: apitypes.BaseRuntimeAlert{
			UniqueID:    HashStringToMD5(fmt.Sprintf("%s%s%d", sshEvent.Comm, sshEvent.DstIP, sshEvent.DstPort)),
			AlertName:   rule.Name(),
			InfectedPID: sshEvent.Pid,
			Arguments: map[string]interface{}{
				"dstIP":   sshEvent.DstIP,
				"dstPort": sshEvent.DstPort,
			},
			Severity: R1003MaliciousSSHConnectionRuleDescriptor.Priority,
			Identifiers: &common.Identifiers{
				Process: &common.ProcessEntity{
					Name: sshEvent.Comm,
				},
				Network: &common.NetworkEntity{
					DstIP:    sshEvent.DstIP,
					DstPort:  int(sshEvent.DstPort),
					Protocol: "TCP",
				},
			},
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
			RuleDescription: fmt.Sprintf("Malicious SSH connection attempt to %s:%d", sshEvent.DstIP, sshEvent.DstPort),
		},
		RuntimeAlertK8sDetails: apitypes.RuntimeAlertK8sDetails{
			PodName:   sshEvent.GetPod(),
			PodLabels: sshEvent.K8s.PodLabels,
		},
		RuleID: rule.ID(),
	}
}

func (rule *R1003MaliciousSSHConnection) Requirements() ruleengine.RuleSpec {
	return &RuleRequirements{
		EventTypes: R1003MaliciousSSHConnectionRuleDescriptor.Requirements.RequiredEventTypes(),
		ProfileRequirements: ruleengine.ProfileRequirement{
			ProfileDependency: apitypes.Optional,
			ProfileType:       apitypes.NetworkProfile,
		},
	}
}
