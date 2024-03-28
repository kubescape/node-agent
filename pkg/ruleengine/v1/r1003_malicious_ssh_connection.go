package ruleengine

import (
	"fmt"
	"log"
	"node-agent/pkg/objectcache"
	"node-agent/pkg/ruleengine"
	"node-agent/pkg/utils"
	"slices"
	"strings"
	"time"

	tracernetworktype "github.com/inspektor-gadget/inspektor-gadget/pkg/gadgets/trace/network/types"

	traceropentype "github.com/inspektor-gadget/inspektor-gadget/pkg/gadgets/trace/open/types"

	"github.com/kubescape/go-logger"
)

const (
	R1003ID              = "R1003"
	R1003Name            = "Malicious SSH Connection"
	MaxTimeDiffInSeconds = 2
)

var SSHRelatedFiles = []string{
	"ssh_config",
	"sshd_config",
	"ssh_known_hosts",
	"ssh_known_hosts2",
	"ssh_config.d",
	"sshd_config.d",
	".ssh",
	"authorized_keys",
	"authorized_keys2",
	"known_hosts",
	"known_hosts2",
	"id_rsa",
	"id_rsa.pub",
	"id_dsa",
	"id_dsa.pub",
	"id_ecdsa",
	"id_ecdsa.pub",
	"id_ed25519",
	"id_ed25519.pub",
	"id_xmss",
	"id_xmss.pub",
}

var R1003MaliciousSSHConnectionRuleDescriptor = RuleDescriptor{
	ID:          R1003ID,
	Name:        R1003Name,
	Description: "Detecting ssh connection to disallowed port",
	Tags:        []string{"ssh", "connection", "port", "malicious"},
	Priority:    RulePriorityHigh,
	Requirements: &RuleRequirements{
		EventTypes: []utils.EventType{utils.OpenEventType, utils.NetworkEventType},
	},
	RuleCreationFunc: func() ruleengine.RuleEvaluator {
		return CreateRuleR1003MaliciousSSHConnection()
	},
}

var _ ruleengine.RuleEvaluator = (*R1003MaliciousSSHConnection)(nil)

type R1003MaliciousSSHConnection struct {
	BaseRule
	accessRelatedFiles        bool
	sshInitiatorPid           uint32
	configFileAccessTimeStamp int64
	allowedPorts              []uint16
}

func CreateRuleR1003MaliciousSSHConnection() *R1003MaliciousSSHConnection {
	return &R1003MaliciousSSHConnection{accessRelatedFiles: false,
		sshInitiatorPid:           0,
		configFileAccessTimeStamp: 0,
		allowedPorts:              []uint16{22},
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

func (rule *R1003MaliciousSSHConnection) ProcessEvent(eventType utils.EventType, event interface{}, objCache objectcache.ObjectCache) ruleengine.RuleFailure {
	if eventType != utils.OpenEventType && eventType != utils.NetworkEventType {
		return nil
	}

	if eventType == utils.OpenEventType && !rule.accessRelatedFiles {
		openEvent, ok := event.(*traceropentype.Event)
		if !ok {
			return nil
		} else {
			if IsSSHConfigFile(openEvent.Path) {
				rule.accessRelatedFiles = true
				rule.sshInitiatorPid = openEvent.Pid
				rule.configFileAccessTimeStamp = int64(openEvent.Timestamp)
			}

			return nil
		}
	} else if eventType == utils.NetworkEventType && rule.accessRelatedFiles {
		networkEvent, ok := event.(*tracernetworktype.Event)
		if !ok {
			return nil
		}

		timestampDiffInSeconds := calculateTimestampDiffInSeconds(int64(networkEvent.Timestamp), rule.configFileAccessTimeStamp)
		if timestampDiffInSeconds > MaxTimeDiffInSeconds {
			rule.accessRelatedFiles = false
			rule.sshInitiatorPid = 0
			rule.configFileAccessTimeStamp = 0
			return nil
		}
		if networkEvent.Pid == rule.sshInitiatorPid && networkEvent.PktType == "OUTGOING" && networkEvent.Proto == "TCP" && !slices.Contains(rule.allowedPorts, networkEvent.Port) {
			rule.accessRelatedFiles = false
			rule.sshInitiatorPid = 0
			rule.configFileAccessTimeStamp = 0
			return &GenericRuleFailure{
				RuleName:         rule.Name(),
				RuleID:           rule.ID(),
				ContainerId:      networkEvent.Runtime.ContainerID,
				Err:              fmt.Sprintf("ssh connection to port %d is not allowed", networkEvent.Port),
				FixSuggestionMsg: "If this is a legitimate action, please add the port as a parameter to the binding of this rule",
				FailureEvent:     utils.NetworkToGeneralEvent(networkEvent),
				RulePriority:     R1003MaliciousSSHConnectionRuleDescriptor.Priority,
			}
		}
	}

	return nil
}

func calculateTimestampDiffInSeconds(timestamp1 int64, timestamp2 int64) int64 {
	return (timestamp1 - timestamp2) / int64(time.Second)
}

func IsSSHConfigFile(path string) bool {
	for _, sshFile := range SSHRelatedFiles {
		if strings.Contains(path, sshFile) {
			log.Printf("Found SSH related file: %s\n", path)
			return true
		}
	}
	return false
}

func (rule *R1003MaliciousSSHConnection) Requirements() ruleengine.RuleSpec {
	return &RuleRequirements{
		EventTypes: R1003MaliciousSSHConnectionRuleDescriptor.Requirements.RequiredEventTypes(),
	}
}
