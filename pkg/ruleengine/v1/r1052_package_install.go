package ruleengine

import (
	"fmt"
	"strings"

	"github.com/kubescape/node-agent/pkg/ebpf/events"
	"github.com/kubescape/node-agent/pkg/objectcache"
	"github.com/kubescape/node-agent/pkg/ruleengine"
	"github.com/kubescape/node-agent/pkg/utils"

	apitypes "github.com/armosec/armoapi-go/armotypes"
)

const (
	R1052ID   = "R1052"
	R1052Name = "Package Install Detected"
)

var R1052PackageInstallDetectedDescriptor = ruleengine.RuleDescriptor{
	ID:          R1052ID,
	Name:        R1052Name,
	Description: "Detects if a package installation command is executed inside the container",
	Priority:    RulePriorityMed,
	Tags:        []string{"runtime", "security", "package-management"},
	Requirements: &RuleRequirements{
		EventTypes: []utils.EventType{utils.ExecveEventType},
	},
	RuleCreationFunc: func() ruleengine.RuleEvaluator {
		return CreateRuleR1052PackageInstallDetected()
	},
}

var _ ruleengine.RuleEvaluator = (*R1052PackageInstallDetected)(nil)

type R1052PackageInstallDetected struct {
	BaseRule
}

func CreateRuleR1052PackageInstallDetected() *R1052PackageInstallDetected {
	return &R1052PackageInstallDetected{}
}

func (rule *R1052PackageInstallDetected) Name() string {
	return R1052Name
}

func (rule *R1052PackageInstallDetected) ID() string {
	return R1052ID
}

func (rule *R1052PackageInstallDetected) ProcessEvent(eventType utils.EventType, event utils.K8sEvent, objCache objectcache.ObjectCache) ruleengine.RuleFailure {
	if eventType != utils.ExecveEventType {
		return nil
	}

	execEvent, ok := event.(*events.ExecEvent)
	if !ok {
		return nil
	}

	// Common package managers and their command binaries
	installCommands := map[string][]string{
		"apt":     {"install", "add"},
		"apk":     {"add"},
		"yum":     {"install"},
		"dnf":     {"install"},
		"zypper":  {"install"},
		"pacman":  {"-S", "install"},
		"brew":    {"install"},
		"snap":    {"install"},
		"flatpak": {"install"},
	}

	cmd := strings.ToLower(execEvent.Comm)

	// Check if the command is a known package manager
	if options, ok := installCommands[cmd]; ok {
		// Iterate through the command's arguments
		for _, arg := range execEvent.Args {
			lowerArg := strings.ToLower(arg)
			// Check against the known install options for that command
			for _, opt := range options {
				lowerOpt := strings.ToLower(opt)
				match := false

				// If the option is a flag (e.g., -S), check if the argument starts with it.
				// This handles combined flags like "pacman -Syu" matching on "-S".
				if strings.HasPrefix(lowerOpt, "-") {
					if strings.HasPrefix(lowerArg, lowerOpt) {
						match = true
					}
				} else {
					// Otherwise, require an exact match for the argument (e.g., "install").
					if lowerArg == lowerOpt {
						match = true
					}
				}

				if match {
					upperLayer := execEvent.UpperLayer || execEvent.PupperLayer
					argsStr := strings.Join(execEvent.Args, " ")

					ruleFailure := GenericRuleFailure{
						BaseRuntimeAlert: apitypes.BaseRuntimeAlert{
							AlertName:   rule.Name(),
							InfectedPID: execEvent.Pid,
							Arguments: map[string]interface{}{
								"command": cmd,
								"args":    argsStr,
							},
							Severity: R1052PackageInstallDetectedDescriptor.Priority,
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
								Path:       GetExecFullPathFromEvent(execEvent),
								Cmdline:    fmt.Sprintf("%s %s", GetExecPathFromEvent(execEvent), strings.Join(utils.GetExecArgsFromEvent(&execEvent.Event), " ")),
							},
							ContainerID: execEvent.Runtime.ContainerID,
						},
						TriggerEvent: execEvent.Event.Event,
						RuleAlert: apitypes.RuleAlert{
							RuleDescription: fmt.Sprintf("Package installation command detected: %s %s", cmd, argsStr),
						},
						RuntimeAlertK8sDetails: apitypes.RuntimeAlertK8sDetails{
							PodName:   execEvent.GetPod(),
							PodLabels: execEvent.K8s.PodLabels,
						},
						RuleID: rule.ID(),
						Extra:  execEvent.GetExtra(),
					}

					return &ruleFailure
				}
			}
		}
	}

	return nil
}

func (rule *R1052PackageInstallDetected) Requirements() ruleengine.RuleSpec {
	return &RuleRequirements{
		EventTypes: R1052PackageInstallDetectedDescriptor.Requirements.RequiredEventTypes(),
	}
}
