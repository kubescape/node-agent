package ruleengine

import (
	"fmt"
	"strings"
	"time"

	"github.com/kubescape/node-agent/pkg/cooldown"
	"github.com/kubescape/node-agent/pkg/ruleengine"
	"github.com/kubescape/node-agent/pkg/utils"

	"github.com/kubescape/node-agent/pkg/objectcache"

	apitypes "github.com/armosec/armoapi-go/armotypes"
	traceropentype "github.com/inspektor-gadget/inspektor-gadget/pkg/gadgets/trace/open/types"

	"github.com/kubescape/go-logger"
	"github.com/kubescape/go-logger/helpers"
	"github.com/kubescape/storage/pkg/apis/softwarecomposition/v1beta1"
)

const (
	R0002ID   = "R0002"
	R0002Name = "Unexpected file access"
)

var R0002UnexpectedFileAccessRuleDescriptor = ruleengine.RuleDescriptor{
	ID:          R0002ID,
	Name:        R0002Name,
	Description: "Detecting file access that are not whitelisted by application profile. File access is defined by the combination of path and flags",
	Tags:        []string{"open", "whitelisted"},
	Priority:    RulePriorityLow,
	Requirements: &RuleRequirements{
		EventTypes: []utils.EventType{utils.OpenEventType},
	},
	RuleCreationFunc: func() ruleengine.RuleEvaluator {
		return CreateRuleR0002UnexpectedFileAccess()
	},
}
var _ ruleengine.RuleEvaluator = (*R0002UnexpectedFileAccess)(nil)

type R0002UnexpectedFileAccess struct {
	BaseRule
	shouldIgnoreMounts bool
	ignorePrefixes     []string
}

func CreateRuleR0002UnexpectedFileAccess() *R0002UnexpectedFileAccess {
	return &R0002UnexpectedFileAccess{
		shouldIgnoreMounts: false,
		ignorePrefixes:     []string{},
	}
}

func (rule *R0002UnexpectedFileAccess) Name() string {
	return R0002Name
}
func (rule *R0002UnexpectedFileAccess) ID() string {
	return R0002ID
}

func (rule *R0002UnexpectedFileAccess) SetParameters(parameters map[string]interface{}) {
	rule.BaseRule.SetParameters(parameters)

	rule.shouldIgnoreMounts = fmt.Sprintf("%v", rule.GetParameters()["ignoreMounts"]) == "true"

	ignorePrefixesInterface := rule.GetParameters()["ignorePrefixes"]
	if ignorePrefixesInterface == nil {
		return
	}

	ignorePrefixes, ok := interfaceToStringSlice(ignorePrefixesInterface)
	if ok {
		for _, prefix := range ignorePrefixes {
			rule.ignorePrefixes = append(rule.ignorePrefixes, fmt.Sprintf("%v", prefix))
		}
	} else {
		logger.L().Warning("failed to convert ignorePrefixes to []string", helpers.String("ruleID", rule.ID()))
	}
}

func (rule *R0002UnexpectedFileAccess) DeleteRule() {
}

func (rule *R0002UnexpectedFileAccess) generatePatchCommand(event *traceropentype.Event, ap *v1beta1.ApplicationProfile) string {
	flagList := "["
	for _, arg := range event.Flags {
		flagList += "\"" + arg + "\","
	}
	// remove the last comma
	if len(flagList) > 1 {
		flagList = flagList[:len(flagList)-1]
	}
	baseTemplate := "kubectl patch applicationprofile %s --namespace %s --type merge -p '{\"spec\": {\"containers\": [{\"name\": \"%s\", \"opens\": [{\"path\": \"%s\", \"flags\": %s}]}]}}'"
	return fmt.Sprintf(baseTemplate, ap.GetName(), ap.GetNamespace(), event.GetContainer(), event.FullPath, flagList)
}

func (rule *R0002UnexpectedFileAccess) ProcessEvent(eventType utils.EventType, event utils.K8sEvent, objCache objectcache.ObjectCache) ruleengine.RuleFailure {
	if eventType != utils.OpenEventType {
		return nil
	}

	openEvent, ok := event.(*traceropentype.Event)
	if !ok {
		return nil
	}

	// Check if path is ignored
	for _, prefix := range rule.ignorePrefixes {
		if strings.HasPrefix(openEvent.FullPath, prefix) {
			return nil
		}
	}

	if rule.shouldIgnoreMounts {
		mounts, err := getContainerMountPaths(openEvent.GetNamespace(), openEvent.GetPod(), openEvent.GetContainer(), objCache.K8sObjectCache())
		if err != nil {
			return nil
		}
		for _, mount := range mounts {
			if isPathContained(mount, openEvent.FullPath) {
				return nil
			}
		}
	}

	ap := objCache.ApplicationProfileCache().GetApplicationProfile(openEvent.Runtime.ContainerID)
	if ap == nil {
		return nil
	}

	appProfileOpenList, err := getContainerFromApplicationProfile(ap, openEvent.GetContainer())
	if err != nil {
		return nil
	}

	for _, open := range appProfileOpenList.Opens {
		if open.Path == openEvent.FullPath {
			found := 0
			for _, eventOpenFlag := range openEvent.Flags {
				// Check that event open flag is in the open.Flags
				for _, profileOpenFlag := range open.Flags {
					if eventOpenFlag == profileOpenFlag {
						found += 1
					}
				}
			}
			if found == len(openEvent.Flags) {
				return nil
			}
			// TODO: optimize this list (so path will be only once in the list so we can break the loop)
		}
	}

	ruleFailure := GenericRuleFailure{
		BaseRuntimeAlert: apitypes.BaseRuntimeAlert{
			AlertName:   rule.Name(),
			InfectedPID: openEvent.Pid,
			Arguments: map[string]interface{}{
				"flags": openEvent.Flags,
				"path":  openEvent.FullPath,
			},
			FixSuggestions: fmt.Sprintf("If this is a valid behavior, please add the open call \"%s\" to the whitelist in the application profile for the Pod \"%s\". You can use the following command: %s", openEvent.FullPath, openEvent.GetPod(), rule.generatePatchCommand(openEvent, ap)),
			Severity:       R0002UnexpectedFileAccessRuleDescriptor.Priority,
		},
		RuntimeProcessDetails: apitypes.ProcessTree{
			ProcessTree: apitypes.Process{
				Comm: openEvent.Comm,
				Gid:  &openEvent.Gid,
				PID:  openEvent.Pid,
				Uid:  &openEvent.Uid,
			},
			ContainerID: openEvent.Runtime.ContainerID,
		},
		TriggerEvent: openEvent.Event,
		RuleAlert: apitypes.RuleAlert{
			RuleDescription: fmt.Sprintf("Unexpected file access: %s with flags %s in: %s", openEvent.FullPath, strings.Join(openEvent.Flags, ","), openEvent.GetContainer()),
		},
		RuntimeAlertK8sDetails: apitypes.RuntimeAlertK8sDetails{
			PodName: openEvent.GetPod(),
		},
		RuleID:            rule.ID(),
		FailureIdentifier: failureIdentifireMD5(rule.ID(), fmt.Sprintf("%s-%s-%s", openEvent.GetNamespace(), openEvent.GetPod(), openEvent.GetContainer()), openEvent.FullPath),
	}

	return &ruleFailure
}

func isPathContained(basepath, targetpath string) bool {
	return strings.HasPrefix(targetpath, basepath)
}

func (rule *R0002UnexpectedFileAccess) Requirements() ruleengine.RuleSpec {
	return &RuleRequirements{
		EventTypes: R0002UnexpectedFileAccessRuleDescriptor.Requirements.RequiredEventTypes(),
	}
}

func (rule *R0002UnexpectedFileAccess) CooldownConfig() *cooldown.CooldownConfig {
	return &cooldown.CooldownConfig{
		Threshold:        10,
		AlertWindow:      time.Minute * 1,
		BaseCooldown:     time.Second * 30,
		MaxCooldown:      time.Minute * 5,
		CooldownIncrease: 1.5,
	}
}
