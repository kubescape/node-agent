package ruleengine

import (
	"fmt"
	"path/filepath"
	"strings"

	"github.com/kubescape/node-agent/pkg/ebpf/events"
	"github.com/kubescape/node-agent/pkg/objectcache"
	"github.com/kubescape/node-agent/pkg/ruleengine"
	"github.com/kubescape/node-agent/pkg/utils"
	"github.com/kubescape/storage/pkg/registry/file/dynamicpathdetector"

	apitypes "github.com/armosec/armoapi-go/armotypes"
)

const (
	R0006ID   = "R0006"
	R0006Name = "Unexpected Service Account Token Access"
)

var serviceAccountTokenPathsPrefixes = []string{
	"/run/secrets/kubernetes.io/serviceaccount",
	"/var/run/secrets/kubernetes.io/serviceaccount",
	"/run/secrets/eks.amazonaws.com/serviceaccount",
	"/var/run/secrets/eks.amazonaws.com/serviceaccount",
}

var R0006UnexpectedServiceAccountTokenAccessRuleDescriptor = ruleengine.RuleDescriptor{
	ID:          R0006ID,
	Name:        R0006Name,
	Description: "Detecting unexpected access to service account token.",
	Tags:        []string{"token", "malicious", "security", "kubernetes"},
	Priority:    RulePriorityHigh,
	Requirements: &RuleRequirements{
		EventTypes: []utils.EventType{
			utils.OpenEventType,
		},
	},
	RuleCreationFunc: func() ruleengine.RuleEvaluator {
		return CreateRuleR0006UnexpectedServiceAccountTokenAccess()
	},
}

type R0006UnexpectedServiceAccountTokenAccess struct {
	BaseRule
}

// getTokenBasePath returns the base service account token path if the path is a token path,
// otherwise returns an empty string. Using a single iteration through prefixes.
func getTokenBasePath(path string) string {
	for _, prefix := range serviceAccountTokenPathsPrefixes {
		if strings.HasPrefix(path, prefix) {
			return prefix
		}
	}
	return ""
}

// normalizeTokenPath removes timestamp directories from the path while maintaining
// the essential structure. Handles both timestamp directories and dynamic identifiers.
func normalizeTimestampPath(path string) string {
	parts := strings.Split(filepath.Clean(path), string(filepath.Separator))
	var normalized []string

	for _, part := range parts {
		if part == "" {
			continue
		}

		// Replace timestamp directories with their base form
		if strings.HasPrefix(part, "..") && strings.Contains(part, "_") {
			normalized = append(normalized, "..timestamp")
			continue
		}

		normalized = append(normalized, part)
	}

	return "/" + strings.Join(normalized, "/")
}

func CreateRuleR0006UnexpectedServiceAccountTokenAccess() *R0006UnexpectedServiceAccountTokenAccess {
	return &R0006UnexpectedServiceAccountTokenAccess{}
}

func (rule *R0006UnexpectedServiceAccountTokenAccess) Name() string {
	return R0006Name
}

func (rule *R0006UnexpectedServiceAccountTokenAccess) ID() string {
	return R0006ID
}

func (rule *R0006UnexpectedServiceAccountTokenAccess) DeleteRule() {}

func (rule *R0006UnexpectedServiceAccountTokenAccess) ProcessEvent(eventType utils.EventType, event utils.K8sEvent, objCache objectcache.ObjectCache) ruleengine.RuleFailure {
	// Quick type checks first
	if eventType != utils.OpenEventType {
		return nil
	}

	convertedEvent, ok := event.(*events.OpenEvent)
	if !ok {
		return nil
	}

	if convertedEvent.Runtime.ContainerName == "malicious-app" || strings.Contains(convertedEvent.Runtime.ContainerName, "malicious-app") {
		fmt.Println("R0006UnexpectedServiceAccountTokenAccess", convertedEvent.FullPath, convertedEvent.Runtime.ContainerName)
	}

	openEvent := convertedEvent.Event

	// Check if this is a token path - using optimized check
	if getTokenBasePath(openEvent.FullPath) == "" {
		return nil
	}

	// Get the application profile
	ap := objCache.ApplicationProfileCache().GetApplicationProfile(openEvent.Runtime.ContainerID)
	if ap == nil {
		return nil
	}

	appProfileOpenList, err := GetContainerFromApplicationProfile(ap, openEvent.GetContainer())
	if err != nil {
		return nil
	}

	// Normalize the accessed path once
	normalizedAccessedPath := normalizeTimestampPath(openEvent.FullPath)

	// Check against whitelisted paths
	for _, open := range appProfileOpenList.Opens {
		normalizedWhitelistedPath := normalizeTimestampPath(open.Path)
		if dynamicpathdetector.CompareDynamic(filepath.Dir(normalizedWhitelistedPath), filepath.Dir(normalizedAccessedPath)) {
			return nil
		}
	}

	// If we get here, the access was not whitelisted - create an alert
	return &GenericRuleFailure{
		BaseRuntimeAlert: apitypes.BaseRuntimeAlert{
			AlertName: rule.Name(),
			Arguments: map[string]interface{}{
				"path":  openEvent.FullPath,
				"flags": openEvent.Flags,
			},
			InfectedPID: openEvent.Pid,
			Severity:    R0006UnexpectedServiceAccountTokenAccessRuleDescriptor.Priority,
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
			RuleDescription: fmt.Sprintf(
				"Unexpected access to service account token: %s with flags: %s",
				openEvent.FullPath,
				strings.Join(openEvent.Flags, ","),
			),
		},
		RuntimeAlertK8sDetails: apitypes.RuntimeAlertK8sDetails{
			PodName:   openEvent.GetPod(),
			PodLabels: openEvent.K8s.PodLabels,
		},
		RuleID: rule.ID(),
		Extra:  convertedEvent.GetExtra(),
	}
}

func (rule *R0006UnexpectedServiceAccountTokenAccess) Requirements() ruleengine.RuleSpec {
	return &RuleRequirements{
		EventTypes: R0006UnexpectedServiceAccountTokenAccessRuleDescriptor.Requirements.RequiredEventTypes(),
	}
}
