package ruleengine

import (
	"fmt"
	"path/filepath"
	"strings"

	"github.com/kubescape/node-agent/pkg/objectcache"
	"github.com/kubescape/node-agent/pkg/ruleengine"
	"github.com/kubescape/node-agent/pkg/utils"
	"github.com/kubescape/storage/pkg/registry/file/dynamicpathdetector"

	apitypes "github.com/armosec/armoapi-go/armotypes"
	traceropentype "github.com/inspektor-gadget/inspektor-gadget/pkg/gadgets/trace/open/types"
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
func normalizeTokenPath(path string) string {
	// Get the base path - if not a token path, return original
	basePath := getTokenBasePath(path)
	if basePath == "" {
		return path
	}

	// Get the final component (usually "token", "ca.crt", etc.)
	finalComponent := filepath.Base(path)

	// Split the middle part (between base path and final component)
	middle := strings.TrimPrefix(filepath.Dir(path), basePath)
	if middle == "" {
		return filepath.Join(basePath, finalComponent)
	}

	// Check if the path contains a dynamic identifier
	if strings.Contains(middle, dynamicpathdetector.DynamicIdentifier) {
		// If it has a dynamic identifier, keep the base structure but normalize the variable part
		return filepath.Join(basePath, dynamicpathdetector.DynamicIdentifier, finalComponent)
	}

	// Process middle parts
	var normalizedMiddle strings.Builder
	parts := strings.Split(middle, "/")
	for _, part := range parts {
		if part == "" {
			continue
		}
		// Skip timestamp directories (starting with ".." and containing "_")
		if strings.HasPrefix(part, "..") && strings.Contains(part, "_") {
			normalizedMiddle.WriteString("/")
			normalizedMiddle.WriteString(dynamicpathdetector.DynamicIdentifier)
			break // We only need one dynamic identifier
		}
		normalizedMiddle.WriteString("/")
		normalizedMiddle.WriteString(part)
	}

	// If no middle parts remain, join base and final
	if normalizedMiddle.Len() == 0 {
		return filepath.Join(basePath, finalComponent)
	}

	// Join all parts
	return basePath + normalizedMiddle.String() + "/" + finalComponent
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

	openEvent, ok := event.(*traceropentype.Event)
	if !ok {
		return nil
	}

	// Check if this is a token path - using optimized check
	if getTokenBasePath(openEvent.FullPath) == "" {
		return nil
	}

	// Get the application profile
	ap := objCache.ApplicationProfileCache().GetApplicationProfile(openEvent.Runtime.ContainerID)
	if ap == nil {
		return nil
	}

	appProfileOpenList, err := getContainerFromApplicationProfile(ap, openEvent.GetContainer())
	if err != nil {
		return nil
	}

	// Normalize the accessed path once
	normalizedAccessedPath := normalizeTokenPath(openEvent.FullPath)
	dirPath := filepath.Dir(normalizedAccessedPath)

	// Check against whitelisted paths
	for _, open := range appProfileOpenList.Opens {
		if dirPath == filepath.Dir(normalizeTokenPath(open.Path)) {
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
			FixSuggestions: fmt.Sprintf(
				"If this is a valid behavior, please add the open call to the whitelist in the application profile for the Pod %s",
				openEvent.GetPod()),
			Severity: R0006UnexpectedServiceAccountTokenAccessRuleDescriptor.Priority,
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
				"Unexpected access to service account token: %s with flags: %s in: %s",
				openEvent.FullPath,
				strings.Join(openEvent.Flags, ","),
				openEvent.GetContainer(),
			),
		},
		RuntimeAlertK8sDetails: apitypes.RuntimeAlertK8sDetails{
			PodName:   openEvent.GetPod(),
			PodLabels: openEvent.K8s.PodLabels,
		},
		RuleID: rule.ID(),
	}
}

func (rule *R0006UnexpectedServiceAccountTokenAccess) Requirements() ruleengine.RuleSpec {
	return &RuleRequirements{
		EventTypes: R0006UnexpectedServiceAccountTokenAccessRuleDescriptor.Requirements.RequiredEventTypes(),
	}
}
