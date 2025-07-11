package ruleengine

import (
	"fmt"
	"path/filepath"
	"strings"

	apitypes "github.com/armosec/armoapi-go/armotypes"
	"github.com/armosec/armoapi-go/armotypes/common"
	"github.com/kubescape/node-agent/pkg/ebpf/events"
	"github.com/kubescape/node-agent/pkg/objectcache"
	"github.com/kubescape/node-agent/pkg/ruleengine"
	"github.com/kubescape/node-agent/pkg/utils"
	"github.com/kubescape/storage/pkg/registry/file/dynamicpathdetector"
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

func (rule *R0006UnexpectedServiceAccountTokenAccess) EvaluateRule(eventType utils.EventType, event utils.K8sEvent, k8sObjCache objectcache.K8sObjectCache) ruleengine.DetectionResult {
	if eventType != utils.OpenEventType {
		return ruleengine.DetectionResult{IsFailure: false, Payload: nil}
	}

	convertedEvent, ok := event.(*events.OpenEvent)
	if !ok {
		return ruleengine.DetectionResult{IsFailure: false, Payload: nil}
	}

	openEvent := convertedEvent.Event

	// Check if this is a token path - using optimized check
	if getTokenBasePath(openEvent.FullPath) == "" {
		return ruleengine.DetectionResult{IsFailure: false, Payload: nil}
	}

	return ruleengine.DetectionResult{IsFailure: true, Payload: openEvent.FullPath}
}

func (rule *R0006UnexpectedServiceAccountTokenAccess) EvaluateRuleWithProfile(eventType utils.EventType, event utils.K8sEvent, objCache objectcache.ObjectCache) (ruleengine.DetectionResult, error) {
	// First do basic evaluation
	detectionResult := rule.EvaluateRule(eventType, event, objCache.K8sObjectCache())
	if !detectionResult.IsFailure {
		return ruleengine.DetectionResult{IsFailure: false, Payload: nil}, nil
	}

	openEventTyped, _ := event.(*events.OpenEvent)
	ap, err := GetApplicationProfile(openEventTyped.Runtime.ContainerID, objCache)
	if err != nil {
		return ruleengine.DetectionResult{IsFailure: false, Payload: nil}, err
	}

	appProfileOpenList, err := GetContainerFromApplicationProfile(ap, openEventTyped.GetContainer())
	if err != nil {
		return ruleengine.DetectionResult{IsFailure: false, Payload: nil}, err
	}

	// Normalize the accessed path once
	normalizedAccessedPath := normalizeTimestampPath(openEventTyped.FullPath)

	// Check against whitelisted paths
	for _, open := range appProfileOpenList.Opens {
		normalizedWhitelistedPath := normalizeTimestampPath(open.Path)
		if dynamicpathdetector.CompareDynamic(filepath.Dir(normalizedWhitelistedPath), filepath.Dir(normalizedAccessedPath)) {
			return ruleengine.DetectionResult{IsFailure: false, Payload: nil}, nil
		}
	}

	return detectionResult, nil
}

func (rule *R0006UnexpectedServiceAccountTokenAccess) CreateRuleFailure(eventType utils.EventType, event utils.K8sEvent, objCache objectcache.ObjectCache, payload ruleengine.DetectionResult) ruleengine.RuleFailure {
	convertedEvent, _ := event.(*events.OpenEvent)
	openEvent := convertedEvent.Event

	return &GenericRuleFailure{
		BaseRuntimeAlert: apitypes.BaseRuntimeAlert{
			UniqueID:  HashStringToMD5(openEvent.Comm), // We don't want to use the full path as it can be dynamic (https://kubernetes.io/docs/concepts/security/service-accounts/#assign-to-pod)
			AlertName: rule.Name(),
			Arguments: map[string]interface{}{
				"path":  openEvent.FullPath,
				"flags": openEvent.Flags,
			},
			InfectedPID: openEvent.Pid,
			Severity:    R0006UnexpectedServiceAccountTokenAccessRuleDescriptor.Priority,
			Identifiers: &common.Identifiers{
				Process: &common.ProcessEntity{
					Name: openEvent.Comm,
				},
				File: &common.FileEntity{
					Name:      filepath.Base(openEvent.FullPath),
					Directory: filepath.Dir(openEvent.FullPath),
				},
			},
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
		ProfileRequirements: ruleengine.ProfileRequirement{
			ProfileDependency: apitypes.Required,
			ProfileType:       apitypes.ApplicationProfile,
		},
	}
}
