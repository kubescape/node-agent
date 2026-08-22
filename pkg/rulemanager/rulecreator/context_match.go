package rulecreator

import (
	"strings"

	"github.com/kubescape/node-agent/pkg/contextdetection"
	typesv1 "github.com/kubescape/node-agent/pkg/rulemanager/types/v1"
)

// RuleMatchesContext is the single source of truth for context-based rule matching.
func RuleMatchesContext(rule *typesv1.Rule, currentContext contextdetection.EventSourceContext) bool {
	isContainerContext := currentContext == contextdetection.Kubernetes ||
		currentContext == contextdetection.Standalone ||
		currentContext == contextdetection.Container ||
		currentContext == contextdetection.ECS

	var hasContextTags bool
	for _, tag := range rule.Tags {
		if ctx, found := strings.CutPrefix(tag, "context:"); found {
			if ctx == string(currentContext) {
				return true
			}
			if ctx == string(contextdetection.Container) && isContainerContext {
				return true
			}
			hasContextTags = true
		}
	}

	if !hasContextTags {
		return currentContext == contextdetection.Kubernetes
	}

	return false
}
