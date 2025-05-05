package storage

import (
	"github.com/kubescape/k8s-interface/instanceidhandler/v1/helpers"
	"github.com/kubescape/node-agent/pkg/utils"
)

func IsComplete(annotations map[string]string, newCompletionStatus utils.WatchedContainerCompletionStatus) bool {
	// check if the profile is already completed (completed and partial)
	if c, ok := annotations[helpers.CompletionMetadataKey]; ok {
		if s, ok := annotations[helpers.StatusMetadataKey]; ok {
			return s == helpers.Complete && c == helpers.Completed ||
				s == helpers.Complete && c == helpers.Partial && newCompletionStatus == helpers.Partial
		}
	}
	return false
}

func IsSeenFromStart(annotations map[string]string, watchedContainer *utils.WatchedContainerData) bool {
	return annotations[helpers.CompletionMetadataKey] == helpers.Complete && watchedContainer.GetCompletionStatus() == helpers.Partial
}
