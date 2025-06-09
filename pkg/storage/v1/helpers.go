package storage

import (
	"github.com/kubescape/k8s-interface/instanceidhandler/v1/helpers"
	"github.com/kubescape/node-agent/pkg/objectcache"
	"github.com/kubescape/storage/pkg/registry/softwarecomposition/common"
)

func IsComplete(annotations map[string]string, newCompletionStatus objectcache.WatchedContainerCompletionStatus) bool {
	newAnnotations := make(map[string]string)
	newAnnotations[helpers.CompletionMetadataKey] = string(newCompletionStatus)
	return common.IsComplete(annotations, newAnnotations)
}

func IsSeenFromStart(annotations map[string]string, watchedContainer *objectcache.WatchedContainerData) bool {
	return annotations[helpers.CompletionMetadataKey] == helpers.Full && watchedContainer.GetCompletionStatus() == helpers.Partial
}
