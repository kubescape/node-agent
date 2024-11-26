package sbomhandler

import (
	"github.com/kubescape/node-agent/pkg/utils"
)

type SBOMHandlerClient interface {
	FilterSBOM(watchedContainer *utils.WatchedContainerData, sbomFileRelevantMap map[string]bool) error
	IncrementImageUse(imageID string)
	DecrementImageUse(imageID string)
}
