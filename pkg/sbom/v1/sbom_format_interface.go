package sbom

import (
	"context"

	"github.com/kubescape/k8s-interface/instanceidhandler"
)

type SBOMFormat interface {
	GetFilterSBOMData() any
	StoreSBOM(ctx context.Context, sbomData any) error
	ValidateSBOM(ctx context.Context) error
	FilterSBOM(sbomFileRelevantMap map[string]bool) error
	IsNewRelevantSBOMDataExist() bool
	IsSBOMAlreadyExist() bool
	SetFilteredSBOMName(string)
	StoreMetadata(wlidData, imageID string, instanceID instanceidhandler.IInstanceID)
	CleanResources()
}
