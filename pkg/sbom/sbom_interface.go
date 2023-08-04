package sbom

import "context"

type SBOMClient interface {
	GetSBOM(ctx context.Context, imageTag, imageID string) error
	IsSBOMAlreadyExist() bool
	ValidateSBOM(ctx context.Context) error
	FilterSBOM(sbomFileRelevantMap map[string]bool) error
	StoreFilterSBOM(imageID, instanceID string) error
	CleanResources()
}
