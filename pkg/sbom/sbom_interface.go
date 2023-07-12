package sbom

import "context"

type SBOMClient interface {
	GetSBOM(ctx context.Context, imageTag, imageID string) error
	IsSBOMAlreadyExist() bool
	ValidateSBOM(ctx context.Context) error
	FilterSBOM(ctx context.Context, sbomFileRelevantMap map[string]bool) error
	StoreFilterSBOM(ctx context.Context, imageID, instanceID string) error
	CleanResources()
}
