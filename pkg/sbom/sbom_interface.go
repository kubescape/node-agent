package sbom

import "context"

type SBOMClient interface {
	GetSBOM(ctx context.Context, imageTAG, imageID string) error
	ValidateSBOM(ctx context.Context) error
	FilterSBOM(ctx context.Context, sbomFileRelevantMap map[string]bool) error
	StoreFilterSBOM(ctx context.Context, imageID, instanceID string) error
	CleanResources()
}
