package sbom

type SBOMClient interface {
	GetSBOM(imageID string) error
	ValidateSBOM() error
	FilterSBOM(sbomFileRelevantMap map[string]bool) error
	StoreFilterSBOM(instanceID string) error
	CleanResources()
}
