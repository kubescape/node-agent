package sbom

type SBOMClient interface {
	GetSBOM(imageID string) error
	FilterSBOM(sbomFileRelevantMap map[string]bool) error
	StoreFilterSBOM(instanceID string) error
	CleanResources()
}
