package sbom

type SBOMClient interface {
	GetSBOM(imageID string) error
	FilterSBOM(containerID string, sbomFileRelevantMap map[string]bool) error
	StoreFilterSBOM(instanceID string) error
}
