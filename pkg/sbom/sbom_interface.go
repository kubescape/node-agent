package sbom

type SBOMClient interface {
	GetSBOM(imageTAG, imageID string) error
	ValidateSBOM() error
	FilterSBOM(sbomFileRelevantMap map[string]bool) error
	StoreFilterSBOM(imageID, instanceID string) error
	CleanResources()
}
