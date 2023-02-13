package sbom

type SbomClient interface {
	GetSBOM(imageID string)
	FilterSBOM(sbomFileRelevantMap map[string]bool)
	StoreFilterSBOM()
}
