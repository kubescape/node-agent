package sbom

type SBOMFormat interface {
	GetFilterSBOMData() any
	StoreSBOM(any) error
	FilterSBOM(sbomFileRelevantMap map[string]bool) error
	IsNewRelevantSBOMDataExist() bool
	IsSBOMAlreadyExist() bool
	StoreFilteredSBOMName(string)
	StoreMetadata(string)
}
