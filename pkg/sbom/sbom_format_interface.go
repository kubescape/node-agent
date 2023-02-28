package sbom

type SBOMFormat interface {
	GetFilterSBOMInBytes() ([]byte, error)
	StoreSBOM([]byte) error
	FilterSBOM(sbomFileRelevantMap map[string]bool) error
	IsNewRelevantSBOMDataExist() bool
	IsSBOMAlreadyExist() bool
}
