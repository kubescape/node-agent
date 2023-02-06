package sbom

type SbomClient interface {
	GetSBOM(imageID)
	FilterSBOM()
	PostFilterSBOM(key inteface{}, data []byte)
}