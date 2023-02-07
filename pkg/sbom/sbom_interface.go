package sbom

type SbomClient interface {
	GetSBOM(imageID string)
	FilterSBOM()
	PostFilterSBOM(key interface{}, data []byte)
}
