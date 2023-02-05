package sbom

type SbomClient interface {
	GetSbom(imageID)
	FilterSbom()
	PostFilterSbom(key inteface{}, data []byte)
}