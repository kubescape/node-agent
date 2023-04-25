package sbom

import "github.com/kubescape/k8s-interface/instanceidhandler"

type SBOMFormat interface {
	GetFilterSBOMData() any
	StoreSBOM(any) error
	FilterSBOM(sbomFileRelevantMap map[string]bool) error
	IsNewRelevantSBOMDataExist() bool
	IsSBOMAlreadyExist() bool
	StoreFilteredSBOMName(string)
	StoreMetadata(wlidData, imageID string, instanceID instanceidhandler.IInstanceID)
	CleanResources()
}
