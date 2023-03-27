package sbom

import instanceidhandler "github.com/kubescape/k8s-interface/instanceidhandler"

type SBOMFormat interface {
	GetFilterSBOMData() any
	StoreSBOM(any) error
	FilterSBOM(sbomFileRelevantMap map[string]bool) error
	IsNewRelevantSBOMDataExist() bool
	IsSBOMAlreadyExist() bool
	StoreFilteredSBOMName(string)
	StoreMetadata(instanceID instanceidhandler.IInstanceID)
}
