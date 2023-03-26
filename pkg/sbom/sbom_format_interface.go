package sbom

import instanceidhandler "github.com/kubescape/k8s-interface/instanceidhandler/v1"

type SBOMFormat interface {
	GetFilterSBOMData() any
	StoreSBOM(any) error
	FilterSBOM(sbomFileRelevantMap map[string]bool) error
	IsNewRelevantSBOMDataExist() bool
	IsSBOMAlreadyExist() bool
	StoreFilteredSBOMName(string)
	StoreMetadata(instanceID instanceidhandler.InstanceID)
}
